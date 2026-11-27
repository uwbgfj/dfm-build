// aa_builtin.c —— 编进内核的判定篡改（不再是模块）
// 放到 drivers/misc/aa_builtin.c，并在 drivers/misc/Makefile 里加 obj-y += aa_builtin.o
//
// 行为：
//   1. 开机起一个内核线程，每 2 秒扫一次进程表
//   2. 发现目标进程（comm 匹配）就在它的 mm 里找 libUE4.so 的基址
//   3. 在 base+pc0 / base+pc1 挂硬件执行断点
//   4. 命中时改 pt_regs（pc / 条件标志），浮点用 cpacr_el1 开关（和原版模块同一手法）
//   5. 进程退出自动注销
//
// 参数来源（按优先级）：/data/local/tmp/aa.cfg > 下面的默认值
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <trace/events/sched.h>
#include <linux/binfmts.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <asm/neon.h>

#define AA_CFG   "/data/adb/aa.cfg"

static char     aa_pkg[64]  = "MainThread-UE4";
static int      aa_on       = 1;
static int      aa_strength = 50;
static unsigned long aa_pc0 = 0x0B81F4F4UL;
static unsigned long aa_pc1 = 0x0B81F47CUL;
static int aa_pass_near = 95;      /* 近距通过率 % */
static int aa_pass_mid  = 88;
static int aa_pass_far  = 78;
static unsigned int aa_near_exp = 63;   /* |s0| 指数 < 63 → 近距 */
static unsigned int aa_mid_exp  = 66;   /* < 66 → 中距，否则远距 */
static u32 aa_seed = 0x9E3779B9;

static unsigned long aa_dbg_tick;
static unsigned long aa_dbg_tick2;

static struct task_struct *aa_task;

#define AA_MAX_TH 512
struct aa_th_bp { pid_t pid; struct perf_event *e0, *e1; };
static struct aa_th_bp aa_th[AA_MAX_TH];
static int aa_th_n;
static unsigned long aa_base, aa_base_end;
static int aa_pid;
static int aa_live;
static atomic64_t aa_hits0 = ATOMIC64_INIT(0), aa_hits1 = ATOMIC64_INIT(0);

static const u32 aa_ge[11] = {0x00000000,0x40800000,0x41000000,0x41400000,0x41800000,
                             0x41a00000,0x41c00000,0x41e00000,0x42000000,0x42100000,0x42200000};
static const u32 aa_cmp[11] = {0x00000000,0x3f4ed917,0x3f1db22d,0x3ed91687,0x3e6d9168,
                               0x3d23d70a,0x3d088889,0x3cea0ea1,0x3ccccccd,0x3cb60b61,0x3ca3d70a};

/* ---------- 浮点：原版模块用 cpacr_el1 直接开关，这里照抄 ---------- */
static inline u64 aa_fp_on(void)
{
    u64 v;
    asm volatile("mrs %0, cpacr_el1" : "=r"(v));
    asm volatile("msr cpacr_el1, %0" :: "r"(v | 0x300000UL));
    asm volatile("isb");
    return v;
}
static inline void aa_fp_off(u64 v)
{
    asm volatile("msr cpacr_el1, %0" :: "r"(v));
    asm volatile("isb");
}

static inline u32 aa_rand(void)
{
    u32 x = aa_seed;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    aa_seed = x;
    return x;
}

static void aa_handler(struct perf_event *bp, struct perf_sample_data *data,
                       struct pt_regs *regs)
{
    unsigned long pc, a0, a1;
    if (!aa_live || !regs || !user_mode(regs)) return;
    if (current->tgid != aa_pid) return;

    pc = regs->pc;
    a0 = aa_base + aa_pc0;
    a1 = aa_base + aa_pc1;

    if (pc == a0) {
        /* 原版语义：把 v0 两个 lane 写成 ge_bits[level]，再执行 fcmge */
        int i = aa_strength / 10;
        u32 gb;
        u64 st;
        if (i < 0) i = 0;
        if (i > 10) i = 10;
        gb = aa_ge[i];
        st = aa_fp_on();
        {
            register u32 b0 asm("w2") = gb;
            /* fmov s0, w2 ; fmov s1, w2 ; fcmge v1.2s, v0.2s, #0.0 */
            asm volatile(".inst 0x1e270040\n\t"
                         ".inst 0x1e270041\n\t"
                         ".inst 0x2ea0c801"
                         : : "r"(b0) : "memory");
        }
        aa_fp_off(st);
        regs->pc = pc + 4;
        atomic64_inc(&aa_hits0);
    } else if (pc == a1) {
        /* 原版语义：无随机、无距离分档，直接按 cmp_bits[level] 比较并写 NZCV */
        int i = aa_strength / 10;
        u32 cb;
        u64 nzcv, st;
        if (i < 0) i = 0;
        if (i > 10) i = 10;
        cb = aa_cmp[i];
        st = aa_fp_on();
        {
            register u32 bin asm("w1") = cb;
            register u64 nz asm("x1");
            /* fmov s1, w1 ; fcmp s0, s1 ; mrs x1, nzcv */
            asm volatile(".inst 0x1e270021\n\t"
                         ".inst 0x1e212000\n\t"
                         ".inst 0xd53b4201"
                         : "=r"(nz) : "r"(bin) : "cc", "memory");
            nzcv = nz;
        }
        aa_fp_off(st);
        {
            unsigned long ps = regs->pstate;
            ps &= ~(0xFUL << 28);
            ps |= ((nzcv & 0xFUL) << 28);
            regs->pstate = ps;
        }
        regs->pc = pc + 4;
        atomic64_inc(&aa_hits1);
    }
}

static int aa_install(struct perf_event **out, unsigned long addr, struct task_struct *task)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.sample_period = 1;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    *out = register_user_hw_breakpoint(&attr, aa_handler, NULL, task);
    if (IS_ERR(*out)) { int r = PTR_ERR(*out); *out = NULL; return r; }
    return 0;
}

/* ---------- 在目标 mm 里找 libUE4.so 的映射基址 ---------- */
static unsigned long aa_find_base(struct mm_struct *mm)
{
    struct vm_area_struct *v;
    char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
    unsigned long ret = 0;
    if (!buf) return 0;
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, v) {
        if (!v->vm_file) continue;
        if (v->vm_pgoff != 0) continue;
        {
            char *p = d_path(&v->vm_file->f_path, buf, PATH_MAX);
            if (!IS_ERR(p) && strstr(p, "libUE4.so")) { ret = v->vm_start; aa_base_end = v->vm_end; break; }
        }
    }
    kfree(buf);
    return ret;
}

static int aa_arm_all(struct task_struct *p)
{
    struct task_struct *t;
    int fails = 0;
    aa_th_n = 0;
    for_each_thread(p, t) {
        struct perf_event *e0 = NULL, *e1 = NULL;
        if (aa_th_n >= AA_MAX_TH) break;
        if (aa_install(&e0, aa_base + aa_pc0, t) ||
            aa_install(&e1, aa_base + aa_pc1, t)) {
            fails++;
            if (e0) unregister_hw_breakpoint(e0);
            if (e1) unregister_hw_breakpoint(e1);
            continue;
        }
        aa_th[aa_th_n].pid = t->pid;
        aa_th[aa_th_n].e0 = e0;
        aa_th[aa_th_n].e1 = e1;
        aa_th_n++;
    }
    return fails;
}

static void aa_release(void)
{
    int i;
    aa_live = 0;
    for (i = 0; i < aa_th_n; i++) {
        if (aa_th[i].e0) unregister_hw_breakpoint(aa_th[i].e0);
        if (aa_th[i].e1) unregister_hw_breakpoint(aa_th[i].e1);
        aa_th[i].e0 = aa_th[i].e1 = NULL;
    }
    aa_th_n = 0;
    if (aa_task) { put_task_struct(aa_task); aa_task = NULL; }
    aa_pid = 0;
}

static struct task_struct *aa_find_task(void)
{
    struct task_struct *p;
    for_each_process(p) {
        if (!strncmp(p->comm, aa_pkg, sizeof(p->comm))) {
            if (p->mm) return p;
        }
    }
    return NULL;
}



static const u64 AA_FP_PC0 = 0x1E2701022EA0C801ULL;  /* fcmge ; fmov s2,w8 */
static const u64 AA_FP_PC1 = 0x5400236D1E212000ULL;  /* fcmp  ; b.le      */
#define AA_PC_DELTA 0x78UL                          /* pc0 - pc1 */

static int aa_read_bytes(unsigned long addr, void *buf, int len)
{
    return access_process_vm(aa_task, addr, buf, len, 0);
}

static int aa_fp_ok(unsigned long addr, u64 expect)
{
    u64 v = 0;
    if (aa_read_bytes(addr, &v, 8) != 8) return 0;
    return v == expect;
}

/* 在 [start,end) 里按 4 字节步进找 8 字节特征 */
static unsigned long aa_scan(unsigned long start, unsigned long end, u64 pat)
{
    unsigned long a;
    u8 *buf = kmalloc(65536 + 8, GFP_KERNEL);
    int got;
    if (!buf) return 0;
    for (a = start; a + 8 <= end; a += 65536) {
        int len = (end - a) > 65536 ? 65536 : (int)(end - a);
        int i;
        got = aa_read_bytes(a, buf, len);
        if (got < 8) continue;
        for (i = 0; i + 8 <= got; i += 4) {
            u64 v;
            memcpy(&v, buf + i, 8);
            if (v == pat) { kfree(buf); return a + i; }
        }
    }
    kfree(buf);
    return 0;
}

static int aa_verify_or_relocate(void)
{
    unsigned long a0 = aa_base + aa_pc0;
    if (aa_fp_ok(a0, AA_FP_PC0)) return 0;              /* 指纹对，直接挂 */
    {
        unsigned long hit = aa_scan(aa_base, aa_base_end, AA_FP_PC0);
        if (!hit) return -1;
        aa_pc0 = hit - aa_base;
        if (aa_pc0 > AA_PC_DELTA) aa_pc1 = aa_pc0 - AA_PC_DELTA;
        if (!aa_fp_ok(aa_base + aa_pc1, AA_FP_PC1)) return -1;
        return 1;                                        /* 已重定位 */
    }
}

static struct delayed_work aa_work;
static int aa_pending_pid;
static int aa_retry;


/* 游戏进程 exec 时被内核通知（不轮询） */
static void aa_exec_cb(void *ignore, struct task_struct *p, pid_t old_pid,
                       struct linux_binprm *bprm)
{
    const char *fn = bprm && bprm->filename ? bprm->filename : "";
    if (strstr(fn, "com.tencent.tmgp.dfm") || !strncmp(p->comm, "com.tencent.tmg", 15)) {
        aa_pending_pid = p->tgid;
        aa_retry = 0;
        schedule_delayed_work(&aa_work, msecs_to_jiffies(1000));
    }
}

static void aa_work_fn(struct work_struct *w)
{
    struct task_struct *t;

    if (!aa_pending_pid) return;

    if (aa_on) {
        t = aa_find_task();
        if (t && !(aa_live && aa_pid == t->tgid)) {
            aa_release();
            get_task_struct(t);
            aa_task = t;
            aa_pid  = t->tgid;
            aa_base = aa_find_base(t->mm);
            if (aa_base) {
                int rr = aa_verify_or_relocate();
                if (rr >= 0) {
                    aa_arm_all(t);
                    if (aa_th_n > 0) aa_live = 1; else aa_release();
                }
            }
        }
    }

    if (aa_live) return;                 /* 成功就不再重排 */

    if (++aa_retry < 120)                /* 最多重试 120 次 × 500ms = 60s */
        schedule_delayed_work(&aa_work, msecs_to_jiffies(500));
}

static int __init aa_setup_level(char *s)
{
    aa_strength = simple_strtol(s, NULL, 10) * 10;   /* aa.level=0..10 */
    return 1;
}
__setup("aa.level=", aa_setup_level);

static int __init aa_setup_pc0(char *s)
{
    aa_pc0 = simple_strtoul(s, NULL, 0);
    return 1;
}
__setup("aa.pc0=", aa_setup_pc0);

static int __init aa_setup_pc1(char *s)
{
    aa_pc1 = simple_strtoul(s, NULL, 0);
    return 1;
}
__setup("aa.pc1=", aa_setup_pc1);

static int __init aa_builtin_init(void)
{
    /* 参数来自内核命令行：aa.level=8 aa.pc0=0x... aa.pc1=0x... */
    INIT_DELAYED_WORK(&aa_work, aa_work_fn);
    register_trace_sched_process_exec(aa_exec_cb, NULL);
    return 0;
}
late_initcall(aa_builtin_init);
