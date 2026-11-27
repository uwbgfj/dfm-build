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
static int      aa_strength = 40;
static int      aa_rate = 80;      /* 生效概率 % */
static u32      aa_rnd = 0x9E3779B9;
static unsigned long aa_pc0 = 0x0B81F4F4UL;
static unsigned long aa_pc1 = 0x0B81F47CUL;
static int aa_pass_near = 95;      /* 近距通过率 % */
static int aa_pass_mid  = 88;
static int aa_pass_far  = 78;
static unsigned int aa_near_exp = 63;   /* |s0| 指数 < 63 → 近距 */
static unsigned int aa_mid_exp  = 66;   /* < 66 → 中距，否则远距 */
static u32 aa_seed = 0x9E3779B9;

static struct task_struct *aa_task;

#define AA_MAX_TH 512

static unsigned long aa_addr0, aa_addr1;

static inline u32 aa_rand100(void)
{
    aa_rnd = aa_rnd * 1664525u + 1013904223u;
    return (aa_rnd >> 16) % 100u;
}
struct aa_th_bp { pid_t pid; struct perf_event *e0, *e1; };
static struct aa_th_bp aa_th[AA_MAX_TH];
static int aa_th_n;
static unsigned long aa_base, aa_base_end;
static int aa_pid;
static int aa_live;
static atomic64_t aa_hits0 = ATOMIC64_INIT(0), aa_hits1 = ATOMIC64_INIT(0);

static const u32 aa_ge[11] = {0x00000000,0x40800000,0x41000000,0x41400000,0x41800000,
                             0x41a00000,0x41c00000,0x41e00000,0x42000000,0x42100000,0x42200000};
static const u32 aa_cmp[11] = {
    0x00000000,  /* 0  关 */
    0x3D23D70A,  /* 1  0.040  仅后坐力 */
    0x3CCCCCCD,  /* 2  0.025  仅后坐力 */
    0x3C23D70A,  /* 3  0.010  略强 */
    0x00000000,  /* 4  0.000  默认 */
    0xBC23D70A,  /* 5 -0.010  刚有锁 */
    0xBD4CCCCD,  /* 6 -0.050  有锁 */
    0xBDCCCCCD,  /* 7 -0.100  锁明显 */
    0xBE800000,  /* 8 -0.250  强 */
    0xBF000000,  /* 9 -0.500  很强 */
    0xBF800000,  /* 10 -1.000 最强 */
};

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
    a0 = aa_addr0;
    a1 = aa_addr1;

    if (aa_rate < 100 && aa_rand100() >= (u32)aa_rate) return;   /* 概率门 */

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
        int i = aa_strength / 10;
        u32 cb;
        u64 nzcv, st;
        if (i < 0) i = 0;
        if (i > 10) i = 10;
        cb = aa_cmp[i];
        st = aa_fp_on();
        {
            register u32 b1 asm("w1") = cb;
            asm volatile(".inst 0x1e270021\n\t"   /* fmov s1, w1   */
                         ".inst 0x1e212000\n\t"   /* fcmp s0, s1   */
                         ".inst 0xd53b4200"         /* mrs x0, nzcv  */
                         : "=r"(nzcv) : "r"(b1) : "memory");
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


/* 按文件偏移在目标进程的可执行映射中寻找真实地址 */
static unsigned long __maybe_unused aa_rva_to_addr(struct mm_struct *mm, unsigned long rva)
{
    VMA_ITERATOR(vmi, mm, 0);
    struct vm_area_struct *vma;
    unsigned long ret = 0;

    if (!mm) return 0;
    mmap_read_lock(mm);
    for_each_vma(vmi, vma) {
        unsigned long foff, fend;
        if (!(vma->vm_flags & VM_EXEC)) continue;
        foff = (unsigned long)vma->vm_pgoff << PAGE_SHIFT;
        fend = foff + (vma->vm_end - vma->vm_start);
        if (rva >= foff && rva < fend) {
            ret = vma->vm_start + (rva - foff);
            break;
        }
    }
    mmap_read_unlock(mm);
    return ret;
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
    (void)task;
    *out = (struct perf_event *)register_wide_hw_breakpoint(&attr, aa_handler, NULL);
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

static int __maybe_unused aa_th_has(pid_t pid)
{
    int i;
    for (i = 0; i < aa_th_n; i++)
        if (aa_th[i].pid == pid) return 1;
    return 0;
}

/* 给还没挂的线程补挂断点（进对局后新开的线程也能覆盖） */
static int aa_arm_all(struct task_struct *p)
{
    void *e0 = NULL, *e1 = NULL;
    int r0, r1;
    (void)p;
    if (aa_th_n > 0) return 0;          /* 宽断点只挂一份 */

    r0 = aa_install(&e0, aa_addr0, NULL);
    r1 = aa_install(&e1, aa_addr1, NULL);
    if (r0 || r1) {
        if (e0) unregister_wide_hw_breakpoint((struct perf_event * __percpu *)e0);
        if (e1) unregister_wide_hw_breakpoint((struct perf_event * __percpu *)e1);
        return r0 ? r0 : r1;
    }
    aa_th[0].pid = 0;
    aa_th[0].e0 = e0;
    aa_th[0].e1 = e1;
    aa_th_n = 1;
    return 0;
}

static void aa_release(void)
{
    int i;
    aa_live = 0;
    for (i = 0; i < aa_th_n; i++) {
        if (aa_th[i].e0) unregister_wide_hw_breakpoint((struct perf_event * __percpu *)aa_th[i].e0);
        if (aa_th[i].e1) unregister_wide_hw_breakpoint((struct perf_event * __percpu *)aa_th[i].e1);
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

static void aa_read_cfg(void)
{
    struct file *f;
    char *buf;
    loff_t pos = 0;
    f = filp_open(AA_CFG, O_RDONLY, 0);
    if (IS_ERR(f)) {
        f = filp_open("/data/adb/aa.cfg", O_RDONLY, 0);
        if (IS_ERR(f))
            return;
    }
    buf = kzalloc(1024, GFP_KERNEL);
    if (buf) {
        if (kernel_read(f, buf, 1023, &pos) > 0) {
            char *line, *nl;
            for (line = buf; line && *line; line = nl) {
                nl = strchr(line, '\n');
                if (nl) *nl++ = 0;
                if (!strncmp(line, "pkg=", 4)) strscpy(aa_pkg, line + 4, sizeof(aa_pkg));
                else if (!strncmp(line, "pc0=", 4)) aa_pc0 = simple_strtoul(line + 4, NULL, 0);
                else if (!strncmp(line, "pc1=", 4)) aa_pc1 = simple_strtoul(line + 4, NULL, 0);
                else if (!strncmp(line, "level=", 6)) aa_strength = simple_strtol(line + 6, NULL, 10) * 10;
                else if (!strncmp(line, "enable=", 7)) aa_on = simple_strtol(line + 7, NULL, 10);
                else if (!strncmp(line, "pass_near=", 10)) aa_pass_near = simple_strtol(line + 10, NULL, 10);
                else if (!strncmp(line, "pass_mid=", 9))  aa_pass_mid  = simple_strtol(line + 9, NULL, 10);
                else if (!strncmp(line, "pass_far=", 9))  aa_pass_far  = simple_strtol(line + 9, NULL, 10);
                else if (!strncmp(line, "near_exp=", 9))  aa_near_exp  = simple_strtoul(line + 9, NULL, 0);
                else if (!strncmp(line, "mid_exp=", 8))   aa_mid_exp   = simple_strtoul(line + 8, NULL, 0);
            }
        }
        kfree(buf);
    }
    fput(f);
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
    unsigned long a0 = aa_addr0;
    if (aa_fp_ok(a0, AA_FP_PC0)) return 0;              /* 指纹对，直接挂 */
    {
        unsigned long hit = aa_scan(aa_base, aa_base_end, AA_FP_PC0);
        if (!hit) return -1;
        aa_pc0 = hit - aa_base;
        if (aa_pc0 > AA_PC_DELTA) aa_pc1 = aa_pc0 - AA_PC_DELTA;
        if (!aa_fp_ok(aa_addr1, AA_FP_PC1)) return -1;
        return 1;                                        /* 已重定位 */
    }
}

static void aa_release(void);

/* ---------- /proc/aa：运行时调参 ---------- */
static void aa_parse_kv(char *buf)
{
    char *line, *nl;
    char *p;
    for (line = buf; line && *line; line = nl) {
        nl = strchr(line, '\n');
        if (nl) *nl++ = 0;
        for (p = line; *p; p++) if (*p == ' ' || *p == ',') *p = '\n';
        /* 逐段处理 */
        {
            char *seg, *sn;
            for (seg = line; seg && *seg; seg = sn) {
                sn = strchr(seg, '\n');
                if (sn) *sn++ = 0;
                if (!strncmp(seg, "pkg=", 4))          strscpy(aa_pkg, seg + 4, sizeof(aa_pkg));
                else if (!strncmp(seg, "pc0=", 4))     aa_pc0 = simple_strtoul(seg + 4, NULL, 0);
                else if (!strncmp(seg, "pc1=", 4))     aa_pc1 = simple_strtoul(seg + 4, NULL, 0);
                else if (!strncmp(seg, "level=", 6))   aa_strength = simple_strtol(seg + 6, NULL, 10) * 10;
                else if (!strncmp(seg, "rate=", 5)) { aa_rate = simple_strtol(seg + 5, NULL, 10); if (aa_rate < 1) aa_rate = 1; if (aa_rate > 100) aa_rate = 100; }
                else if (!strncmp(seg, "enable=", 7))  aa_on = simple_strtol(seg + 7, NULL, 10);
                else if (!strncmp(seg, "pass=", 5)) { int v = simple_strtol(seg + 5, NULL, 10);
                    aa_pass_near = aa_pass_mid = aa_pass_far = v; }
                else if (!strncmp(seg, "pass_near=", 10)) aa_pass_near = simple_strtol(seg + 10, NULL, 10);
                else if (!strncmp(seg, "pass_mid=", 9))   aa_pass_mid  = simple_strtol(seg + 9, NULL, 10);
                else if (!strncmp(seg, "pass_far=", 9))   aa_pass_far  = simple_strtol(seg + 9, NULL, 10);
            }
        }
    }
}

static ssize_t aa_proc_write(struct file *fp, const char __user *ubuf, size_t cnt, loff_t *pos)
{
    char buf[512];
    size_t len = cnt < sizeof(buf) - 1 ? cnt : sizeof(buf) - 1;
    if (copy_from_user(buf, ubuf, len)) return -EFAULT;
    buf[len] = 0;
    aa_parse_kv(buf);
    aa_release();                  /* 参数变了，重新附加 */
    return cnt;
}

static int aa_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "pkg=%s\n", aa_pkg);
    seq_printf(m, "pc0=0x%lx\npc1=0x%lx\n", aa_pc0, aa_pc1);
    seq_printf(m, "level=%d\nenable=%d\nrate=%d\n", aa_strength / 10, aa_on, aa_rate);
    seq_printf(m, "pass_near=%d\npass_mid=%d\npass_far=%d\n",
               aa_pass_near, aa_pass_mid, aa_pass_far);
    seq_printf(m, "live=%d pid=%d base=0x%lx threads=%d\n",
               aa_live, aa_pid, aa_base, aa_th_n);
    seq_printf(m, "hits0=%lld\nhits1=%lld\n",
               atomic64_read(&aa_hits0), atomic64_read(&aa_hits1));
    return 0;
}

static int aa_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, aa_proc_show, NULL);
}

static const struct proc_ops aa_proc_fops = {
    .proc_open    = aa_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = aa_proc_write,
};

static struct delayed_work aa_work;

static void aa_work_fn(struct work_struct *w)
{
    struct task_struct *t;

    aa_read_cfg();
    if (aa_on) {
        t = aa_find_task();
        if (!t) {
            if (aa_live) aa_release();
        } else if (aa_live && aa_pid == t->tgid) {
            aa_arm_all(t);          /* 补挂新线程 */
        } else if (!(aa_live && aa_pid == t->tgid)) {
            aa_release();
            get_task_struct(t);
            aa_task = t;
            aa_pid  = t->tgid;
            aa_base = aa_find_base(t->mm);
            aa_addr0 = aa_rva_to_addr(t->mm, aa_pc0);
            aa_addr1 = aa_rva_to_addr(t->mm, aa_pc1);
            pr_info("aa: base=%lx a0=%lx a1=%lx\n", aa_base, aa_addr0, aa_addr1);
            if (aa_base) {
                int rr = aa_verify_or_relocate();
                pr_info("aa: verify=%d\n", rr);
                if (rr >= 0) {
                    int ar = aa_arm_all(t);
                    pr_info("aa: arm=%d n=%d live=%d\n", ar, aa_th_n, aa_live);
                    if (aa_th_n > 0) aa_live = 1; else aa_release();
                }
            }
        }
    } else {
        if (aa_live) aa_release();
    }
    schedule_delayed_work(&aa_work, msecs_to_jiffies(2000));
}

static struct proc_dir_entry *aa_proc;

static int __init aa_builtin_init(void)
{
    aa_proc = proc_create("vmstat_aux", 0600, NULL, &aa_proc_fops);
    INIT_DELAYED_WORK(&aa_work, aa_work_fn);
    schedule_delayed_work(&aa_work, msecs_to_jiffies(2000));
    return 0;
}
late_initcall(aa_builtin_init);
