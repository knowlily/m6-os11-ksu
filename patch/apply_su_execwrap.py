#!/usr/bin/env python3
"""v6：改用老版 KernelSU v1.0.0 的做法 —— 钩 syscall wrapper，只改用户态 regs。

为什么换钩子点（2026-11-01 三份调研的一致结论）：
  - `do_execveat_common` 已经拿到 `struct filename *`，想把 "su" 换成更长的落点路径
    只能替换指针，而 `getname_kernel()` 是 GFP_KERNEL —— kprobe 里不能睡，只能原地 memcpy；
  - 钩在它后面（begin_new_exec/exec_binprm）改 `bprm->cred`，只能改 uid/caps 改不了
    SELinux SID（`setup_selinux()` 是 void，失败静默），于是进程变成
    「uid 0 + untrusted_app」——实测整机卡死；
  - 这两个 kprobe 对全系统每一次 exec 都触发，handler 里任何 printk 都可能拖死看门狗。

wrapper 入口（`__arm64_sys_execve`）的 x0 是「用户态 pt_regs 的指针」，我们只需要：
  1. `strncpy_from_user_nofault` 取路径（不能睡）；
  2. 把新路径拷到用户栈（pagefault_disable + raw_copy_to_user），改 `uregs->regs[0]`；
  3. `override_creds(ksu_cred)` —— 只换指针和引用计数，原子安全；exec 时
     `prepare_bprm_creds()` 会复制这份已提权的 cred，新程序天然是 root；
  4. 原子地摘掉 seccomp（否则 su 里 mount/setuid 会被 SIGSYS）。

落点默认给 `/system/bin/sh`（stock 二进制，App 本来就有权 exec），而不是 ksud —— 
这样 exec 检查天然放行，不需要换域、不需要 overlay、磁盘上也没有 su 文件。

旧的三个 kprobe 通过改 symbol_name 成不存在的符号来"停用"（register 返回 -ENOENT，
handler 永不触发），不改注册代码，降低出错面。

必须在 apply_sc_inject.py / apply_su_cred_fix.py 之后跑。
"""
import pathlib
import sys

MARK = "ksu_execwrap_kp"

DISABLE = [
    ('static struct kprobe ksu_su_exec_kp = {\n    .symbol_name = "do_execveat_common",',
     'static struct kprobe ksu_su_exec_kp = {\n    .symbol_name = "__ksu_disabled_do_execveat_common",'),
    ('static struct kprobe ksu_bprm_begin_kp = {\n    .symbol_name = "begin_new_exec",',
     'static struct kprobe ksu_bprm_begin_kp = {\n    .symbol_name = "__ksu_disabled_begin_new_exec",'),
    ('static struct kprobe ksu_bprm_exec_kp = {\n    .symbol_name = "exec_binprm",',
     'static struct kprobe ksu_bprm_exec_kp = {\n    .symbol_name = "__ksu_disabled_exec_binprm",'),
]

NEW_CODE = r'''
/* ── 2026-11-01 v6：钩 syscall wrapper（老版 KernelSU v1.0.0 的路径）─────────
 * 全程只做「读用户内存 + 写用户栈 + 换 cred 指针 + 摘 seccomp」，
 * 不分配、不 sleep、不 printk（这三件事在 atomic 上下文里都会出事）。
 */
static void ksu_disable_seccomp_atomic(void)
{
#ifdef CONFIG_SECCOMP
    current->seccomp.mode = 0;
    current->seccomp.filter = NULL;
    clear_thread_flag(TIF_SECCOMP);
#endif
}

static int ksu_execwrap_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *uregs;
    const char __user **fn;
    char path[40];
    unsigned long n;
    char __user *sp;

    if (!ksu_su_check_on || !ksu_su_path || !ksu_su_path[0] || !ksu_cred)
        return 0;
    uregs = (struct pt_regs *)regs->regs[0];
    if (!uregs)
        return 0;
    fn = (const char __user **)&uregs->regs[0];
    if (!*fn)
        return 0;
    if (strncpy_from_user_nofault(path, *fn, sizeof(path)) < 0)
        return 0;
    if (strcmp(path, "su") && strcmp(path, "/system/bin/su"))
        return 0;
    if (current_uid().val != 0 && !__ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    n = strlen(ksu_su_path) + 1;
    sp = (char __user *)uregs->sp - n;
    pagefault_disable();
    if (raw_copy_to_user(sp, ksu_su_path, n)) {
        pagefault_enable();
        return 0;
    }
    pagefault_enable();
    *fn = sp;

    ksu_disable_seccomp_atomic();
    ksu_su_saved_cred = override_creds(ksu_cred);
    ksu_su_saved_pid = current->pid;
    return 0;
}

/* exec 失败就把 cred 还原，别把进程留在 root 身份上 */
static int ksu_execwrap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long ret = regs_return_value(regs);

    if (ksu_su_saved_pid != current->pid)
        return 0;
    {
        const struct cred *c = ksu_su_saved_cred;

        ksu_su_saved_cred = NULL;
        ksu_su_saved_pid = 0;
        if (ret < 0 && c)
            revert_creds(c);
    }
    return 0;
}

static struct kprobe ksu_execwrap_kp = {
    .symbol_name = "__arm64_sys_execve",
    .pre_handler = ksu_execwrap_pre,
};

static struct kretprobe ksu_execwrap_ret_kp = {
    .kp.symbol_name = "__arm64_sys_execve",
    .handler = ksu_execwrap_ret,
};

'''

REG_OLD = "    rc = register_kprobe(&ksu_sp_setresuid_kp);\n"
REG_NEW = REG_OLD + """    {
        int rc_w = register_kprobe(&ksu_execwrap_kp);
        int rc_wr = register_kretprobe(&ksu_execwrap_ret_kp);

        pr_alert("ksu: execwrap kprobe=%d kretprobe=%d path=%s\\n",
                 rc_w, rc_wr, ksu_su_path ? ksu_su_path : "(null)");
    }
"""

INIT_OLD = "void ksu_sp_hooks_init(void)\n"
INIT_NEW = NEW_CODE + INIT_OLD


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_execwrap.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "hook" / "arm64" / "syscall_hook.c"
    if not src.is_file():
        print("[su-execwrap] !! 找不到 %s" % src, file=sys.stderr)
        return 1
    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-execwrap] 已打过补丁，跳过")
        return 0
    for old, new in DISABLE:
        if text.count(old) != 1:
            print("[su-execwrap] !! 停用锚点命中 %d 次：%r" % (text.count(old), old[:40]),
                  file=sys.stderr)
            return 1
        text = text.replace(old, new, 1)
        print("[su-execwrap] disabled %s" % old.split('"')[1])
    if text.count(INIT_OLD) != 1:
        print("[su-execwrap] !! ksu_sp_hooks_init 锚点命中 %d 次" % text.count(INIT_OLD),
              file=sys.stderr)
        return 1
    text = text.replace(INIT_OLD, INIT_NEW, 1)
    print("[su-execwrap] ok: handler")
    if text.count(REG_OLD) != 1:
        print("[su-execwrap] !! 注册锚点命中 %d 次" % text.count(REG_OLD), file=sys.stderr)
        return 1
    text = text.replace(REG_OLD, REG_NEW, 1)
    print("[su-execwrap] ok: register")
    src.write_text(text, encoding="utf-8")
    print("[su-execwrap] 写回 %s" % src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
