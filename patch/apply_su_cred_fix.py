#!/usr/bin/env python3
"""修 su 重定向的 creds 泄漏：exec 失败时把 creds 还原。

背景（2026-11-01 真机）：`patch/apply_sc_inject.py` 生成的 ①预处理器里
`override_creds(ksu_cred)` 之后**故意不还原**，注释写「exec 之后这个进程就该是 root」。
但只要 `open_exec(ksu_su_path)` 失败，这个进程就带着 root/kernel 域 cred 继续跑普通代码，
实测模块装载成功 25 秒内整机重启。

本补丁做三件事：
  1. 记录 override 前的 creds + pid；
  2. 给 do_execveat_common 加 kretprobe：返回值 < 0 且 pid 对得上时 revert_creds()；
  3. 注册这个 kretprobe。

必须在 apply_sc_inject.py 之后跑（它改的是同一份 syscall_hook.c）。
"""
import pathlib
import sys

MARK = "ksu_su_saved_cred"

GLOBAL_OLD = "static int ksu_su_pid;\n"
GLOBAL_NEW = GLOBAL_OLD + """/* 2026-11-01: exec 失败时用来还原 creds（原来 override 后故意不还原，失败路径会把
 * 普通进程留在 root/kernel 域，实测装载后 25 秒内整机重启）。 */
static const struct cred *ksu_su_saved_cred;
static int ksu_su_saved_pid;
"""

CRED_OLD = """    {
        const struct cred *old_cred = override_creds(ksu_cred);
        (void)old_cred;   /* 故意不还原：exec 之后这个进程就该是 root */
        pr_alert("ksu: su-escape creds->ksu pid=%d comm=%s\\n", current->pid, current->comm);
    }
"""
CRED_NEW = """    {
        const struct cred *old_cred = override_creds(ksu_cred);

        /* 2026-11-01：不能「故意不还原」。exec 失败时进程会带着 root/kernel 域
         * 的 cred 继续跑普通代码（实测整机重启）。这里只记账，由
         * do_execveat_common 的 kretprobe 在返回 -errno 时还原。 */
        ksu_su_saved_cred = old_cred;
        ksu_su_saved_pid = current->pid;
        pr_alert("ksu: su-escape creds->ksu pid=%d comm=%s\\n", current->pid, current->comm);
    }
"""

KP_OLD = """static struct kprobe ksu_su_exec_kp = {
    .symbol_name = "do_execveat_common",
    .pre_handler = ksu_su_exec_pre,
};
"""
KP_NEW = KP_OLD + """
/* 2026-11-01：exec 返回负值时把 cred 还原，绝不让失败路径留在 root/kernel 域。 */
static int ksu_su_exec_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long ret = regs_return_value(regs);

    if (ksu_su_saved_pid != current->pid)
        return 0;
    {
        const struct cred *c = ksu_su_saved_cred;

        ksu_su_saved_cred = NULL;
        ksu_su_saved_pid = 0;
        if (ret < 0 && c) {
            revert_creds(c);
            pr_alert("ksu: su-escape revert creds pid=%d ret=%ld\\n", current->pid, ret);
        }
    }
    return 0;
}

static struct kretprobe ksu_su_ret_kp = {
    .kp.symbol_name = "do_execveat_common",
    .handler = ksu_su_exec_ret,
};
"""

REG_OLD = "    rc2 = register_kprobe(&ksu_su_exec_kp);\n"
REG_NEW = REG_OLD + """    {
        int rc_suret = register_kretprobe(&ksu_su_ret_kp);

        pr_alert("ksu: kretprobe su-ret rc=%d\\n", rc_suret);
    }
"""

EDITS = [
    ("globals", GLOBAL_OLD, GLOBAL_NEW, 1),
    ("creds-save", CRED_OLD, CRED_NEW, 1),
    ("kretprobe", KP_OLD, KP_NEW, 1),
    ("register", REG_OLD, REG_NEW, 1),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_cred_fix.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "hook" / "arm64" / "syscall_hook.c"
    if not src.is_file():
        print("[su-cred] !! 找不到 %s" % src, file=sys.stderr)
        return 1

    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-cred] 已打过补丁，跳过")
        return 0

    for name, old, new, want in EDITS:
        got = text.count(old)
        if got != want:
            print("[su-cred] !! 锚点 '%s' 命中 %d 次（期望 %d），放弃" % (name, got, want),
                  file=sys.stderr)
            return 1
        text = text.replace(old, new, want)
        print("[su-cred] ok: %s" % name)

    src.write_text(text, encoding="utf-8")
    print("[su-cred] 写回 %s" % src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
