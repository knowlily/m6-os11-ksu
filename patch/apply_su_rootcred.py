#!/usr/bin/env python3
"""v4：把「只改 uid/caps」换成「换上预分配的 kernel cred」。

为什么（2026-11-01 三次真机卡死）：
  - 步骤② 原来只改 bprm->cred 的 uid/gid/caps，`->security`（SELinux SID）还是 App 的
    untrusted_app。进程最后是「uid 0 + untrusted_app 域 + 原 binder 身份」，ksud 一跑
    就把 system_server/binder 拖死 —— 表现为打开应用就卡死重启。
  - su_cred=2 的 task_work → escape_with_root_profile() 同样卡死。

这里改成：模块 init（可睡眠上下文）里 prepare_kernel_cred(NULL) 预分配一份
init_cred 副本（uid 0、全 caps、SID=kernel），kprobe 里只做
`get_cred()` + `put_cred(bprm->cred)` + 指针替换 —— 不分配、不 sleep，
进程最终身份是完整一致的 root/kernel，不留半个身份。

必须在 apply_sc_inject.py 之后跑。
"""
import pathlib
import sys

MARK = "ksu_root_cred"

GLOBAL_OLD = "module_param_named(su_cred, ksu_su_cred, int, 0644);\n"
GLOBAL_NEW = GLOBAL_OLD + """
/* 2026-11-01：直接用内核自带的 init_cred（uid/gid 0、全 caps、SID=kernel）。
 * 本机 kallsyms 里没有 prepare_kernel_cred（被内联/裁掉了），init_cred 是 D 符号，有。
 * kprobe 里只做 get_cred + 指针替换：不分配、不 sleep。 */
extern struct cred init_cred;
static struct cred *ksu_root_cred;
"""

BLOCK_OLD = """    if (!bprm || !bprm->cred)
        return 0;
    c = bprm->cred;
    c->uid = c->euid = c->suid = c->fsuid = GLOBAL_ROOT_UID;
    c->gid = c->egid = c->sgid = c->fsgid = GLOBAL_ROOT_GID;
    c->securebits = 0;
    c->cap_inheritable = CAP_FULL_SET;
    c->cap_permitted = CAP_FULL_SET;
    c->cap_effective = CAP_FULL_SET;
    c->cap_bset = CAP_FULL_SET;
    c->cap_ambient = CAP_EMPTY_SET;
    ksu_su_pid = 0;
    pr_alert("ksu: su-cred -> root (pid=%d comm=%s)\\n", current->pid, current->comm);
    return 0;
"""

BLOCK_NEW = """    if (!bprm || !bprm->cred)
        return 0;
    /* 2026-11-01：不再「只改 uid/caps」。那样 SID 还是 untrusted_app，
     * 进程变成 uid0+untrusted_app，ksud 一跑就把系统拖死（实测卡死重启）。
     * 换成 init 时预分配的 kernel cred：指针替换 + 引用计数，不分配、不 sleep。 */
    if (ksu_root_cred) {
        struct cred *newc = (struct cred *)get_cred(ksu_root_cred);   /* 6.1 的 get_cred 返回 const */

        put_cred(bprm->cred);
        bprm->cred = newc;
        ksu_su_pid = 0;
        pr_alert("ksu: su-cred -> rootcred(pid=%d comm=%s)\\n", current->pid, current->comm);
        return 0;
    }
    /* 兜底：预分配失败时退回改字段（保留旧行为，便于 A/B） */
    c = bprm->cred;
    c->uid = c->euid = c->suid = c->fsuid = GLOBAL_ROOT_UID;
    c->gid = c->egid = c->sgid = c->fsgid = GLOBAL_ROOT_GID;
    c->securebits = 0;
    c->cap_inheritable = CAP_FULL_SET;
    c->cap_permitted = CAP_FULL_SET;
    c->cap_effective = CAP_FULL_SET;
    c->cap_bset = CAP_FULL_SET;
    c->cap_ambient = CAP_EMPTY_SET;
    ksu_su_pid = 0;
    pr_alert("ksu: su-cred -> root (pid=%d comm=%s)\\n", current->pid, current->comm);
    return 0;
"""

INIT_OLD = """    if (ksu_sp_inited)
        return;
    ksu_sp_inited = true;
"""
INIT_NEW = """    if (ksu_sp_inited)
        return;
    ksu_sp_inited = true;
    /* 直接用内核自带的 init_cred（本机 kallsyms 里没有 prepare_kernel_cred） */
    ksu_root_cred = &init_cred;
    pr_alert("ksu: rootcred=init_cred uid=%d gid=%d\\n",
             ksu_root_cred->uid.val, ksu_root_cred->gid.val);
"""

EDITS = [
    ("global", GLOBAL_OLD, GLOBAL_NEW, 1),
    ("swap", BLOCK_OLD, BLOCK_NEW, 1),
    ("init", INIT_OLD, INIT_NEW, 1),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_rootcred.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "hook" / "arm64" / "syscall_hook.c"
    if not src.is_file():
        print("[su-rootcred] !! 找不到 %s" % src, file=sys.stderr)
        return 1
    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-rootcred] 已打过补丁，跳过")
        return 0
    for name, old, new, want in EDITS:
        got = text.count(old)
        if got != want:
            print("[su-rootcred] !! 锚点 '%s' 命中 %d 次（期望 %d），放弃" % (name, got, want),
                  file=sys.stderr)
            return 1
        text = text.replace(old, new, want)
        print("[su-rootcred] ok: %s" % name)
    src.write_text(text, encoding="utf-8")
    print("[su-rootcred] 写回 %s" % src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
