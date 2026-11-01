#!/usr/bin/env python3
"""v7：把 exec 挂钩里的 override_creds 换成 commit_creds —— 这是卡死的真正原因。

`override_creds()` 只改 `current->cred`，**不改 `current->real_cred`**。
exec 末尾的 `commit_creds(bprm->cred)` 里有：

    BUG_ON(task->cred != old);      /* old = task->real_cred */

我们 override 之后 `cred=ksu_cred`、`real_cred=app_cred`，两者不等 →
BUG_ON 命中 → 内核 panic → 整机重启。这和"一执行 su 就重启、pstore 里什么都没有"
的指纹完全吻合（BUG_ON 走的是 panic 而不是 oops，ramoops 也没留正文）。

正确做法与老版 KernelSU 的 escape_to_root() 一致：一次 commit_creds 把两个指针
一起换掉，状态永远一致。commit_creds 全程是原子安全的（引用计数 + RCU 指针赋值
+ put_cred），不分配、不睡眠。

必须在 apply_su_execwrap.py 之后跑。
"""
import pathlib
import sys

MARK = "v7：commit_creds"

OLD_SET = """    ksu_disable_seccomp_atomic();
    ksu_su_saved_cred = override_creds(ksu_cred);
    ksu_su_saved_pid = current->pid;
"""

NEW_SET = """    ksu_disable_seccomp_atomic();
    /* v7：commit_creds 而不是 override_creds。
     * override_creds 只改 current->cred，real_cred 还是 App 的；exec 末尾的
     * commit_creds(bprm->cred) 里 BUG_ON(task->cred != real_cred) 会直接 panic。
     * 一次 commit_creds 把 real_cred/cred 一起换，状态一致。 */
    ksu_su_saved_cred = get_cred(current->real_cred);
    ksu_su_saved_pid = current->pid;
    commit_creds((struct cred *)get_cred(ksu_cred));
"""

OLD_RET = """        ksu_su_saved_cred = NULL;
        ksu_su_saved_pid = 0;
        if (ret < 0 && c)
            revert_creds(c);
"""

NEW_RET = """        ksu_su_saved_cred = NULL;
        ksu_su_saved_pid = 0;
        if (!c)
            return 0;
        if (ret < 0)
            commit_creds((struct cred *)c);   /* exec 失败：还原并归还引用 */
        else
            put_cred(c);                      /* exec 成功：新程序已继承 root cred */
"""


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_commitcred.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "hook" / "arm64" / "syscall_hook.c"
    if not src.is_file():
        print("[su-commitcred] !! 找不到 %s" % src, file=sys.stderr)
        return 1
    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-commitcred] 已打过补丁，跳过")
        return 0
    for name, old, new in (("set", OLD_SET, NEW_SET), ("ret", OLD_RET, NEW_RET)):
        n = text.count(old)
        if n != 1:
            print("[su-commitcred] !! 锚点 '%s' 命中 %d 次" % (name, n), file=sys.stderr)
            return 1
        text = text.replace(old, new, 1)
        print("[su-commitcred] ok: %s" % name)
    src.write_text(text, encoding="utf-8")
    print("[su-commitcred] 写回 %s" % src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
