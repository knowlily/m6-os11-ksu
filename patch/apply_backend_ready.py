#!/usr/bin/env python3
"""把 `ksu_hook_backend_ready` 从「分发器装不上就 false」改成「强制 true」。

为什么：这台荣耀内核的 `sys_call_table` 是只读页，`ksu_syscall_hook_init()` 里的
`ksu_syscall_table_hook()` 写入返回 0 但 readback 仍是 ni_syscall ⇒ 分发器永远装不上。
可是管理器跟内核的通路**不走分发器**：
    userspace: syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd)  → 拿 [ksu_driver] fd
    kernel   : ksu_supercalls_init() 注册的 reboot kprobe → task_work → ksu_install_fd()
之后全部走 ioctl(fd, cmd, arg)。

`ksu_hook_backend_ready` 只影响 get_info 响应里的 KSU_GET_INFO_FLAG_HOOK_READY 位
（见 kernel/supercall/dispatch.c），而新版管理器把这一位当「内核已装好」的判据 ⇒ 为 0 就显示「未安装」。
我们自己的 execve/setresuid kprobe 已经把钩子那摊活干了，所以这里置 true 是诚实的。

用法: python patch/apply_backend_ready.py <源码树根>
幂等：命中过就返回 already。
"""
import sys
from pathlib import Path

MARK = "ksu: backend_ready forced=1"
# 常见形态（FinaSU / BakaSU / tianr 分支基本一致）
ANCHOR = """    ret = ksu_syscall_hook_init();
    if (ret) {"""
FALSE_LINE = "        ksu_hook_backend_ready = false;"


def patch(path: Path) -> str:
    s = path.read_text(encoding="utf-8", errors="surrogateescape")
    if MARK in s:
        return "already"
    if ANCHOR not in s:
        return "skip: anchor not found"
    idx = s.index(ANCHOR)
    tail = s[idx:idx + 600]
    if FALSE_LINE not in tail:
        return "skip: false-line not found"
    new_tail = tail.replace(
        FALSE_LINE,
        "        /* 2026-11-02: 本机 sys_call_table 只读 ⇒ 分发器装不上；管理器通信用的是\n"
        "         * reboot kprobe + ioctl，不依赖分发器。别把这个标志压成 false，否则\n"
        "         * get_info 的 HOOK_READY 位为 0，管理器界面判「未安装」。 */\n"
        "        ksu_hook_backend_ready = true;\n"
        '        pr_alert("' + MARK + ' (dispatcher ret=%d)\\n", ret);',
        1,
    )
    s = s[:idx] + new_tail + s[idx + 600:]
    path.write_text(s, encoding="utf-8", errors="surrogateescape")
    return "patched"


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    cands = list(root.glob("**/kernel/core/init.c"))
    if not cands:
        print("[backend-ready] !! 没找到 kernel/core/init.c")
        return 1
    rc = 0
    for p in cands:
        r = patch(p)
        print(f"[backend-ready] {p.relative_to(root)} : {r}")
        if r.startswith("skip"):
            rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
