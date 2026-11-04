#!/usr/bin/env python3
"""
selinux_hide 真正的死因：三个 hook 都用 ksu_patch_text 去改 .data 里的函数指针，
而 ksu_patch_text 只对内核 text 段有效 —— 日志里 ret=0 但目标值一点没变。

实测（boot f526b367）：
  HOOKTRACE context_write after patch: 0x...92e4 (my=0x...8b70) ret=0
  → 0x...92e4 还是 sel_write_context，根本没换成 hook。

本补丁：
  1) 三处函数指针改成 memcpy 直接写（.data 本来就可写）
  2) context/access 的 hook 换成「参数自适应」包装：先 copy_from_user，
     失败就按内核缓冲区处理 —— 这内核的 write_op[] 到底收内核 buffer
     还是 __user 指针不确定，两种都不能崩
"""
import os
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
path = os.path.join(root, "kernel", "feature", "selinux_hide.c")
if not os.path.exists(path):
    print("not found:", path)
    sys.exit(0)
src = open(path, encoding="utf-8", errors="surrogateescape").read()
if "DIRECTSTORE" in src:
    print("already patched")
    sys.exit(0)

anchor = "static int ksu_selinux_hide_enable()"
i = src.find(anchor)
if i < 0:
    print("enable() not found")
    sys.exit(1)

wrappers = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "selinux_hide_wrappers.inc"),
                encoding="utf-8").read()
src = src[:i] + wrappers + src[i:]

fails = []


def rep(old, new, tag):
    global src
    if src.count(old) != 1:
        fails.append(tag)
        return
    src = src.replace(old, new, 1)


rep("""    write_op_fn my = my_write_context;
    orig_context_write = *context_write;
    ret = ksu_patch_text(context_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """    write_op_fn my = (write_op_fn)(void *)my_write_context_auto;
    orig_context_write = *context_write;
    memcpy((void *)context_write, &my, sizeof(my)); /* DIRECTSTORE: .data 直接写 */
    ret = 0;""", "install-context")

rep("""    my = my_write_access;
    orig_access_write = *access_write;
    ret = ksu_patch_text(access_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """    my = (write_op_fn)(void *)my_write_access_auto;
    orig_access_write = *access_write;
    memcpy((void *)access_write, &my, sizeof(my)); /* DIRECTSTORE: .data 直接写 */
    ret = 0;""", "install-access")

rep("""        ret =
            ksu_patch_text(context_write, &orig_context_write, sizeof(orig_context_write), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """        memcpy((void *)context_write, &orig_context_write, sizeof(orig_context_write)); /* DIRECTSTORE */
        ret = 0;""", "unhook-context")

rep("""        ret = ksu_patch_text(access_write, &orig_access_write, sizeof(orig_access_write), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """        memcpy((void *)access_write, &orig_access_write, sizeof(orig_access_write)); /* DIRECTSTORE */
        ret = 0;""", "unhook-access")

rep("""        ret = ksu_patch_text(sel_open_handle_status_slot, &orig_sel_open_handle_status,
                             sizeof(orig_sel_open_handle_status), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """        memcpy((void *)sel_open_handle_status_slot, &orig_sel_open_handle_status,
               sizeof(orig_sel_open_handle_status)); /* DIRECTSTORE */
        ret = 0;""", "unhook-status")

rep("""    int ret = ksu_patch_text(sel_open_handle_status_slot, &new_fn, sizeof(new_fn), KSU_PATCH_TEXT_FLUSH_DCACHE);""",
    """    memcpy((void *)sel_open_handle_status_slot, &new_fn, sizeof(new_fn)); /* DIRECTSTORE */
    int ret = 0;
    pr_info("selinux_hide: DIRECTSTORE status_open slot=0x%lx now=0x%lx\\n",
            (unsigned long)sel_open_handle_status_slot, (unsigned long)*sel_open_handle_status_slot);""",
    "install-status")

if fails:
    print("!! 这些替换点没命中:", ", ".join(fails))
    sys.exit(1)

open(path, "w", encoding="utf-8", newline="\n", errors="surrogateescape").write(src)
print("patched: direct-store + adaptive wrappers; ksu_patch_text left =", src.count("ksu_patch_text"))
