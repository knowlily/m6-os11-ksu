#!/usr/bin/env python3
"""
给 selinux_hide 的两个 write hook 加进入日志。

目的：区分两种失败
  A) hook 被调用，但 backup_sepolicy 里也带着 ksu 类型 → 回答仍是 valid（备份脏）
  B) hook 根本没被调用（本内核的 selinuxfs 用的是 sel_context_ops 里那份拷贝，
     而我们只改了 write_op[] 这个模板数组）→ 机制在此内核上是死的

做法：在 my_write_context / my_write_access 开头插一行 pr_info(uid, size)，
并在 enable() 打完 patch 后回读一次数组元素，确认写入生效。
"""
import os
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
path = os.path.join(root, "kernel", "feature", "selinux_hide.c")
if not os.path.exists(path):
    print("selinux_hide.c not found:", path)
    sys.exit(0)
src = open(path, encoding="utf-8", errors="surrogateescape").read()
if "HOOKTRACE" in src:
    print("already patched")
    sys.exit(0)

def inject(src, fname, tag):
    # 签名可能是 ssize_t / static ssize_t，buf 可能是 char * 或 const char __user *
    key = "ssize_t %s(struct file *file," % fname
    i = src.find(key)
    if i < 0:
        print("signature not found for", fname)
        return src
    brace = src.find("{", i)
    if brace < 0:
        return src
    ins = ("\n    /* HOOKTRACE */ pr_info(\"selinux_hide: HOOK %s uid=%%d size=%%zu\\n\","
           " current_uid().val, size);" % tag)
    return src[:brace + 1] + ins + src[brace + 1:]

src = inject(src, "my_write_context", "context")
src = inject(src, "my_write_access", "access")

# 打完 patch 后回读，确认数组元素真的变成本 hook
old = """    ret = ksu_patch_text(context_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);"""
new = """    ret = ksu_patch_text(context_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);
    pr_info(\"selinux_hide: HOOKTRACE context_write after patch: 0x%lx (my=0x%lx) ret=%d\\n\",
            (unsigned long)*context_write, (unsigned long)(void *)my, ret);"""
if old in src:
    src = src.replace(old, new, 1)
old2 = """    ret = ksu_patch_text(access_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);"""
new2 = """    ret = ksu_patch_text(access_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);
    pr_info(\"selinux_hide: HOOKTRACE access_write after patch: 0x%lx (my=0x%lx) ret=%d\\n\",
            (unsigned long)*access_write, (unsigned long)(void *)my, ret);"""
if old2 in src:
    src = src.replace(old2, new2, 1)

open(path, "w", encoding="utf-8", newline="\n", errors="surrogateescape").write(src)
print("patched hooks with HOOKTRACE")
