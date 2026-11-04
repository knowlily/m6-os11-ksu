#!/usr/bin/env python3
"""
让 selinux_hide 的 backup_sepolicy 只抓一次。

apply_kernelsu_rules() 在 KSU 的流程里可能被调用多次（重放/重装模块/ksud 二次应用）。
它每次都会无条件 `backup_sepolicy = ksu_dup_sepolicy(old_pol)`，而第二次开始
old_pol 已经是「注入了 KSU 规则」的那份策略 —— 备份被污染。

后果：selinux_hide 用这份备份回答 App(uid>=10000) 对 /sys/fs/selinux/{context,access}
的查询，于是 u:r:ksu:s0 / u:object_r:ksu_file:s0 依旧 "valid"，
第三方检测器（LSPosed/DirtySepolicy 那套）照样能认出来。

修法：只在 backup_sepolicy 为空时抓快照。
"""
import os
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
path = os.path.join(root, "kernel", "selinux", "rules.c")
if not os.path.exists(path):
    print("rules.c not found:", path)
    sys.exit(0)

src = open(path, encoding="utf-8", errors="surrogateescape").read()
if "backup_once" in src:
    print("already patched")
    sys.exit(0)

START = "backup_sepolicy = ksu_dup_sepolicy(old_pol);"
END = "pol = ksu_dup_sepolicy(old_pol);"
i = src.find(START)
if i < 0:
    print("START marker not found")
    sys.exit(1)
j = src.find(END, i)
if j < 0:
    print("END marker not found")
    sys.exit(1)

block = src[i:j]
indented = "\n".join(("    " + ln if ln.strip() else ln) for ln in block.splitlines())
guarded = (
    "/* backup_once: 只在第一次应用规则时抓快照，避免被后续调用污染 */\n"
    "    if (!backup_sepolicy) {\n"
    + indented
    + "\n    }\n"
)
out = src[:i] + guarded + src[j:]
open(path, "w", encoding="utf-8", newline="\n", errors="surrogateescape").write(out)
print("patched: backup_sepolicy capture is now one-shot")
