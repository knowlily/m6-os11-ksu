#!/usr/bin/env python3
"""把 ko 里报给管理器的 KSU_VERSION 改成指定值（各管理器自己的版本号）。

各家算版本的写法不一样，但都落在 kernel/Kbuild 里：
  tiann/FinaSU/Next : $(eval KSU_VERSION=$(shell expr 30000 + $(KSU_GIT_VERSION)))
                      ccflags-y += -DKSU_VERSION=$(KSU_VERSION)      （无 git 时 =16 / $(KSU_VERSION_FALLBACK)）
  SukiSU            : ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
  BakaSU            : KSU_VERSION := $(shell expr 30000 + ... + 700)

只动 KSU_VERSION，不碰 KSU_VERSION_FULL / KSU_VERSION_TAG，也不碰 uapi 版本。

用法: python3 patch/set_version.py <ksu_src_dir> <version_int>
"""
import re
import sys
import pathlib


def main(root, ver):
    if not ver.isdigit():
        raise SystemExit("version 必须是十进制整数，收到: %r" % ver)
    kb = pathlib.Path(root) / "kernel" / "Kbuild"
    if not kb.exists():
        raise SystemExit("找不到 %s" % kb)
    s = kb.read_text(encoding="utf-8")
    orig = s

    # 1) 赋值形式：$(eval KSU_VERSION=...) 或 KSU_VERSION := $(shell ...)
    # 整行替换（原来的非贪婪写法会把 $(KSU_GIT_VERSION) 的右括号吃掉，留下 ")))" → make 报 missing separator）
    s = re.sub(r"^([ 	]*)\$\(eval KSU_VERSION=.*$",
               lambda m: m.group(1) + "$(eval KSU_VERSION=%s)" % ver, s, flags=re.M)
    s = re.sub(r"^(\s*)KSU_VERSION\s*:?=\s*\$\(shell expr[^\n]*",
               r"\1KSU_VERSION := %s" % ver, s, flags=re.M)
    # 2) 编译宏：-DKSU_VERSION=...（排除 _FULL / _TAG）
    s = re.sub(r"(-DKSU_VERSION=)(?!FULL|TAG)[^\s\\]+", r"\g<1>%s" % ver, s)

    if s == orig:
        raise SystemExit("kernel/Kbuild 里没找到可改的 KSU_VERSION —— 检查上游结构是否变了")
    kb.write_text(s, encoding="utf-8")

    hits = [l.strip() for l in s.splitlines() if "-DKSU_VERSION=" in l]
    print("set_version: KSU_VERSION=%s" % ver)
    for h in hits:
        print("  " + h)
    if not any(("-DKSU_VERSION=%s" % ver) in h for h in hits):
        raise SystemExit("改完没有出现 -DKSU_VERSION=%s" % ver)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
