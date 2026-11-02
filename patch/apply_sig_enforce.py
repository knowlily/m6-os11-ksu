#!/usr/bin/env python3
"""把 sig_enforce 写回 1（exploit 为了 insmod 未签名模块会把它清成 0）。

为什么不写在 syscall_hook.c 里：那个文件已经被注入器改得很满，任何结构改动都可能把
后面的 `#include` 顶进函数体（2026-11-02 就因为这个连环炸过一次）。这里独立成一个编译
单元，只做一件事，出错也只影响它自己。

做法：
  1. 新建 `<ksu>/kernel/ksu_sigenforce.c`
  2. 往 `<ksu>/kernel/Kbuild` 追加 `kernelsu-objs += ksu_sigenforce.o`
  3. 在 `kernelsu_init()` 里、**最后一个 return 之前**插调用
     （插在右大括号前会落到 return 之后成死代码 —— 这个坑在 2026-11-02 踩过）

符号 `sig_enforce` 是内核里的 static 变量（kallsyms 里是 `d`），模块自己 link 不上，
靠离线 patcher 按 kallsyms 解析成绝对地址（和 commit_creds 一样）。所以这里只写
`extern bool sig_enforce;`，绝不能加 weak（weak 会生成 R_AARCH64_ADR_GOT_PAGE→ENOEXEC）。

用法: python3 patch/apply_sig_enforce.py <ksu_src_root>
幂等：重复执行不会叠加。
"""
import os
import sys

NL = chr(10)
MARKER = "ksu_sp_restore_sigenforce"
OBJ = "ksu_sigenforce.o"

SRC = """// SPDX-License-Identifier: GPL-2.0
/*
 * m6 补丁：装载成功后把 sig_enforce 写回 1。
 *
 * 背景：CVE-2026-98260 链在 insmod 未签名模块之前，会把内核的 sig_enforce 清成 0。
 * 这个参数在 sysfs 上是 0444（只读），用户态没法写回去，只能在内核侧直接改全局量。
 *
 * 符号解析：sig_enforce 是 kernel/module/signing.c 里的 static bool，没 EXPORT_SYMBOL，
 * 所以模块这边留 UND，由离线 patcher 从 /proc/kallsyms 取地址回填。
 * 注意：绝不能写成 __attribute__((weak)) —— 那会生成 R_AARCH64_ADR_GOT_PAGE(311)，
 * 本机模块加载器不支持 GOT 重定位，装的时候直接 ENOEXEC。
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>

extern bool sig_enforce;

void ksu_sp_restore_sigenforce(void)
{
	if (sig_enforce) {
		pr_alert("ksu: sig_enforce already 1\\n");
		return;
	}

	sig_enforce = true;
	pr_alert("ksu: sig_enforce restored to 1\\n");
}
"""


def insert_call(path):
    """在 kernelsu_init() 的最后一个 return 之前插入调用。"""
    if not os.path.exists(path):
        return "skip: no init.c"
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        s = f.read()
    if MARKER in s:
        return "already"

    anchor = "int __init kernelsu_init(void)"
    if anchor not in s:
        return "skip: anchor not found"
    idx = s.index(anchor)
    brace = s.find("{", idx)
    if brace < 0:
        return "skip: no body"

    depth = 0
    end = -1
    for i in range(brace, len(s)):
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end < 0:
        return "skip: body not closed"

    body = s[brace:end]
    rel = body.rfind("return")
    if rel < 0:
        return "skip: no return in body"
    abs_pos = brace + rel
    line_start = s.rfind(NL, 0, abs_pos) + 1
    indent = s[line_start:abs_pos]
    if indent.strip():
        indent = "    "

    call = (indent + "extern void ksu_sp_restore_sigenforce(void);" + NL
            + indent + "ksu_sp_restore_sigenforce();" + NL)
    s = s[:line_start] + call + s[line_start:]

    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(s)
    return "patched"


def add_to_kbuild(path):
    if not os.path.exists(path):
        return "skip: no Kbuild"
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        s = f.read()
    if OBJ in s:
        return "already"
    if not s.endswith(NL):
        s += NL
    s += "# m6: sig_enforce 恢复（独立编译单元）" + NL
    s += "kernelsu-objs += " + OBJ + NL
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(s)
    return "patched"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    root = sys.argv[1]
    kernel = os.path.join(root, "kernel")
    if not os.path.isdir(kernel):
        print("[sig] 找不到 kernel/ 目录: %s" % kernel)
        return 1

    src = os.path.join(kernel, "ksu_sigenforce.c")
    with open(src, "w", encoding="utf-8", newline=NL) as f:
        f.write(SRC.replace(chr(13) + chr(10), chr(10)).replace(chr(13), chr(10)))
    print("[sig] 写入 %s" % os.path.relpath(src, root))

    print("[sig] Kbuild: %s" % add_to_kbuild(os.path.join(kernel, "Kbuild")))
    print("[sig] init.c: %s" % insert_call(os.path.join(kernel, "core", "init.c")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
