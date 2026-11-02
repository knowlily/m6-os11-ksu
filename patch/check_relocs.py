#!/usr/bin/env python3
"""扫 ko 的 .rela 段，拦住本机内核模块加载器不支持的重定位类型。

背景：AArch64 上 `R_AARCH64_ADR_GOT_PAGE`(311) / `LD64_GOT_LO12_NC`(312) /
`LD64_GOTPAGE_LO15`(313) 会走 GOT，而 honor 这颗厂商内核的
`apply_relocate_add()` 不认它们，装载直接 `errno=8 ENOEXEC`
（dmesg: `unsupported RELA relocation: 311`）。

典型来源：对模块内符号用 `__attribute__((weak))` 取地址。

用法：
    python3 patch/check_relocs.py out/ci/foo.ko [more.ko ...]
退出码 1 = 有不支持的重定位。
"""
import struct
import sys
from collections import Counter

BAD = {311: "ADR_GOT_PAGE", 312: "LD64_GOT_LO12_NC", 313: "LD64_GOTPAGE_LO15"}


def rela_types(path):
    d = open(path, "rb").read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize = struct.unpack_from("<H", d, 0x3a)[0]
    shnum = struct.unpack_from("<H", d, 0x3c)[0]
    c = Counter()
    for i in range(shnum):
        off = shoff + i * shentsize
        if struct.unpack_from("<I", d, off + 4)[0] != 4:  # SHT_RELA
            continue
        sh_off = struct.unpack_from("<Q", d, off + 24)[0]
        sh_size = struct.unpack_from("<Q", d, off + 32)[0]
        for k in range(0, sh_size, 24):
            c[struct.unpack_from("<Q", d, sh_off + k + 8)[0] & 0xFFFFFFFF] += 1
    return c


def main(paths):
    bad = 0
    for p in paths:
        c = rela_types(p)
        hits = {t: c.get(t, 0) for t in BAD if c.get(t, 0)}
        total = sum(c.values())
        print(f"{p}: relas={total} " + ("".join(f"{BAD[t]}={n} " for t, n in hits.items()) or "GOT=0"))
        if hits:
            bad = 1
            print(f"  !! {p} 含 GOT 重定位，装上去会 ENOEXEC —— 检查是否有 weak 引用")
    return bad


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
