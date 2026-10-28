#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 ko 的 `__versions` 段原地清零（sh_size = 0），做出「B 路线」产物。

为什么要这么绕，而不是直接 `-d MODVERSIONS` 编：
    内核比对的是**整串** vermagic，其中 `modversions` 这个 token 由构建内核的
    CONFIG_MODVERSIONS 决定。设备内核是 MODVERSIONS=y ⇒ 它的 VERMAGIC_STRING 里带
    `modversions`；我们若关掉再编，产物 vermagic 少这个 token，insmod 直接被拒。

    所以正确姿势是：**开着 MODVERSIONS 编**（vermagic 形状对），编完把 `__versions`
    段长度清零（内核遍历版本条目时得到 0 条 ⇒ 不做任何 CRC 比对），未定义符号由装载器
    `ko_patch2 <ko> /proc/kallsyms` 改写成 live 地址的 SHN_ABS。
    作者包里的 kernelsu_v325_os11.ko 就是这个形状。

用法:
    python3 scripts/strip_versions.py out.ko [more.ko ...]     # 原地改
    python3 scripts/strip_versions.py --dry out.ko             # 只报告
"""
import struct
import sys

SHT = 0x28  # e_shoff 偏移
SHENTSIZE = 0x3A


def sections(data):
    e_shoff, = struct.unpack_from("<Q", data, SHT)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, SHENTSIZE)
    shs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        shs.append(dict(i=i, hdr=off, name=name, type=typ, offset=offset, size=size))
    st = shs[e_shstrndx]
    names = data[st["offset"]:st["offset"] + st["size"]]
    for s in shs:
        s["sname"] = names[s["name"]:names.find(b"\0", s["name"])].decode("latin1")
    return shs


def main(argv):
    dry = "--dry" in argv
    files = [a for a in argv[1:] if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    rc = 0
    for p in files:
        data = bytearray(open(p, "rb").read())
        hit = 0
        for s in sections(data):
            if s["sname"] == "__versions" or s["sname"].startswith("__version_ext"):
                if s["size"] == 0:
                    print(f"  {p}: {s['sname']} 已经是 size=0")
                    continue
                # sh_size 是该 section header 里的第 6 个字段（偏移 +32）
                struct.pack_into("<Q", data, s["hdr"] + 32, 0)
                print(f"  {p}: {s['sname']} {s['size']}B → 0")
                hit += 1
        if hit and not dry:
            open(p, "wb").write(bytes(data))
        if not hit:
            print(f"  {p}: 没有需要清空的版本段（本来就没有）")
        rc |= 0
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
