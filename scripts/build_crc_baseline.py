#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从「已知能在目标内核上装载」的 .ko 反推 CRC 基准表（config/device-crc-os11.json）。

背景：os10 那边 `config/device_crc.json` 是从设备 436 个厂商 ko 的 `__versions` 扫出来的
（设备在手，直接 adb pull /vendor/lib/modules/*.ko）。os11 现在没有设备可用，但有一份
**作者包里配 110 内核编的** `kernelsu_v325_os11.ko` —— 它的 `__versions` 就是该内核+该 config
下的真实 CRC。用它当基准，就能判断「同一棵树 + 我们的 device.config 编出来的 ko 能不能装」。

用法：
    python scripts/build_crc_baseline.py out.json a.ko b.ko ...
    python scripts/build_crc_baseline.py --check out.json artifacts/kernelsu_finasu121_os11.ko

退出码：0 成功 / 1 找不到 __versions / 2 多份 ko 之间 CRC 冲突
"""
import argparse
import json
import sys

# 复用 check_crc.py 的解析（同一个 __versions 结构：u64 crc + char name[56]）
from check_crc import crc_pairs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("kos", nargs="*")
    ap.add_argument("--check", default="", help="只做校验：把 out 当基准比这个 ko")
    ap.add_argument("--label", default="", help="写进 JSON 的 _source 说明")
    args = ap.parse_args()

    if args.check:
        sys.path.insert(0, ".")
        from check_crc import main as check_main
        return check_main(args.check, args.out)

    base, conflict, srcs = {}, {}, []
    for ko in args.kos:
        pairs = crc_pairs(ko)
        if not pairs:
            print(f"!! {ko}: 没有 __versions 段（不是 MODVERSIONS 构建？）")
            return 1
        srcs.append({"ko": ko, "symbols": len(pairs)})
        for name, crc in pairs.items():
            if name in base and base[name] != crc:
                conflict.setdefault(name, []).append((ko, crc))
            base[name] = crc

    data = {"_source": args.label or "; ".join(f"{s['ko']}({s['symbols']})" for s in srcs)}
    data.update(dict(sorted(base.items())))
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=0)
        f.write("\n")

    print(f"基准表 → {args.out}：{len(base)} 个符号")
    for s in srcs:
        print(f"  from {s['ko']}  {s['symbols']} 个")
    if conflict:
        print(f"!! {len(conflict)} 个符号在多份 ko 之间 CRC 不一致（说明它们不是同一次构建）：")
        for k, v in list(conflict.items())[:10]:
            print(f"   {k}: " + ", ".join(f"{p}→0x{c:08x}" for p, c in v))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
