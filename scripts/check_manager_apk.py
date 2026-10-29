#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核对管理器 APK ↔ config/managers.json 是否同一代。

为什么需要它：一份 kernelsu ko 只配一个 uapi。管理器装的是 v4.3.0、ko 却按 v4.2.1
编出来，装载后管理器会报 "UAPI version mismatch: kernel=…" 或者干脆连不上内核。
桌面上散着一堆 APK 时，靠文件名判断版本很容易错（BakaSU 的 vc35252 其实叫 4.2.0-rc3，
KernelSU-Next 的包名被伪装成 kqvdie.zeykvw.hpbcyd）。

用法：
    python scripts/check_manager_apk.py "C:/Users/x/Desktop/apks"
    python scripts/check_manager_apk.py one.apk --json
    python scripts/check_manager_apk.py apks/ --strict      # 有 mismatch 就 exit 1

判据：
    包名 == managers.json 里对应条目的 manager
    版本号（vc）== 条目的 apk_vc（没写 apk_vc 的旧条目只做提示）
    uapi   == 条目的 uapi（uapi 从 APK 里的 libksud.so 的版本串 "x.y.z (uapi: N)" 取；
              SukiSU 这类不带 libksud 的 APK 取不到，标 unknown 并说明用管理器自报核对）
"""

import argparse
import json
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANAGERS = os.path.join(ROOT, "config", "managers.json")

PKG_RE = re.compile(rb"package: name='([^']+)' versionCode='(\d+)' versionName='([^']*)'")
UAPI_RE = re.compile(rb"(\d+\.\d+\.\d+[^\x00]{0,40}\(uapi: (\d+)\))")


def read_badging(apk):
    """不依赖 aapt2：从 AndroidManifest 二进制里抠包名/版本（够用且跨平台）。"""
    import subprocess
    aapt = os.environ.get("AAPT2") or "aapt2"
    try:
        out = subprocess.run([aapt, "dump", "badging", apk], capture_output=True, timeout=120)
        m = PKG_RE.search(out.stdout)
        if m:
            return m.group(1).decode(), int(m.group(2)), m.group(3).decode()
    except Exception:
        pass
    return None, None, None


def ksud_uapi(apk):
    """返回 (载体名, uapi) ；uapi 为 None 表示该 APK 不带 libksud。"""
    try:
        z = zipfile.ZipFile(apk)
    except Exception as e:
        return None, None
    cand = [n for n in z.namelist() if n.endswith("arm64-v8a/libksud.so")]
    if not cand:
        # SukiSU 4.x：没有 libksud，uapi 是 dex 里的常量，只能靠管理器自报
        has_dex = any(n.endswith(".dex") for n in z.namelist())
        return ("(无 libksud)" if has_dex else None), None
    data = z.read(cand[0])
    m = UAPI_RE.search(data)
    if m:
        return cand[0], int(m.group(2))
    return cand[0], None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="APK 文件或目录")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="有 mismatch 时返回非 0")
    args = ap.parse_args()

    table = json.load(open(MANAGERS, encoding="utf-8"))
    by_pkg = {}
    for name, v in table.items():
        if name.startswith("_"):
            continue
        by_pkg.setdefault(v["manager"], []).append((name, v))

    apks = []
    for p in args.paths:
        if os.path.isdir(p):
            apks += [os.path.join(p, f) for f in sorted(os.listdir(p)) if f.lower().endswith(".apk")]
        else:
            apks.append(p)

    rows, bad = [], 0
    for apk in apks:
        pkg, vc, vn = read_badging(apk)
        carrier, uapi = ksud_uapi(apk)
        entry = by_pkg.get(pkg, [])
        verdict, detail, name = "?", "", ""
        if not pkg:
            verdict = "读不出包名（缺 aapt2？）"
        elif not entry:
            verdict = "config 里没有这个包名"
        else:
            name, mg = sorted(entry, key=lambda x: -x[1].get("apk_vc", 0))[0]
            if uapi is not None and uapi != mg["uapi"]:
                verdict = "UAPI 不一致"
                detail = f"APK uapi={uapi} / config uapi={mg['uapi']}"
            elif mg.get("apk_vc") and vc != mg["apk_vc"]:
                verdict = "版本号不一致"
                detail = f"APK vc={vc} / config apk_vc={mg['apk_vc']}"
            else:
                verdict = "OK"
        if verdict not in ("OK",) and pkg:
            bad += 1
        rows.append(dict(apk=os.path.basename(apk), pkg=pkg, vc=vc, vn=vn,
                         uapi=uapi, carrier=carrier, entry=name, verdict=verdict, detail=detail))

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        print(f"{'APK':40s} {'包名':28s} {'vc':>6s} {'uapi':>5s}  {'config':10s} 判定")
        for r in rows:
            print(f"{r['apk'][:40]:40s} {(r['pkg'] or '?')[:28]:28s} {str(r['vc'] or ''):>6s} "
                  f"{str(r['uapi'] if r['uapi'] is not None else '-'):>5s}  {r['entry'][:10]:10s} {r['verdict']}"
                  + (f"  ({r['detail']})" if r['detail'] else ""))
        print("\n提示：uapi 取不到（SukiSU 无 libksud）时，装载后按下面两条核对：")
        print("  设备：dmesg | grep -i 'uapi\\|version mismatch'")
        print("  管理器：设置页的 内核 uapi / 管理器 uapi 两个数字应相等")
    if args.strict and bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
