#!/usr/bin/env python3
"""审计一个 APK（或目录）里的 kernelsu*.ko：vermagic / 版本常数 / 上报函数 是否都成立。

用法：
    python scripts/audit_apk_kos.py D:/githubs/ksu-app/dist/M6Shell-9.30-multimgr.apk
    python scripts/audit_apk_kos.py payload/os11 --expect-build g84ffa64b710b
    python scripts/audit_apk_kos.py a.ko b.ko --json

判据（与 App 里 KoPatcher 的定位方式一致，所以「这里过」= 现场改版本号这条路能走）：
  1. ELF64 LE、有 .text / .symtab；
  2. 同时存在 do_get_info 与 do_get_info_legacy 两个非空符号；
  3. 两个函数体里「都出现、30_000..65535、后面不跟 movk」的 movz 立即数**正好一个** → 那就是编进去的 KSU_VERSION；
  4. vermagic 命中 --expect-build（不给则只记录）。

退出码：0 = 全部通过；1 = 有文件不合格；2 = 用法/读文件错误。
"""
import argparse
import json
import os
import re
import struct
import sys
import zipfile

VERSION_FUNCS = ("do_get_info", "do_get_info_legacy")
VERSION_MIN, VERSION_MAX = 30000, 65535


def sections(b):
    if len(b) < 64 or b[:4] != b"\x7fELF":
        raise ValueError("不是 ELF")
    if b[4] != 2:
        raise ValueError("不是 ELF64")
    if b[5] != 1:
        raise ValueError("不是小端 ELF")
    shoff = struct.unpack_from("<Q", b, 0x28)[0]
    shent, shnum, shstr = struct.unpack_from("<HHH", b, 0x3A)
    if shoff <= 0 or shent < 64 or shnum <= 0 or shstr >= shnum:
        raise ValueError("节表不合法")
    raw = []
    for i in range(shnum):
        o = shoff + i * shent
        name_off, typ = struct.unpack_from("<II", b, o)
        addr, off, size = struct.unpack_from("<QQQ", b, o + 16)
        link = struct.unpack_from("<I", b, o + 40)[0]
        raw.append(dict(name_off=name_off, type=typ, addr=addr, off=off, size=size, link=link))
    base = raw[shstr]["off"]
    for s in raw:
        end = b.index(b"\x00", base + s["name_off"])
        s["name"] = b[base + s["name_off"]:end].decode("latin1")
    return raw


def symbols(b, secs):
    symtab = next((s for s in secs if s["type"] == 2), None)
    if symtab is None:
        raise ValueError("没有 .symtab（被 strip 过？）")
    strtab = secs[symtab["link"]]
    out = {}
    for i in range(symtab["size"] // 24):
        o = symtab["off"] + i * 24
        name_off = struct.unpack_from("<I", b, o)[0]
        value, size = struct.unpack_from("<QQ", b, o + 8)
        if not size:
            continue
        end = b.index(b"\x00", strtab["off"] + name_off)
        name = b[strtab["off"] + name_off:end].decode("latin1")
        out.setdefault(name, (value, size))
    return out


def movz_candidates(b, start, end):
    """函数体内的 movz wN,#imm16；跳过后面紧跟同寄存器 movk 的长常数。"""
    out = set()
    i = start
    while i + 4 <= end:
        w = struct.unpack_from("<I", b, i)[0]
        if (w & 0xFF800000) == 0x52800000:
            rd = w & 0x1F
            nxt = struct.unpack_from("<I", b, i + 4)[0] if i + 8 <= end else 0
            long_const = ((nxt & 0xFF800000) in (0x72800000, 0xF2800000)) and (nxt & 0x1F) == rd
            if not long_const:
                imm = (w >> 5) & 0xFFFF
                if VERSION_MIN <= imm <= VERSION_MAX:
                    out.add(imm)
        i += 4
    return out


def verdet(b):
    """返回 (候选版本列表, 找到的上报函数个数)。"""
    secs = sections(b)
    text = next((s for s in secs if s["name"] == ".text"), None)
    if text is None:
        raise ValueError("没有 .text")
    syms = symbols(b, secs)
    sets = []
    for fn in VERSION_FUNCS:
        if fn not in syms:
            continue
        val, size = syms[fn]
        start = text["off"] + (val - text["addr"])
        sets.append(movz_candidates(b, start, start + size))
    if not sets:
        return [], 0
    common = sets[0]
    for s in sets[1:]:
        common &= s
    return sorted(common), len(sets)


def audit(name, b, expect_build):
    row = {"name": name, "size": len(b), "ok": False, "error": None,
           "version": None, "funcs": 0, "vermagic": None, "build": None}
    m = re.search(rb"vermagic=(\S+) (\S+)", b)
    if m:
        row["vermagic"] = m.group(0).decode("latin1")
        vm = m.group(1).decode("latin1")
        row["build"] = vm.rsplit("-g", 1)[-1] if "-g" in vm else vm
    try:
        cands, nfuncs = verdet(b)
    except ValueError as e:
        row["error"] = str(e)
        return row
    row["funcs"] = nfuncs
    row["version"] = cands[0] if len(cands) == 1 else None
    problems = []
    if nfuncs < 2:
        problems.append(f"上报函数只有 {nfuncs} 个（要 2 个才能全改）")
    if len(cands) != 1:
        problems.append(f"版本常数候选 {cands}（应正好 1 个）")
    if row["vermagic"] is None:
        problems.append("读不到 vermagic")
    elif expect_build and row["build"] != expect_build:
        problems.append(f"vermagic 内核串是 {row['build']}，期望 {expect_build}")
    row["error"] = "; ".join(problems) or None
    row["ok"] = not problems
    return row


def collect(path):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in sorted(files):
                if f.endswith(".ko"):
                    p = os.path.join(root, f)
                    yield os.path.relpath(p, path), open(p, "rb").read()
    elif path.lower().endswith(".apk"):
        with zipfile.ZipFile(path) as z:
            for n in sorted(z.namelist()):
                if n.startswith("assets/") and n.endswith(".ko"):
                    yield n[len("assets/"):], z.read(n)
    elif path.endswith(".ko"):
        yield os.path.basename(path), open(path, "rb").read()
    else:
        raise SystemExit(f"不认识的目标：{path}（给 .apk / .ko / 目录）")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+", help=".apk / .ko / 目录")
    ap.add_argument("--expect-build", default="",
                    help="要求 vermagic 的内核串，如 g84ffa64b710b 或 g7db56fb8f741")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    a = ap.parse_args()

    rows = []
    for t in a.targets:
        try:
            for name, blob in collect(t):
                rows.append(audit(f"{os.path.basename(t)}:{name}", blob, a.expect_build))
        except (OSError, zipfile.BadZipFile) as e:
            print(f"!! 读不了 {t}: {e}", file=sys.stderr)
            return 2

    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        for r in rows:
            flag = "OK  " if r["ok"] else "FAIL"
            ver = f"{r['version']}" if r["version"] else "-"
            build = r["build"] or "-"
            print(f"{flag} {r['name']:<62s} {r['size']:>8d}B  ver={ver:>6s} funcs={r['funcs']} kernel={build}")
            if r["error"]:
                print(f"     ↳ {r['error']}")
        bad = sum(1 for r in rows if not r["ok"])
        print(f"\n{len(rows)} 份 ko，不合格 {bad}")
    return 0 if all(r["ok"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
