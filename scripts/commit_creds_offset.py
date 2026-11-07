#!/usr/bin/env python3
"""从 Android boot.img 直接算出 commit_creds 的内核相对偏移。

用途：patcher 的 --fallback commit_creds=<off> 不能靠现场抓 /proc/kallsyms（有些场景
读不到、或 chain 前半段还没 root）。既然内核镜像能拿到，就直接把偏移算出来烘进脚本。

原理：
  __ksymtab 里每个条目是 3 个 s32 相对偏移（PREL32）：
      struct kernel_symbol {
          int value_offset;      /* 相对 &value_offset 自身 */
          int name_offset;       /* 相对 &name_offset 自身（即条目 +4） */
          int namespace_offset;
      };
  所以对一个位于文件偏移 F 的条目：
      name_addr = F + 4 + name_offset
      value_addr = F + 0 + value_offset
  本脚本先把 kernel 段切出来（跳过 ANDROID! header），此后所有偏移都以 Image 起点
  为基准。PREL32 是位置无关的「符号 − 字段自身」，加出来的正好就是相对 Image 起点的
  位置，所以：
      kimg_offset = value_addr            （不要再减 0x1000）

用法:
    python3 scripts/commit_creds_offset.py <boot.img> [符号名]
输出:
    0x15fe88    （可直接抄进 kgo.sh 的 case 表）
"""
import struct
import sys

SYM_DEFAULT = "commit_creds"


def load_kernel(path: str) -> bytes:
    """从 boot.img 里取出未压缩的内核（只支持 Image 直出，跟 honor 6.1 一致）。"""
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:8] != b"ANDROID!":
        raise SystemExit("不是 Android boot image（magic 不对）")
    kernel_size = struct.unpack_from("<I", blob, 8)[0]
    header_version = struct.unpack_from("<I", blob, 40)[0] if len(blob) > 44 else 0
    # v3/v4 的 header 是 1584 字节；v0~v2 是 1632 字节
    hdr = 1584 if header_version >= 3 else 1632
    start = (hdr + 4095) & ~4095
    kernel = blob[start:start + kernel_size]
    if len(kernel) != kernel_size:
        raise SystemExit("kernel 段长度不对，可能这个镜像头解析有误")
    if kernel[:2] != b"MZ":
        print("[!] 内核不是未压缩的 Image（可能是 gzip/lz4），本脚本直接扫符号表会失败",
              file=sys.stderr)
    return kernel


def find_symbol(img: bytes, name: str) -> int:
    needle = name.encode() + b"\x00"
    n = len(img)
    for off in range(0, n - 12, 4):
        value_off, name_off, _ns = struct.unpack_from("<iii", img, off)
        name_addr = off + 4 + name_off
        if not (0 <= name_addr < n - len(needle)):
            continue
        if img[name_addr:name_addr + len(needle)] != needle:
            continue
        value_addr = off + value_off
        if not (0 <= value_addr < n):
            continue
        # PREL32 是「符号 − 字段自身」，扁平 Image 里加出来的就是相对 Image 起点的位置，
        # 不再减 header 的 0x1000（否则会少一个页）。
        return value_addr
    raise SystemExit(f"没找到 {name}（镜像可能被裁剪或符号表不在段内）")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    sym = sys.argv[2] if len(sys.argv) > 2 else SYM_DEFAULT
    img = load_kernel(path)
    off = find_symbol(img, sym)
    print(f"0x{off:x}")


if __name__ == "__main__":
    main()
