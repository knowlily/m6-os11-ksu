#!/usr/bin/env bash
# =============================================================================
#  pull_device_truth.sh —— 把「设备上的真相」抓成本仓库的两份基准
#
#  这是 m6-bvlgari-ksu 在 MagicOS 10 上用过的同一套办法（只是当初是手工做的）：
#    1) /proc/config.gz          → config/device-os11.config   （编 ko 的 .config 真源）
#    2) /vendor/lib/modules/*.ko → config/device-crc-os11.json （__versions CRC 基准）
#
#  为什么要抓：vermagic 只证明「版本串对上」，真正决定 ko 能不能用的是
#    · .config 里的 MODVERSIONS / CFI / 结构体开关
#    · 每个导入符号的 CRC（genksyms 按树的类型算出来的），差一个就 "disagrees about version"
#
#  用法（设备插上、adb 可用）：
#      bash scripts/pull_device_truth.sh                 # 自动挑唯一设备
#      PHONE_SERIAL=ACPR024524000114 bash scripts/pull_device_truth.sh
#      bash scripts/pull_device_truth.sh --config-only   # 只抓 config
#
#  产物落在仓库里，之后 CI 会自动用它（targets.json 里已指向这两个路径）。
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

SERIAL="${PHONE_SERIAL:-}"
CONFIG_ONLY=0
[ "${1:-}" = "--config-only" ] && CONFIG_ONLY=1

q() { # q "<cmd>"
  if [ -n "$SERIAL" ]; then adb -s "$SERIAL" shell "$1" 2>/dev/null
  else adb shell "$1" 2>/dev/null; fi
}
adbq() { # adbq pull <remote> <local>
  if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi
}

echo "=== 0. 识别设备"
MODEL=$(q 'getprop ro.product.model' | tr -d '\r')
REL=$(q 'uname -r' | tr -d '\r')
FINGER=$(q 'getprop ro.build.fingerprint' | tr -d '\r')
echo "  model : $MODEL"
echo "  kernel: $REL"
echo "  build : $FINGER"
case "$REL" in
  *g84ffa64b710b*) echo "  ✓ 正是 os11 目标内核" ;;
  *) echo "  !! 不是 os11 目标内核（要 *g84ffa64b710b*）——抓下来的东西不能当 os11 基准"
     echo "     继续会把 m6 的真相覆盖掉，已中止。确要抓请加 FORCE=1"
     [ "${FORCE:-0}" = "1" ] || exit 2 ;;
esac

echo "=== 1. 抓 .config"
CFG=$(mktemp)
if q 'ls -l /proc/config.gz' | grep -q config.gz; then
  adbq exec-out "sh -c 'zcat /proc/config.gz'" > "$CFG" 2>/dev/null
else
  echo "  /proc/config.gz 不在 ⇒ 试 IKCONFIG 从 boot 分区提（可能要 root）"
  q 'dd if=/dev/block/by-name/boot_a of=/data/local/tmp/_b.img bs=1M 2>/dev/null; ls -l /data/local/tmp/_b.img' | tail -1
  adbq exec-out "sh -c 'cat /data/local/tmp/_b.img'" > /tmp/_b.img 2>/dev/null
  python3 - <<'PY' || true
data = open("/tmp/_b.img","rb").read()
i, j = data.find(b"IKCFG_ST"), data.find(b"IKCFG_ED")
if i >= 0 and j > i:
    open("/tmp/_dev.config","wb").write(data[i+8:j]); print("  IKCFG 提取成功", j-i, "字节")
else:
    print("  !! boot.img 里没有 IKCFG_ST（CONFIG_IKCONFIG 未开）")
PY
  cp -f /tmp/_dev.config "$CFG" 2>/dev/null
fi
if [ -s "$CFG" ] && grep -q '^CONFIG_' "$CFG"; then
  TGT=${TARGET_CONFIG:-config/device-os11.config}
  cp -f "$CFG" "$TGT"
  echo "  → $TGT ($(grep -c '^CONFIG_' "$TGT") 条)"
  grep -E '^CONFIG_(MODVERSIONS|MODULE_SIG|CFI_CLANG|LTO)' "$TGT" | sed 's/^/    /'
else
  echo "  !! 没拿到 config（需要 root 或设备没开 IKCONFIG）"
  exit 3
fi
[ "$CONFIG_ONLY" = "1" ] && { echo "只抓 config，结束"; exit 0; }

echo "=== 2. 抓 /vendor/lib/modules/*.ko 当 CRC 基准"
TMPD=$(mktemp -d)
adbq pull /vendor/lib/modules "$TMPD/" >/dev/null 2>&1
N=$(ls "$TMPD"/modules/*.ko 2>/dev/null | wc -l)
echo "  拉到 $N 个厂商 ko"
if [ "$N" -lt 5 ]; then
  echo "  !! ko 太少（$N），可能被 SELinux 挡了。退路：adb shell su -c 'tar cf - /vendor/lib/modules' | tar xf -"
  exit 4
fi

# ★ 先把「不是主内核编的 ko」剔掉：Honor 的 /vendor_dlkm/lib/modules 里绝大多数是 DSP/ADSP
#   内核（例：6.1.57-gbfe3896ae95e）编的，混进去会污染基准表。
KEEP="$TMPD/main_kernel_ko"; mkdir -p "$KEEP"
python3 - "$TMPD/modules" "$KEEP" "$REL" <<'PY'
import glob, os, shutil, sys
src, dst, rel = sys.argv[1], sys.argv[2], sys.argv[3]
def vm(p):
    b = open(p, "rb").read(); i = b.find(b"vermagic=")
    if i < 0: return ""
    t = b[i + 9:i + 9 + 200]; out = []
    for ch in t:
        if ch in (0, 10, 13): break
        out.append(chr(ch))
    return "".join(out)
keep = 0
for p in glob.glob(os.path.join(src, "*.ko")):
    if vm(p).startswith(rel):
        shutil.copy2(p, dst); keep += 1
print(f"  与主内核 {rel} 匹配的 ko: {keep} 个")
if keep == 0:
    print("  !! 一个都没匹配上 ⇒ 这台机的厂商 ko 是别的内核编的（Honor 常见：DSP 6.1.57），")
    print("     CRC 基准拿不到；走 B 路线（编完清空 __versions 段）即可。")
PY
[ -n "$(ls -1 "$KEEP" 2>/dev/null)" ] || { echo "CRC 基准跳过（没有主内核编的厂商 ko）"; echo "只抓到了 config，已足够"; exit 0; }

echo "=== 3. 建 CRC 基准表"
python3 scripts/build_crc_baseline.py config/device-crc-os11.json "$KEEP"/*.ko \
  --label "device $MODEL $REL ($FINGER)" || exit 5

echo
echo "完成。两份基准已就位："
ls -l config/device-os11.config config/device-crc-os11.json 2>/dev/null
echo "下一步：git add -A && git commit -m 'config: 从设备抓 os11 的 config + CRC 基准' && git push"
