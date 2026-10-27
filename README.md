# m6-os11-ksu

为 **荣耀 Magic6 Pro / MagicOS 11（`6.1.157-android14-11-g84ffa64b710b`）** 编 KernelSU 系 `.ko` 的独立仓库。

流程照抄自 [`m6-bvlgari-ksu`](../m6-bvlgari-ksu)（那边是 MagicOS 10 / `…g7d3922fade43`，已验证），
这边只做两件事：**换档位**（`config/targets.json` 的 `os11` 项）+ **独立产物命名**（`kernelsu_<alias>_os11.ko`），
这样两个内核档的 ko 不会互相覆盖。

## 为什么必须分仓库编

| | m6（那边） | os11（这边） |
|---|---|---|
| 内核 | `6.1.157-android14-11-g7d3922fade43` | `6.1.157-android14-11-g84ffa64b710b` |
| vermagic | 逐字比对，差一个字符内核就拒载 | 同左 |
| 产物名 | `kernelsu_<alias>.ko` | `kernelsu_<alias>_os11.ko` |
| 载荷落点 | `m6-jailbreak-core/payload/` | `m6-jailbreak-core/payload/os11/` |

一份 ko 只对一个 build 有效（`vermagic` + `__versions` CRC 双重门），混装 = 管理器报「需要更新内核」或直接 panic。

## 源码从哪来

优先 `vars.HONOR_SRC_URL_OS11`（MagicOS 11.0.0.110 对应的荣耀开源包）；
没配就退回 `vars.HONOR_SRC_URL`（MagicOS 10 的 `Bvlgari_MagicOS10.0_Code_Opensource`，树是 6.1.128）。

退路为什么也能用：workflow 会把 `SUBLEVEL` 改成 157、`LOCALVERSION` 设成
`-android14-11-g84ffa64b710b`，vermagic 就对齐了（m6 那边一直这么干）。
**但** `__versions` 里的结构体 CRC 是按树算的，如果 110 的内核对某些结构体有改动，
编译出的 ko 装载后会在 `execve` 阶段跪 —— 所以第一发务必按下面的判据验一遍。

## 跑

```bash
# 单发（推荐先这么打一发验证流程）
gh workflow run build-ko-os11.yml -f ksu_repo=LyraVoid/FinaSU -f ksu_ref=v1.2.1 \
  -f ksu_tarball=https://github.com/LyraVoid/FinaSU/archive/refs/tags/v1.2.1.tar.gz \
  -f ko_alias=finasu121 -f ksu_debug=true

# 一次把 8 个管理器都排上（每个 job 独立跑 25~40 分钟，注意额度）
for m in "tiann/KernelSU v3.3.1 ksu331 false" \
         "KernelSU-Next/KernelSU-Next v3.4.2 next true" \
         "SukiSU-Ultra/SukiSU-Ultra v4.2.1-r1 sukisu true" \
         "LyraVoid/FinaSU v1.2.1 finasu121 true" \
         "LyraVoid/FinaSU v1.0.10 finasu110 true" \
         "Baka-SU/BakaSU main custom true"; do
  set -- $m
  tb=""; [ "$4" = "true" ] && tb="-f ksu_tarball=https://github.com/$1/archive/refs/heads/$2.tar.gz"
  gh workflow run build-ko-os11.yml -f ksu_repo=$1 -f ksu_ref=$2 -f ko_alias=$3 $tb
done
```

产物 → 载荷 → APK：

```bash
python tools/ci_ko.py pull --target os11 --sync     # 校验 vermagic 后落进 payload/os11/
cd ../m6-shell && bash tools/build_apk.sh release   # sync 自动跑，末尾逐文件核对
```

## 产物判据（CI 里自动跑，不符直接失败）

1. `vermagic` 逐字等于 `6.1.157-android14-11-g84ffa64b710b`；
2. `__versions` CRC 与 `config/device-crc-os11.json` 一致（**这份还没抓到**，见下）；
3. `strings kernelsu_*.ko | grep sucompat` 有输出（kprobe 后端补丁生效）。

## 已知缺口

1. **`config/device_crc.json` 现在是 MagicOS 10 那份**（436 个厂商 ko 的 `__versions` 基准）。
   要在 os11 机器上导一份：`adb pull /vendor/lib/modules/*.ko` → 跑 `scripts/check_crc.py --build-baseline`
   （或称手写个小脚本扫 `.ko` 的 `__versions`），另存为 `config/device-crc-os11.json`。
   在那之前 CRC 检查只能当"参考"，不能当门禁。
2. **`config/device.config` 也是 MagicOS 10 的**。110 机器连上后跑 `scripts/get_config.sh`
   取 `/proc/config.gz`，存成 `config/device-os11.config`（`targets.json` 里已指向它，缺了自动回退）。
3. 还没在 os11 真机上验证过任何一份产物 —— 第一次打的 ko 要按
   `m6-jailbreak-core/docs/08-os11-route.md` 的流程上机（`FORCE_KO` 先兜底那份 v325）。

## 目录

```
.github/workflows/build-ko-os11.yml   CI（照抄 m6-bvlgari-ksu，target 默认 os11）
config/targets.json                   档位表（唯一真源：localversion / sublevel / config / source_var）
config/managers.json                  管理器 ↔ 上游仓库/tag/uapi
config/device.config                  m6 的厂商 config（os11 的待抓）
config/device_crc.json                m6 的 CRC 基准（os11 的待导出）
patch/apply_sc_inject.py              uapi6 的 sc_table 注入补丁
patch/apply_mgr_pkgs.py               多管理器包名补丁
scripts/check_crc.py                  __versions CRC 比对
scripts/gen_shim.py                   缺失符号的 kallsyms 运行时解析垫片
tools/target.py resolve/vermagic/matrix
tools/ci_ko.py pull/status            产物回灌到 payload/os11
```

## 与另一仓库的分工

- `m6-bvlgari-ksu`：MagicOS 10 档，公开、有历史记录、产物已被真机验证。
- **本仓库**：MagicOS 11 档，独立演进；流程变了也优先在这边试，稳了再回灌那边。

## os11 没有设备时的两条路（照 os10 的经验）

os10（`m6-bvlgari-ksu`）的做法是「设备在手」路线：`adb pull /vendor/lib/modules/*.ko` →
扫 `__versions` 生成 `config/device_crc.json` → CI 里 `check_crc.py` 当门禁；`.config` 也是
`/proc/config.gz` 抓的。**os11 目前没设备**，于是有第二条：

| 路线 | 产物形状 | 门禁 | 适用 |
|---|---|---|---|
| A 有设备 | `__versions` 有 180 条左右（`MODVERSIONS=y`） | vermagic + **CRC 逐符号比对** | 有 os11 机器时首选 |
| B 无设备 | `__versions` **size=0**（`MODVERSIONS=n`） | vermagic + 装载时 `ko_patch2` 把 UNDEF 写成 live kallsyms 的 `SHN_ABS`（内核不做版本比对） | 现在；作者包 `kernelsu_v325_os11.ko` 就是这个形状，实测能装 |

B 的实测依据：作者包那份 ko 的 `__versions` 段是 **size=0**（`MODVERSIONS=n` 编的），
配上 `ko_patch2 $KO /proc/kallsyms` 照样在 110 内核上 Live —— 说明这条路不依赖 CRC。
workflow 的 `no_modversions` 输入（默认 **true**）就是产出 B 形状。

有设备后补基准（一条命令）：

```bash
bash scripts/pull_device_truth.sh          # 抓 config + vendor ko → 生成两份 os11 基准
git add -A && git commit -m "config: 从设备抓 os11 的 config + CRC 基准" && git push
```

之后把 `no_modversions` 设回 false，就能用 A 路线的 CRC 门禁。

`scripts/build_crc_baseline.py` 可以从任意「已知能在目标内核装载」的 ko 反推基准表
（多份会互相比对，冲突就报错），设备不在手边时也能用别人给的 ko 建表。
