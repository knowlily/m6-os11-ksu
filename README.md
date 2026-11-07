# m6-os11-ksu

为**荣耀 Magic6 Pro 的两个内核档**编 KernelSU 系 `.ko` 的独立仓库：

| 档位 | 内核 | 产物后缀 |
|---|---|---|
| `os11` | `6.1.157-android14-11-g84ffa64b710b`（本机 / MagicOS 11） | `_os11` |
| `os11sp7` | `6.1.157-android14-11-g7db56fb8f741`（另一台机器 / SP7） | `_os11sp7` |

流程照抄自 [`m6-bvlgari-ksu`](../m6-bvlgari-ksu)（MagicOS 10 / `…g7d3922fade43`，已验证），
这边做三件事：**加档位**（`config/targets.json` 的 `os11` / `os11sp7`）、**独立产物命名**（两份 ko 不会互相覆盖）、
**SELinux 隐藏层只挂在我们自己那条线**（见下文）。

## 两个内核档其实同源

SP7 的 boot.img 实测（`荣耀Magic6Pro-boot分区-实机提取-SP7-20261105.img`）：

| 检查项 | 结果 |
|---|---|
| 内核版本 | `6.1.157-android14-11-g7db56fb8f741`，与本机同属 **ACK android14-11 / 6.1.157** |
| 内嵌 IKCONFIG | sha256 `7fbcc7c9…8061`，与本仓库 `config/device-os11.config` **逐字节相同**（7888 行） |
| boot header | v4，无 ramdisk，`kernel_size=40,942,080`，AVB 自洽（内核没被改过） |
| 唯一差异 | `LOCALVERSION`：`-g7db56fb8f741` vs `-g84ffa64b710b` |

所以**源码、config、补丁偏移全共用**（`commit_creds` 都是 `0x15fe88`），
只是 `vermagic` 逐字比对，所以两档必须各出一份 ko —— 混装要么被内核直接拒载
（`invalid module format`），要么管理器报「需要更新内核」。

> 想合成一份？实测两档产物**同尺寸**（719,104 B）、`vermagic` 同在**偏移 203,046**、
> 只差 12 个十六进制字符（`84ffa64b710b` / `7db56fb8f741`，等长）。
> 也就是说「一份 ko + 装载前原地改这 12 字节」可行（`susfs_insmod` 就是这套思路），
> 但默认仍出两份：零风险，且 APK 侧按 `uname -r` 自动选，不需要额外逻辑。

## 源码从哪来

优先 `vars.HONOR_SRC_URL_OS11`（MagicOS 11.0.0.110 对应的荣耀开源包）；
没配就退回 `vars.HONOR_SRC_URL`（MagicOS 10 的 `Bvlgari_MagicOS10.0_Code_Opensource`，树是 6.1.128）。

退路为什么也能用：workflow 会把 `SUBLEVEL` 改成 157、`LOCALVERSION` 设成目标串，
vermagic 就对齐了。**但** `__versions` 里的结构体 CRC 是按树算的，如果目标内核对某些结构体有改动，
编译出的 ko 装载后会在 `execve` 阶段跪 —— 所以第一发务必按下面的判据验一遍。

## 跑

```bash
# 单发：FinaSU（这条线带我们的 SELinux 隐藏补丁）
gh workflow run build-ko-os11.yml --ref rel-150 -f target=os11 \
  -f ksu_repo=LyraVoid/FinaSU -f ksu_ref=v1.5.0 \
  -f ksu_tarball=https://codeload.github.com/LyraVoid/FinaSU/tar.gz/refs/tags/v1.5.0 \
  -f ko_alias=finasu150 -f ksu_version=33174 -f mgr_pkg=me.yuki.fina \
  -f hook_mode=manual -F no_modversions=true -F ksu_debug=true

# 一次把「四家原厂管理器 × 两个内核」排上（每个 job 25~40 分钟，注意额度）
# 原厂线一律 selinux_patch=false：不改上游一个字节，保证稳定性
for t in os11 os11sp7; do
  for m in "SukiSU-Ultra/SukiSU-Ultra v4.3.0-r1 sukisu430 41140 com.sukisu.ultra manual" \
           "KernelSU-Next/KernelSU-Next v3.4.2 ksunext342 33355 com.rifsxd.ksunext manual" \
           "Baka-SU/BakaSU d5e9e025b8b49155f8014684d64c91742b465f65 bakasu420 35252 com.resukisu.resukisu manual" \
           "tiann/KernelSU v3.3.1 ksu331 32680 me.weishu.kernelsu auto"; do
    set -- $m
    gh workflow run build-ko-os11.yml --ref rel-150 -R knowlily/m6-os11-ksu \
      -f target=$t -f ksu_repo=$1 -f ksu_ref=$2 \
      -f ksu_tarball="https://codeload.github.com/$1/tar.gz/$2" \
      -f ko_alias=$3 -f ksu_version=$4 -f mgr_pkg=$5 -f hook_mode=$6 \
      -F selinux_patch=false -F no_modversions=true -F ksu_debug=true
    sleep 2
  done
done
```

`selinux_patch`（默认 `true`）是总闸：关掉时 workflow 会跳过**四个**入口 ——
`apply_selinux_hide_direct_store.py` 以及三个 `selinux_hide*` 步骤
（备份只抓一次 / hook 进入日志 / 改直写 .data）。只关一处不够：那三步各自都会改 `selinux_hide.c`。

产物 → 载荷 → APK：

```bash
python tools/ci_ko.py pull --target os11 --sync     # 校验 vermagic 后落进 payload/os11/
cd ../m6-shell && bash tools/build_apk.sh release   # sync 自动跑，末尾逐文件核对
```

## 产物判据（CI 里自动跑，不符直接失败）

1. `vermagic` 逐字等于目标档位的内核串（`os11` / `os11sp7` 各一个）；
2. `__versions` 段 `size=0`（B 路线形状，见文末）；
3. `strings kernelsu_*.ko | grep sucompat` 有输出（kprobe 后端补丁生效）；
4. 打进 APK 后再跑一遍总检：

```bash
python scripts/audit_apk_kos.py "D:/githubs/ksu-app/dist/M6Shell-9.30-multimgr.apk" \
  --expect-build g84ffa64b710b
```

`audit_apk_kos.py` 用的是和 App 里 `KoPatcher` **同一套定位方式**（`.symtab` →
`do_get_info`/`do_get_info_legacy` → `movz` 立即数），所以它过了就等于「现场改版本号这条路能走」：
每份 ko 必须有两个非空上报符号，且两个函数体里「都出现、30000..65535、后面不跟 movk」的常数**正好一个**。
不合格退出码 1，可以直接当门禁（`--json` 便于机器读）。

## 管理器矩阵

一个管理器一份 ko（`uapi` 是内核态 ABI，跨代必报 `UAPI version mismatch`）。五家实测：

| 管理器 | 包名 | vc | uapi | 源码点 | config 键 | SELinux 补丁 |
|---|---|---|---|---|---|---|
| FinaSU 1.5.0 | `me.yuki.fina` | 33174 | 6 | `v1.5.0` | `rel-150` 线 | **有**（我们那套） |
| SukiSU Ultra | `com.sukisu.ultra` | 41140（r1）/ 41150（r2） | 6 | `v4.3.0-r1` | `sukisu430` | 无（原厂） |
| KernelSU-Next | `com.rifsxd.ksunext` | 33355 | 5 | `v3.4.2` | `next342` | 无 |
| BakaSU | `com.resukisu.resukisu` | 35252 | 6 | **commit `d5e9e025`** | `basu420` | 无 |
| KernelSU | `me.weishu.kernelsu` | 32680 | 5 | `v3.3.1` | `ksu331` | 无 |

### ⚠ BakaSU 的 tag 与 APK 不是一回事

```
BakaSU d5e9e025b8b49155f8014684d64c91742b465f65: KERNEL_SU_UAPI_VERSION = 6;   ← 对应 APK 35252
BakaSU v4.2.0-rc3:                               KERNEL_SU_UAPI_VERSION = 4;   ← tag，编出来必 mismatch
```

按 tag `v4.2.0-rc3` 编的 ko（493,568 B）装到 35252 的 APK 上会直接报 `UAPI version mismatch`；
按 commit 编才是对的（564,256 B）。**一律以 `config/managers.json` 的 `basu420.ref` 为准，不要用 tag。**

### uapi 对照（按源码 `uapi/supercall.h` 核实）

```
tiann/KernelSU v3.2.5        → 2   ← 一键越狱包/kit 自带那份，只配它自带的 3.2.5 管理器
tiann/KernelSU v3.3.1        → 5
KernelSU-Next v3.4.2         → 5
BakaSU d5e9e025              → 6
FinaSU v1.5.0                → 6
SukiSU v4.3.0-r1 / r2        → 6
```

uapi6 的几家编的时候会自动跑 `patch/apply_sc_inject.py`（配置里 `sc_inject: true`）。
核对任意一批 APK 是否和仓库配置同一代：

```bash
AAPT2="D:/Android/Sdk/build-tools/35.0.0/aapt2.exe" \
  python scripts/check_manager_apk.py "C:/Users/<user>/Desktop/apks" --strict
```

## SELinux 隐藏层只挂 FinaSU 这条线

实现在 `patch/selinux_hide_wrappers.inc`（由 `patch/apply_selinux_hide_direct_store.py` 插入 `kernel/feature/selinux_hide.c`）：

| 层 | 做法 |
|---|---|
| 类型真相源 | 开机读 `/vendor/etc/selinux/precompiled_sepolicy`，不在出厂策略里的类型 → `-EINVAL` |
| status 假页 | app 读到的 `sequence=0 policyload=0` |
| access 规则对 | 命中表 → 照常算，再把 allowed 首 token 清零 |
| `avdSeqNo` | app 的**所有** access 响应统一写成 `1`（一位数也要改，否则永远停在原值） |
| attr 第三条腿 | kretprobe `selinux_setprocattr`：把 `EPERM` 改写 `EINVAL` |

验证基线（DirtySepolicy 2.2，FinaSU 1.5.0 + 上面这套）：

```
OK: no dirty sepolicy found
INFO: sequence=0 policyload=0
```

其它管理器**不带这套**：SukiSU/KernelSU 上游自带的 `selinux_hide` 仍在（那是它自己的特性），
我们只是不改它。原因很实在 —— 我们的补丁靠 `selinux_hide.c` 里的锚点，跟着五家一起追版本只会让稳定性崩。

## 已知缺口

1. **CRC 基准在这台机上拿不到**（2026-10-28 实测，见 `docs/device-truth-os11-20261028.md`）：
   `/vendor_dlkm/lib/modules` 那 436 个 ko **全部是 DSP 内核（6.1.57-gbfe3896ae95e / maybe-dirty）编的**，
   与主内核 6.1.157 无关，`match_main_kernel = 0`。不是权限问题，是数据不存在 ⇒ A 路线不成立，
   **B 路线（开着 MODVERSIONS 编、编完清空 `__versions`、装载时 SHN_ABS）是唯一路线**。
2. **四家原厂管理器还没在真机上跑完一次提权**：ko 都编好、`vermagic` 与版本号自检已过，
   差的只是真机装载那一下（FinaSU 线已全绿）。
3. `su98260` 只在 SELinux Permissive 窗口可用；模块加载后 Enforcing 恢复，装完再做特性探测必失败 ——
   这是设计使然，不是 bug。

## 目录

```
.github/workflows/build-ko-os11.yml         CI（target 默认 os11，另有 os11sp7 / m6 档）
config/targets.json                         档位表（唯一真源：localversion / sublevel / config / source_var）
config/managers.json                        管理器 ↔ 上游仓库/ref/uapi/apk 版本号
config/device-os11.config                   从 boot.img 的 IKCONFIG 解出来的真机 config（两档共用）
patch/selinux_hide_wrappers.inc             SELinux 隐藏层实现（只进 FinaSU 线）
patch/apply_selinux_hide_direct_store.py    把它插进 selinux_hide.c（锚点失败即退出）
patch/apply_sc_inject.py                    uapi6 的 sc_table 注入补丁
patch/apply_mgr_pkgs.py                     多管理器包名补丁
scripts/audit_apk_kos.py                    包内 ko 总检（vermagic / 版本常数 / 上报函数），可当门禁
scripts/commit_creds_offset.py              从 boot.img 的 __ksymtab 离线算 commit_creds 偏移
scripts/check_crc.py                        __versions CRC 比对
scripts/gen_shim.py                         缺失符号的 kallsyms 运行时解析垫片
scripts/check_manager_apk.py                离线核对「桌面 APK ↔ managers.json」，--strict 可当门禁
docs/                                       逐次推进的取证实录（progress_YYYYMMDD*.md）
tools/target.py                             resolve / vermagic / matrix
tools/ci_ko.py                              pull / status，产物回灌 payload/<target>
```

## 与另一仓库的分工

- `m6-bvlgari-ksu`：MagicOS 10 档，公开、有历史记录、产物已被真机验证。
- **本仓库**：MagicOS 11 + SP7 两档，独立演进；流程变了也优先在这边试，稳了再回灌那边。

## 附：A / B 两条产物形状

| 路线 | 产物形状 | 门禁 | 适用 |
|---|---|---|---|
| A 有设备 | `__versions` 有 180 条左右（`MODVERSIONS=y`） | vermagic + **CRC 逐符号比对** | 能拿到「同内核编的厂商 ko」时首选 |
| B 无设备 | `__versions` **size=0**（`MODVERSIONS=n`） | vermagic + 装载时 `ko_patch2` 把 UNDEF 写成 live kallsyms 的 `SHN_ABS`（内核不做版本比对） | **当前**（`no_modversions` 默认 `true`） |

B 的实测依据：作者包 `kernelsu_v325_os11.ko` 的 `__versions` 段就是 **size=0**，
配上 `ko_patch2 $KO /proc/kallsyms` 照样在 110 内核上 Live。

## 常用命令

```bash
python tools/target.py list                                            # 所有档位
python tools/target.py resolve --target os11sp7                        # 该档位的 localversion / config / 产物名
python tools/target.py vermagic --target os11sp7 --ko kernelsu_x.ko    # 核对该 ko 的 vermagic 是否属于这档
python tools/target.py matrix --targets os11,os11sp7 --managers ksu331,next342,basu420,sukisu430

# 从 boot.img 离线算 commit_creds 偏移（两个内核都是 0x15fe88）
python scripts/commit_creds_offset.py "C:/Users/<user>/Desktop/荣耀Magic6Pro-boot分区-实机提取-SP7-20261105.img"

# 打进 APK 后的总检（SP7 那份）
python scripts/audit_apk_kos.py <apk> --expect-build g7db56fb8f741
```
