# 桌面五份管理器 APK ↔ ko 配置对照（2026-10-29 实测）

来源目录：`C:\Users\阿斯顿\Desktop\apks`
核对工具：`scripts/check_manager_apk.py`（离线读 APK，不依赖 adb）

```bash
AAPT2="D:/Android/Sdk/build-tools/35.0.0/aapt2.exe" \
  python scripts/check_manager_apk.py "C:/Users/阿斯顿/Desktop/apks"
```

## 一、实测结果

| APK | 包名 | versionCode | ksud 版本串 | uapi | 对应 config 条目 |
|---|---|---|---|---|---|
| `KernelSU_v3.3.1.apk` | `me.weishu.kernelsu` | 32680 | `3.3.1 (uapi: 5)` | **5** | `ksu331` |
| `KernelSU-Next_v3.4.2-spoofed.apk` | `kqvdie.zeykvw.hpbcyd` | 33355 | `3.4.2 (uapi: 5)` | **5** | `next` |
| `BakaSU_v4.2.0-rc3.apk` | `com.resukisu.resukisu` | 35252 | `4.2.0-rc3-81-gd5e9e025 (uapi: 6)` | **6** | `basu420` |
| `FinaSU_v1.3.0.apk` | `me.yuki.fina` | 33082 | `1.3.0 (uapi: 6)` | **6** | `finasu130`（本次新增） |
| `SukiSU_v4.3.0.apk` | `com.sukisu.ultra` | 41100 | 无 libksud（uapi 是 dex 常量） | **6**（源码已确认） `sukisu430`（本次新增） |

五条全部 `OK`（包名 / vc / uapi 与 managers.json 一致）。

### 三个容易踩的坑（都是这次核对出来的）

1. **文件名 ≠ 版本号**。`BakaSU_v4.2.0-rc3.apk` 的 versionCode 是 **35252**，
   对应上游 commit `d5e9e025`（ksud 里的长版本串 `4.2.0-rc3-81-gd5e9e025`）。
   按 `4.2.0` 去对 tag 会对不上。
2. **KernelSU-Next 的包名被伪装**成 `kqvdie.zeykvw.hpbcyd`，ksud 里编译期常量仍是
   `com.rifsxd.ksunext`。寄存器认包名时必须传**伪装后的**那个，否则永远认不出。
3. **BakaSU 的 tag 与 APK 不是一回事**：`v4.2.0-rc3` 这个 tag 是 **uapi4**，
   APK 里那份是 `d5e9e025`（tag + 81 commits，uapi6）。按 tag 编出来的 ko 配 APK 会 mismatch。
   识别办法：APK 的 libksud 版本串是 `4.2.0-rc3-81-gd5e9e025 (uapi: 6)`。
4. **SukiSU 没有 libksud**（4.x 起管理器直接走内核接口，uapi 是 dex 常量，
   `libwnhshomyqcv.so` 只有 15 KB 的 JNI 壳）⇒ 没法从 APK 静态读 uapi，
   只能装载后看管理器自报的 `kernelUAPIVersion` / `managerUAPIVersion`。

## 二、uapi 按源码核实（不按 tag 猜）

`KERNEL_SU_UAPI_VERSION` 一律从各仓库 `uapi/supercall.h` 读：

```bash
gh api "repos/<repo>/contents/uapi/supercall.h?ref=<ref>" -H "Accept: application/vnd.github.raw" \
  | grep -m1 KERNEL_SU_UAPI_VERSION
```

| 源 | uapi | 说明 |
|---|---|---|
| `tiann/KernelSU v3.2.5` | **2** | 一键越狱包/kit 自带那份 ko 的内核侧 |
| `tiann/KernelSU v3.3.1` | 5 | 官方现版 |
| `KernelSU-Next v3.4.2` | 5 | 伪装包名那家 |
| `BakaSU d5e9e025` | 6 | APK v4.2.0-rc3 |
| `FinaSU v1.3.0` | 6 | |
| `SukiSU v4.3.0` | 6 | 之前只能推定，现已确认 |

**一条要纠正的旧判断**：v325 那份 ko 是 **uapi 2**，不是 5。
所以它**只能**配 KernelSU 3.2.5 自带管理器；装 3.3.1 / KSU-Next（uapi 5）或任何 uapi6 管理器，
都会报 `UAPI version mismatch: kernel=…`，症状是「模块 Live 但管理器连不上、su 不给权」。
uapi2 的构建参数表也老（只有 `allow_shell` / `norc`），不要拿它当「更稳的兜底」。

### 一个管理器一份 ko

跨代不能混，也不建议用一份 ko 认多个包名来「省编译」：uapi 是内核态 ABI，
五个管理器分三代（2 / 5 / 6），一份 ko 只能落在一代上。所以矩阵是

| 管理器 | 要编的 ko | 档位 |
|---|---|---|
| KernelSU 3.3.1 | `kernelsu_ksu331_os11.ko` | `ksu331` |
| KernelSU-Next 3.4.2 | `kernelsu_next_os11.ko` | `next` |
| BakaSU 4.2.0-rc3 | `kernelsu_basu420_os11.ko` | `basu420` |
| FinaSU 1.3.0 | `kernelsu_finasu130_os11.ko` | `finasu130` |
| SukiSU 4.3.0 | `kernelsu_sukisu430_os11.ko` | `sukisu430` |

（`ksu325` 只作历史对照，标记 `deprecated`，不进装机包。）

## 三、管理器注册方式（各家不一样，不能一套脚本硬套）

| 管理器 | 注册手段 | 前置条件 | 本机要传什么 |
|---|---|---|---|
| 官方 3.3.1 | `ksud debug set-manager <APK>` | 内核 `CONFIG_KSU_DEBUG` | APK 路径（不是包名） |
| KSU-Next 3.4.2 | 同上（`SetManagerAPK`） | 同上 | 伪装包名 APK 的路径 |
| BakaSU 4.2.0-rc3 | **签名扫描加冕** + `set-apk` 动态管理器 | 无需 debug | 签名 + 包名 `com.resukisu.resukisu` |
| FinaSU 1.3.0 | `set-apk` / `set-uid` / `set-hash` + `grant` | 无需 debug | 管理器 APK 的 v2 签名（`GrantAuthorize`） |
| SukiSU 4.3.0 | 管理器自己写（无 ksud） | — | 只要内核认包名 |

**兜底顺序**（每份 ko 只认自己那个管理器）：先管理器自带的注册路径；不行再
`ksud debug set-manager <APK>`（需 `CONFIG_KSU_DEBUG`，本仓库 workflow 的 `ksu_debug` 默认 true）；
再不行 `packages.list` 加冕。**不要**用一份 ko 认五个包名来省事 —— uapi 是内核态 ABI，
五个管理器分三代（2/5/6），一份 ko 只能落一代。

每份 ko 里编译期 `KSU_PACKAGE_NAME` 也各自对应自己的管理器包名（`patch/apply_mgr_pkgs.py`
只用于临时把某个包名补进去，不是主路径）。

## 四、本次改动

1. `config/managers.json`
   - 新增 `finasu130`（FinaSU v1.3.0 / vc 33082）、`sukisu430`（SukiSU v4.3.0 / vc 41100）
   - 给 `ksu331` / `next` / `basu420` 补 `apk_vc` + `apk_file`（桌面上那份 APK 的文件名）
   - 所有 uapi6 档加 `sc_inject: true` 标记
2. 新增 `scripts/check_manager_apk.py`：离线核对「APK ↔ config 条目」，`--strict` 可当门禁用
3. `tools/target.py matrix --managers all` 现在会自动多出 `finasu130` / `sukisu430` 两个 job

## 五、上机验证清单（每个管理器各跑一遍）

| # | 检查 | 命令 / 位置 | 期望 |
|---|---|---|---|
| 1 | 内核 uapi | `ksud debug get-kernel-info`（uapi5 管理器）或管理器设置页 | 与下表对应 |
| 2 | 管理器 uapi | 管理器设置页 / `dmesg | grep -i uapi` | 与内核相等 |
| 3 | 加冕成功 | `dmesg | grep -i crowning` | uid == 该管理器真实 uid |
| 4 | 管理器不闪退 | 打开管理器 | 显示「已工作」+ 版本 |
| 5 | 授权可用 | 管理器给目标 App 点 ROOT → App 内 `su -c id` | `uid=0` |
| 6 | 无 mismatch | `dmesg | grep -i 'version mismatch'` | 空 |

| 管理器 | 期望内核 uapi |
|---|---|
| 官方 3.3.1 / KSU-Next 3.4.2 | 5 |
| BakaSU 4.2.0-rc3 / FinaSU 1.3.0 / SukiSU 4.3.0 | 6 |

## 六、与 OS11 提权链的衔接

`m6-os11-exploit` 的 P6（KSU 装载）现在用的是 1.1.3 包里那份 v325 ko —— 它是 **uapi 2**，
只能配 KernelSU 3.2.5 自带管理器（kit 的 `assets/manager/KernelSU-v325.apk`）。
换成设备上现装的 3.3.1 / SukiSU / FinaSU 全部会 mismatch。

所以 P6 改成「**编一份与已装管理器同代的 ko**」：

| 设备上装的是 | 编哪份 | 装载参数 |
|---|---|---|
| 官方 3.3.1 | `kernelsu_ksu331_os11.ko`（uapi5） | `allow_shell=1`（调试期） |
| KSU-Next 3.4.2 | `kernelsu_next_os11.ko`（uapi5） | 同上 + 伪装包名 |
| BakaSU 4.2.0-rc3 | `kernelsu_basu420_os11.ko`（uapi6） | 同上 |
| FinaSU 1.3.0 | `kernelsu_finasu130_os11.ko`（uapi6） | 同上 |
| SukiSU 4.3.0 | `kernelsu_sukisu430_os11.ko`（uapi6） | 同上 |

步骤：
1. 在本仓库按对应档编 ko（B 路线：开着 MODVERSIONS 编、编完清 `__versions`；uapi6 还要 `sc_inject`）
2. `tools/target.py vermagic --target os11 --ko <产物>` 校验整串（含 `modversions` token）
3. 装载 `insmod <ko> <参数>`，判据 `/proc/modules` 里 `kernelsu … Live` + `/dev/ksu` 存在
4. 回到 `m6-os11-exploit` 的 P7 逐家验
