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
| `SukiSU_v4.3.0.apk` | `com.sukisu.ultra` | 41100 | 无 libksud（uapi 是 dex 常量） | 6（推定） | `sukisu430`（本次新增） |

五条全部 `OK`（包名 / vc / uapi 与 managers.json 一致）。

### 三个容易踩的坑（都是这次核对出来的）

1. **文件名 ≠ 版本号**。`BakaSU_v4.2.0-rc3.apk` 的 versionCode 是 **35252**，
   对应上游 commit `d5e9e025`（ksud 里的长版本串 `4.2.0-rc3-81-gd5e9e025`）。
   按 `4.2.0` 去对 tag 会对不上。
2. **KernelSU-Next 的包名被伪装**成 `kqvdie.zeykvw.hpbcyd`，ksud 里编译期常量仍是
   `com.rifsxd.ksunext`。寄存器认包名时必须传**伪装后的**那个，否则永远认不出。
3. **SukiSU 没有 libksud**（4.x 起管理器直接走内核接口，uapi 是 dex 常量，
   `libwnhshomyqcv.so` 只有 15 KB 的 JNI 壳）⇒ 没法从 APK 静态读 uapi，
   只能装载后看管理器自报的 `kernelUAPIVersion` / `managerUAPIVersion`。

## 二、uapi 分代决定用哪条构建链

一份 ko 只认一个 uapi，跨代必报 `UAPI version mismatch: kernel=…`。

| uapi | 管理器 | 构建配置 | 备注 |
|---|---|---|---|
| 5 | 官方 3.3.1、KSU-Next 3.4.2 | `ksu331` / `next` | 也能用 `Magic6_OS11_110_一键越狱` 包里那份 `kernelsu-v325-kprobe-sucompat.ko`（v325 源码，同属 3.x 线，推定 uapi 5；上机用 `ksud debug get-kernel-info` 或管理器设置页对一遍） |
| 6 | BakaSU 4.2.0-rc3、FinaSU 1.3.0、SukiSU 4.3.0 | `basu420` / `finasu130` / `sukisu430` | 必须自编，且要带 `patch/apply_sc_inject.py`（uapi6 的 sc_table 注入） |

**推论**：v325 那份 ko 只能服务官方 3.3.1 和 KSU-Next 3.4.2。
要用 BakaSU / FinaSU / SukiSU，就得在本仓库按对应档编 ko —— 这是「适配新版管理器」的实质内容。

## 三、管理器注册方式（各家不一样，不能一套脚本硬套）

| 管理器 | 注册手段 | 前置条件 | 本机要传什么 |
|---|---|---|---|
| 官方 3.3.1 | `ksud debug set-manager <APK>` | 内核 `CONFIG_KSU_DEBUG` | APK 路径（不是包名） |
| KSU-Next 3.4.2 | 同上（`SetManagerAPK`） | 同上 | 伪装包名 APK 的路径 |
| BakaSU 4.2.0-rc3 | **签名扫描加冕** + `set-apk` 动态管理器 | 无需 debug | 签名 + 包名 `com.resukisu.resukisu` |
| FinaSU 1.3.0 | `set-apk` / `set-uid` / `set-hash` + `grant` | 无需 debug | 管理器 APK 的 v2 签名（`GrantAuthorize`） |
| SukiSU 4.3.0 | 管理器自己写（无 ksud） | — | 只要内核认包名 |

**共同兜底**：`ksud debug set-manager` 失败时走 `packages.list` 加冕（写 uid 后恢复权限），
或者让 ko 侧直接认包名 —— 这也是 `patch/apply_mgr_pkgs.py` 存在的理由：

```
mgr_pkgs=me.weishu.kernelsu,kqvdie.zeykvw.hpbcyd,com.resukisu.resukisu,me.yuki.fina,com.sukisu.ultra
```

一份 ko 认全部五个包名，装载时按书写顺序优先加冕（真机踩过：设备上同时装着 BakaSU 和官方时，
原生 `track_throne()` 会按 `packages.list` 遍历顺序挑到错的那个，
`Crowning manager: uid=10512` 而用户实际用的是 uid 11207 ⇒ 管理器所有 ioctl 全被 deny）。

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

`m6-os11-exploit` 的 P6（KSU 装载）目前用的是 1.1.3 包里那份 v325 ko ⇒ **只能配官方 3.3.1 / KSU-Next 3.4.2**。

若要落到 BakaSU / FinaSU / SukiSU，需要：
1. 在本仓库按 `basu420` / `finasu130` / `sukisu430` 各编一份 uapi6 ko（B 路线 + `sc_inject` + 多管理器包名补丁）
2. 用 `tools/target.py vermagic` 校验 vermagic 整串（含 `modversions` token）
3. 装载时带 `mgr_pkgs=…`（见上）+ `allow_shell=1`（调试期）
4. 回到 `m6-os11-exploit` 的 P7 逐家验
