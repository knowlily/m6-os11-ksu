# 2026-11-07 多管理器 ko（os11 + SP7，不带 SELinux 补丁）与包内自检

## 交付

同一 APK 内置 5 家管理器 × 2 个内核，`Kernels.pick()` 按 `uname -r` 自动选：

| 管理器 | 包名 | versionCode | uapi | 源码点 |
|---|---|---|---|---|
| FinaSU 1.5.0 | me.yuki.fina | 33174 | 6 | v1.5.0（**唯一带我们的 SELinux 补丁**） |
| SukiSU Ultra | com.sukisu.ultra | 41140 | 6 | v4.3.0-r1 |
| KernelSU-Next | com.rifsxd.ksunext | 33355 | 5 | v3.4.2 |
| BakaSU | com.resukisu.resukisu | 35252 | 6 | **commit d5e9e025**（不是 tag） |
| KernelSU | me.weishu.kernelsu | 32680 | 5 | v3.3.1 |

其它管理器一律 `selinux_patch=false`：CI 里三个 `selinux_hide*` 步骤都挂了 `if: inputs.selinux_patch`，
原厂代码一个字节不改（SukiSU 上游自带的 selinux_hide 仍在，属它自己的特性）。

## 两个真 bug（已修）

### 1) BakaSU 编错源码点

用 tag `v4.2.0-rc3` 编出来的是 **uapi4**，而桌面那份 APK（35252）对应 commit `d5e9e025`（**uapi6**）。
源码实证：

```
BakaSU d5e9e025b8b49155f8014684d64c91742b465f65: KERNEL_SU_UAPI_VERSION = 6;
BakaSU v4.2.0-rc3:                              KERNEL_SU_UAPI_VERSION = 4;
```

按 tag 编的 ko 装上去必报 `UAPI version mismatch`。已改用全 sha 重编（564,256 B vs 错版 493,568 B）。

**教训**：BakaSU 的 tag 与 APK 不是一回事，一律以 `config/managers.json` 的 `basu420.ref=d5e9e025` 为准。

### 2) 伪装包名（kqvdie.zeykvw.hpbcyd）缺 SP7

那份只带 os11 的旧 ko，SP7 机器上会静默回退 → vermagic 不匹配。
按用户要求**直接去掉伪装包**：删 `variants/kqvdie.*`、从 `MANAGERS`/`KO_UAPI` 移除，取消对应构建。

## 包内自检（19→18 份 ko 全过）

用 App 自己的 ELF 解析链路（`.symtab` → `do_get_info`/`do_get_info_legacy` → movz 立即数）核对：

- 18/18 份 ko 可解析，`funcs=2`（两个上报函数都在 → 现场改版本号可行）
- 每份的版本常数与对应管理器 versionCode 完全一致
- vermagic 分别命中 `-g84ffa64b710b` / `-g7db56fb8f741`
- REQUIRED_ASSETS 9/9 齐全，全部 `ELF64 LE machine=0x00b7`（aarch64）
- `kgo.sh` 两个内核串 + `commit_creds=0x15fe88` + 未知内核 `FB=""`（fail-closed）
- `R.id` 引用与布局零悬空；五个 versionCode 全 ≤ 0xFFFF（movz 立即数放得下）

## 一个容易踩的静默坑（已核实没踩）

`Kernels.build` 取 `-g` **之后含 g** 的部分（`g84ffa64b710b`），与 asset 名 `kernelsu-g84ffa64b710b.ko` 对齐。
若取成不含 g，会静默回退到默认 `kernelsu.ko` —— 在 os11 上看不出来（本来就匹配），到 SP7 才炸。

## 高级设置（App 侧）

- 「高级」胶囊挂在信息卡「路线」那一行右边（不放底部按钮行，避免拥挤）
- 开关 `force_no_kcheck`：开着时跳过 vermagic 比对，日志打 ⚠ 并说明后果；
  信息卡该行显示「已强制关闭 · 不校验」
- 只跳过 vermagic 比对，不跳过「管理器 ↔ ko 包名/版本号对齐」

## 真机验证（9.30-multimgr / versionCode 111）

- 设备上装的是 SukiSU **v4.3.0-r2**（41150），ko 是 r1 编的（41140）→ App 现场改成 41150，`内核校验 匹配`
- 说明 `KoPatcher` 对原厂 ko 同样有效（不是只对 FinaSU 有效）
