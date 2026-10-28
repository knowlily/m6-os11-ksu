# 2026-10-28 · os11 真机只读采集（老版本已提权）

设备用作者包的 `kernelsu-v325-kprobe-sucompat.ko` 提权成功（`su -c id` → `uid=0 context=u:r:ksu:s0`），
拿着 root 把「真相」采了一遍。**全程只读**：`adb exec-out 'su -c ...'`，没有 remount、没有往任何系统分区写过文件，
唯一落盘位置是宿主机的 scratch 目录。

## 采到了什么

| 项 | 结果 | 用途 |
|---|---|---|
| `/proc/config.gz` | 2327 条，`config/device-os11.config` | 编 ko 的 `.config` 真源（已在用） |
| `/proc/kallsyms` | 429,835 行 / 220,840 个唯一符号，`kptr_restrict=0` | 符号存在性核对、KASLR 基准 |
| `/proc/version` / cmdline | `#1 SMP PREEMPT Thu Oct 8 09:23:50 UTC 2026`，clang 17.0.2 + LLD 17.0.2 | 记档，用于比对手上源码树 |
| `/vendor_dlkm/lib/modules` | 436 个 ko，45 MB（`/vendor/lib/modules` 是软链） | ❌ 见下，CRC 用不上 |
| 设备侧 payload | `/data/local/tmp/route/m6/`：`kernelsu-v325-kprobe-sucompat.ko` 368,544 B、`auto_load_v325.sh`、`ko_patch.log`、`OPTS` | 摸清作者那条装载链 |
| 已加载模块 | `kernelsu` 212,992 B @ `0xffffffe0f3625000`、`gl3root_kb` 16,384 B | 状态基线 |

## 三个关键结论

### 1. 厂商 ko 全部是 DSP 内核编的，拿不到 CRC 真值

```
348 个  6.1.57-android14-11-gbfe3896ae95e   SMP preempt mod_unload modversions aarch64
 88 个  6.1.57-android14-11-maybe-dirty     SMP preempt mod_unload modversions aarch64
  0 个  6.1.157-android14-11-g84ffa64b710b  ← 主内核
```

`/vendor_dlkm/lib/modules` 里放的是 ADSP/音频那一套（对 6.1.57 编的），跟 AP 主内核不是同一个 build。
**所以 os10 那套「拉设备 vendor ko 建 CRC 基准」在 os11 上根本走不通**——不是权限问题，是数据不存在。
真要 A 路线，只能从 boot 分区的内核镜像里挖 `__kcrctab`（还得用 `_text` 地址把虚拟地址映射回文件偏移），
性价比远不如直接走 B 路线。

### 2. `commit_creds` 不在 kallsyms 里，但**不影响装载**

```
kallsyms 里有:  __ksymtab_commit_creds  (r, 0xffffffe0f5131c3c)     ← 导出表项
kallsyms 里没有: commit_creds            (T)                        ← 文本符号
```

它是通过 `__ksymtab` 导出的，内核在 `insmod` 时按导出表解析模块的 UNDEF，不查 kallsyms。
这也解释了作者那份 `ko_patch.log`：

```
[ko_patch] 206 UNDEF symbols to resolve
[ko_patch] NOTFOUND(exported/hidden, leave UND): commit_creds
[ko_patch] OK: 205/206 UNDEF -> SHN_ABS (live)
```

`ko_patch2` 只读 kallsyms ⇒ 找不到 `commit_creds` ⇒ 留成 UNDEF ⇒ 装载时内核自己解析。**留 UND 是正确行为，不是失败。**

### 3. 我们的 CI 产物符号覆盖 = 作者包同水平

| ko | UNDEF | 110 kallsyms 里没有的 |
|---|---:|---|
| CI 首版 `kernelsu_finasu121_os11.ko` | 240 | `commit_creds`（1 个） |
| 作者 `kernelsu_v325_os11.ko` | 206 | `commit_creds`（1 个） |

缺的是同一个符号，而它由导出表兜底 ⇒ **装载层面的符号风险基本归零**。

## 顺手验了 os11 的静态符号表

`payload/os11/next_sym_addr_11_110.txt`（233 条）跟实机 kallsyms 按 `_text` 偏移**逐条一致，0 条不符**：

```
镜像静态基址  0xffffffc008000000
运行时 _text  0xffffffe0f3a00000
KASLR slide   0x20eba00000
```

只有 `commit_creds` 查不到（同第 2 条）。⇒ 这份符号表可以放心用于 exploit 与 loader。

## 对 os11 编译策略的影响

- **B 路线正式成为唯一可行路线**（A 路线缺数据）：开着 `CONFIG_MODVERSIONS` 编（保住 vermagic 的 `modversions` token），
  编完清空 `__versions` 段，装载时 `ko_patch2` 把 UNDEF 改成 live kallsyms 的 `SHN_ABS`。
- `config/device-crc-os11.json` **不再期待**能从设备厂商 ko 生成；`scripts/pull_device_truth.sh` 的 CRC 那一步
  在这台机上注定产出空表（脚本会报 ko 数量不足/不匹配），它的价值只剩抓 `.config`。
- 结构体偏移的残余风险（树 6.1.128 vs 内核 6.1.157、`GKI_TASK_STRUCT_VENDOR_SIZE_MAX=1024`）只能靠真机装载验证，
  没有别的提前校验手段。

## 复现命令

```bash
S=ACPR024524000114
adb -s $S exec-out 'su -c "zcat /proc/config.gz"'                    > device-os11.config
adb -s $S exec-out 'su -c "cat /proc/kallsyms"'                      > kallsyms.txt
adb -s $S exec-out "su -c 'tar cf - -C /vendor_dlkm/lib/modules .'"  > vmods.tar      # 45 MB
for f in auto_load_v325.sh ko_patch.log insmod_ko.log OPTS; do
  adb -s $S exec-out "su -c 'cat /data/local/tmp/route/m6/$f'" > "dev_side/$f"; done
```
