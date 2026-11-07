# 2026-11-07 SELinux 隐藏：找到真正的漏点（P0）+ 双内核适配

## 1. DirtySepolicy 三条 found 的真正来源

`SELinux.contextExists()` 判「某个 context 是否存在」有**三个**入口（
`org.lsposed.dirtysepolicy` AppZygote 反编译）：

```
1) 写 /sys/fs/selinux/context   -> EINVAL = 不存在
2) 写 /sys/fs/selinux/access    -> EINVAL = 不存在
3) 写 /proc/self/attr/current   -> EPERM  = **存在**（!!）
```

我们在 9.x 里只接管了 1 和 2。第 3 条走 `selinux_setprocattr`，一直没动，
所以无论怎么改 AV 查询，`u:r:su:s0` / `u:object_r:ksu_file:s0` /
`u:object_r:lsposed_file:s0` 都会从这条缝里被判成「存在」，表现就是：

```
WARNING: found Magisk; found KernelSU; found LSPosed;
```

这也解释了为什么 A（对账日志）和 B（strict 全清零）两版行为完全不同、
判定文本却一模一样 —— 它压根没走 AV。

### 试过但不能用的做法

- 改 `.rodata` 里的 `proc_pid_attr_operations`：本机 `set_memory_rw()` 对镜像地址
  返回 `-22`，`memcpy` 裸写会 panic（见 `patch/force_patch_table.c` 的注释，之前试过）
- inline hook：需要页表级可写 + CFI 处理，代价远大于收益

### 采用的实现（ko b3，commit `c685394c`）

`kretprobe` 挂 `selinux_setprocattr`（`CONFIG_KPROBES=y`、LTO 全关，符号存在）：

- `entry_handler`：把 `x1`(value) / `x2`(size) 存进 `ri->data`
- `handler`（返回前）：`current_uid() >= 10000` 且 `ksu_ctx_allowed(value) == 0`
  （即类型不在出厂策略里）→ `regs_set_return_value(regs, -EINVAL)`
- 函数本身照常执行（对不存在的类型本来就是拒绝），**零副作用**
- 注册失败也只是 log 一行，不影响其它隐藏层

真机验证：`hide_mark` 里 `do-setprocattr v=0`（注册成功）。

## 2. APatch / KernelPatch 调研结论

APatch 没有独立的隐藏代码，全在 KernelPatch：

- `kernel/patch/common/selinux_hide.c`：5 个 hook —— `sel_write_context`、
  `sel_write_access`、`selinux_setprocattr`、`sel_read_handle_status`、
  `sel_mmap_handle_status`；每个开头都是 `uid < 10000 -> 原函数`
- `kernel/patch/common/selinux_sepolicy.c`：post-fs-data before 阶段用
  `security_read_policy()` + `policydb_read()` + `policydb_load_isids()`
  深拷贝一份**还没被注入规则**的完整策略，之后所有答案都用这份快照算
- 不写 .rodata：`hotpatch_nosync()` 走页表改 PTE（清 RDONLY）+ `stop_machine`；
  符号在构建期打进 kpimg；拿不到函数符号就改数据槽（`write_op[5]/[6]`）
- 粒度：**按 uid 分域 + 整份策略快照**，不是类型黑名单

**可移植性**：本体不可用（要改 boot.img、手写 GKI 版 `struct policydb/sidtab`、
需要 inline hook）。可拆成 4 级：P0（已做）/ P1（access 响应第 5 字段 seqno=1）/
P2（libsepol 离线差集表）/ P3（真快照）。

它还提醒了一个侧信道：`/sys/fs/selinux/ss/sidtab_hash_stats` 任何进程可读，
**用 live policy 解析一个被拒绝的 context 会让 sidtab 变大**，检测器能反推。
我们的 `ksu_ctx_allowed()` 是先查出厂策略再决定，不碰 live 解析，这点是对的。

## 3. 双内核适配（g84ffa64b710b / g7db56fb8f741）

真机提取的 SP7 boot.img（`荣耀Magic6Pro-boot分区-实机提取-SP7-20261105.img`，96 MiB）：

- header **v4**、`kernel_size=40,942,080`、**无 ramdisk**、cmdline 空
- 内核是**原厂未改**（AVB hash descriptor 自洽，`sha256(salt+image[:40947712])` 命中）
- 内嵌 IKCONFIG 与 `config/device-os11.config` **逐字节相同**
  （sha256 `7fbcc7c9…8061`，7888 行）⇒ 源码、补丁偏移、KMI 全部可沿用
- 关键配置：`MODULE_SIG_FORCE=y`、`CFI_CLANG=y`、`LTO` 全关、`KPROBES=y`、
  `KALLSYMS_ALL=y`、`DEBUG_INFO_BTF=y`

所以适配只有一个变量：**vermagic**。做法：

| 项 | 实现 |
|---|---|
| 内核档位 | `config/targets.json` 新增 `os11sp7`（commit `772271c2d0`） |
| ko | CI `42343022885` → `finasu145sp7`，vermagic 已核对 `…-g7db56fb8f741 SMP preempt mod_unload modversions aarch64` |
| patcher 兜底偏移 | `scripts/commit_creds_offset.py` 从 boot.img 直接算（commit `c6e567ea`），SP7 输出 `0x15fe88`，与独立推导、以及 M6 Shell 1.1 里 patcher 内置常量三方一致 |
| 运行时选 ko | `Kernels.kt`：`变体+内核 > 变体 > 内核 > 默认` 四层优先级；APK 里同时带两个 ko，按 `uname -r` 自动选，状态卡显示「内核校验 匹配」 |
| kgo.sh | 按 `uname -r` 选 `--fallback`，两个内核都是 `0x15fe88`，未知内核只走 kallsyms（fail-closed） |

产物：`M6Shell-9.20-dual.apk`（ko `finasu145b3` os11 + `finasu145sp7` sp7，两个都带 P0）。

### 两个坑

1. `0x15fe88` 第一次被算成 `0x15ee88` —— 多减了一次 header 的 `0x1000`。
   PREL32 是「符号 − 字段自身」，扁平 Image 里加出来就是相对 Image 起点的位置。
2. **这个 bash 里没有 `strings`**，早先据此得出的「我们的 exploit 没有
   build_target」是错的。`grep -a` 复核：`exploit-1022g/h/k` 都含 1 处
   `build_target` 和旧内核串 `g84ffa64b710b`。但桌面那份 1.1 APK 的
   `exploit-1021f/h` 内嵌的也是旧串，却在 SP7 上成功 ⇒ `build_target` 只是
   日志/自检，不是门禁。

## 4. 待办

- [x] **P0 真机验收通过（2026-11-07）**：软重启后 DirtySepolicy 2.2 输出
      `OK: no dirty sepolicy found` / `INFO: sequence=0 policyload=0` —— 与干净机基线一致。
      dmesg 命中记录：`SETPROCATTR 'u:r:adbroot:s0' ret=4294967274 -> EINVAL`
      （`4294967274`=`0xFFFFFFEA`，原函数返回低 32 位 -22 未做符号扩展；改写后是规范的 -22）。
- [ ] P1：access 响应第 5 字段（avdSeqNo）改成 `1` —— 已提交 `cfadc1a786`，**未编译**
      （当前探测器没抱怨 seqno，等下一版一起验证）
- [ ] P2：用 libsepol 离线性算出厂策略的 allowed 位图，替掉手写清位
- [ ] SP7 那台若是别的管理器（SukiSU/Next 等），需按对应 `mgr_pkg` 再编 ko
