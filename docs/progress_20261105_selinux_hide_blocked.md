# 2026-11-05 FinaSU `selinux_hide` 在 Magic6 Pro(MagicOS10 / 6.1.157) 上为什么不可能生效

## 结论先说

**这颗 ROM 保护内核镜像的物理页：任何 EL1 侧经过 fixmap 别名的写都会被静默丢弃**
（`copy_to_kernel_nofault` 返回 0，目标值不变）。所以 FinaSU 的 `selinux_hide`
（以及 SUSFS、kprobe 之类需要改内核 text/data 的方案）在本机**原理上装不上**，
不是参数/包名/版本问题。

## 证据链（按时间）

| 版本 | 做法 | dmesg | 结果 |
|---|---|---|---|
| 6.7 | `ksu_patch_text()` 原样 | `context_write after patch: 0x…92e4 (my=0x…8b70) ret=0` | 值没变 → patch_text 对 .data 无效 |
| 7.0 | `memcpy` 裸写 | 直接 panic（`write to read-only memory`） | `write_op[]` 在 `ro_after_init` |
| 7.1 | `set_memory_rw` + `memcpy` | `set_memory_rw(0x…53000,1) failed: -22` | arm64 `change_memory_common()` 要 `find_vm_area()`，只认 vmalloc 区 → EINVAL |
| 7.1 | fixmap 直写（phys_from_virt + set_fixmap） | `fixmap_write dst=0x… phy=0xa9253680 ret=0 want=0x…a7a00 got=0x…92e4` | 写「成功」，值不变 |
| 7.2 | 三重回读 + 自身对照 | 见下 | **机制没问题，特指内核镜像页** |

7.2 的关键两行：

```
SELFTEST slot=0xffffffd23ebddd98 before=0xa5a5c3c3deadbeef after=0xa5a5c3c3deadbeef want=0xa5a5c3c3deadbeef ret=0
   → 对自己模块里的 .bss 变量做同一套 fixmap 写：fmap_back == va_back == want ✔ 机制是好的

fixmap dst=0xffffffd240853038 phy=0xa9253038 ret=0 want=0xffffffd23ebc89f0
       fmap_back=0xffffffd23fdea510 va_back=0xffffffd23fdea510
   → 同一套代码写内核 .data：**连 fixmap 自己的回读都是旧值**
linear dst=0xffffffd240853038 lin=0xffffff8029253038 ret=-14
   → 线性别名写直接 EFAULT（__va 基址对不上，次要问题）
```

fixmap 别名读回来的还是旧值 ⇒ 不是缓存问题、不是 phys 算错（同一页里读到的就是旧内容），
而是**写被更高 EL 拦下并静默丢弃**。同类保护在 MTK 上叫 MKP，FinaSU 源码注释里专门提到过。

## 因此不可行的路线

- `ksu_patch_text` / `set_memory_rw` / 裸 `memcpy` / fixmap 直写 —— 全部对内核镜像无效
- kprobe / ftrace / syscall table 补丁 —— 都要改 text，同样无效
- `sel_context_ops.write` 等 fops 槽位 —— 同样在镜像里

## 剩下的可行方向（都不碰内核镜像）

1. **改名**：KSU 注入的类型名 `ksu` / `ksu_file` 换成中庸名字，检测器按名字查不到。
   障碍：`ksud` 二进制里有一处硬编码 `u:r:ksu:s0`（11 字节，可等长替换，但需要挑一个
   4 字符、不冲突、又足够权限的域名），且可能牵动 `ksud su` 的 setexeccon。
2. **盲化检测器**：DirtySepolicy 依赖 app_zygote 的 `security:check_context` / `compute_av`。
   但 KSU 的注入 API 只有 `ksu_allow`（加规则），删不掉已有 allow，改不了。
3. **接受现状**：不做 SELinux 层隐藏，改在「检测器够不到」的方向上做（需要 mount namespace
   或策略侧改动，同样受制于不能删 allow）。

## 版本与提交

- App 版本链：6.7 → 6.8(HOOKTRACE) → 6.9(direct-store) → 7.0(set_memory_rw) → 7.1(fixmap) → 7.2(三重回读+对照)
- ko CI run：41836271974 / 41843118163 / 41850855183 / 41858075229 / 41863987620 / 41874519477
- 补丁脚本：`patch/apply_selinux_hide_backup_once.py`、`apply_selinux_hide_trace.py`、
  `apply_selinux_hide_direct_store.py` + `patch/selinux_hide_wrappers.inc`

> 注：`backup_sepolicy` 只抓一次的补丁（`apply_selinux_hide_backup_once.py`）本身是对的，
> 但因为 hook 根本装不上，它现阶段的收益是 0；留着，等换到不设保护的内核时直接可用。
