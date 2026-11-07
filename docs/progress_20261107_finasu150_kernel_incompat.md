# 2026-11-07 FinaSU v1.5.0 内核侧不兼容（退回 v1.4.5）

## 现象

用 v1.5.0 源码 + 我们的 `selinux_hide_wrappers.inc` 编译的 ko（`finasu150`，33174）
提权成功后，DirtySepolicy 2.2 报：

```
WARNING: system_server can execmem; found LSPosed; found ZygiskNext; avdSeqNo=5;
```

而 v1.4.5 基线（`finasu145b3`）同一台机器是 `OK: no dirty sepolicy found`。

## 关键判读

- **没有** `found Magisk` / `found KernelSU` → 类型层（context/attr）仍然被挡住
- 但 `system_server can execmem` / `found LSPosed` / `found ZygiskNext` 都在 → 规则对（access）层完全失效
- `avdSeqNo=5`（没被改写成 1）→ 我们的 access **read** hook 也没跑

即：**上游自己的 selinux_hide 在干活，我们的 wrapper 没装上**。

## 已排除

- 补丁脚本没静默失败：`apply_selinux_hide_direct_store.py` 在 v1.5.0 的
  `selinux_hide.c` 上所有 `rep()` 锚点全命中（脚本命中不全时 `exit 1`）
- `selinux_hide.h` v1.4.5 → v1.5.0 零差异
- ko 本身是对的：`/data/local/tmp/.w9/k9.ko`（真正 insmod 的那份）含
  `selinux_setprocattr`×5 与 `pair deny uid=%d bit=%d`
- 不是旧 ko：`/proc/modules` 里的 `376832` 只是内存大小，不能用来分辨版本

## 推断

v1.5.0 重写了 `kernel/feature/selinux_hide.c`（`string_to_context_struct()` 增加
`policy_generation` 参数、orig-policy 元数据缓存、空/换行 context 处理），
我们的 `ksu_ro_write(access_write, ...)` 在运行时大概没能改到目标槽位
（v1.4.5 上同一段代码是好的），所以 access read/write 两个 hook 都没挂上。

无法直接验证：`dmesg` 对 shell 全 deny，本机 `su`/`/dev/su` 不可用
（`ksud` 没装到 `/data/adb/ksu/bin/`），App 的「内核日志」这次只捞到 1 行。

## 决定

**内核侧退回 v1.4.5**，版本号仍烘 `33174` 以匹配已安装的 FinaSU 1.5.0 管理器
（管理器只校验数字）。等 v1.5.0 的 kernel 侧弄明白（或上游稳定后再跟进）。

## 附：v1.5.0 的其它改动与我们无关

- 策略代次跟踪：我们的 status 假页固定 `1/0/1/0/1`，app 看不到真实代次
- 类型元数据缓存：纯性能
- 空/换行 context：我们的 `ksu_ctx_allowed()` 本来就按 `\n` 截断 token
- 模块管理（LSPosed/Xposed/Vector 识别、排序、zip MIME）：Manager 侧
