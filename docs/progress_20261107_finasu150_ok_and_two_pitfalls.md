# 2026-11-07 FinaSU v1.5.0 适配打通（真机全绿）

## 结果

FinaSU **v1.5.0**（KSU_VERSION 33174）+ 我们的补丁，荣耀 Magic6 Pro 上：

```
OK: no dirty sepolicy found
INFO: sequence=0 policyload=0
```

与未 root 干净机逐字一致。

## 上一版为什么挂（两个都是我们自己的 bug，不是上游）

### 1. 按位掩码在 v1.5.0 下静默失效

把「整字清零」换成「只清 execmem 那一位」后，DirtySepolicy 报
`system_server can execmem; found LSPosed; found ZygiskNext; avdSeqNo=5`。
类型层仍是干净的（没有 found Magisk/KernelSU）—— 说明 access 写路径的
响应被改到了，但位置/形式对不上，掩码没落到 allowed 位上。
**结论：改响应缓冲区这条路上，「清零第一个 token」是稳的，按位掩码不稳。**
（v1.4.5 上也是这样，不是 v1.5.0 特有。）

### 2. seqno 一位数被误判为「不需要改」

```c
delta = (e0 - s0) - 1;      /* "5" 一位数 → delta = 0 */
if (delta <= 0) return;     /* 直接返回，一个字符都没改 */
```

`avdSeqNo` 一位数时长度不变，旧代码把「不需要变长度」当成「不需要修改」，
于是一直停在 5。修法：只有**原本就是 1** 才跳过，否则先写首字符，
需要缩短时再 memmove。

## 另一条死路：不能返回 -EACCES

试着让规则对直接 `return -EACCES`（不依赖缓冲区布局），结果 DirtySepolicy
直接中断：

```
ERROR: checkSELinuxAccess: write failed: EACCES (Permission denied)
```

它把非 0 返回当成致命错误。必须回一条**合法的 allowed=0 响应**。

## 现在的完整链（v1.5.0 内核侧）

| 层 | 做法 |
|---|---|
| 类型真相源 | 开机读 `/vendor/etc/selinux/precompiled_sepolicy`，不在出厂策略里的类型 → `-EINVAL` |
| status 假页 | `1/0/1/0/0` 形态的假页（app 读到的 `sequence=0 policyload=0`） |
| access 规则对 | 命中表（system_server self / shell→su / rootfs→tmpfs / kernel→tmpfs / adb_data_file / apk_data_file / dex2oat_exec）→ 照常算，再把 allowed 首 token 清零 |
| avdSeqNo | **所有** app 的 access 响应都改写成 1（不只命中规则对的） |
| attr 第三条腿 | kretprobe `selinux_setprocattr`，把 `EPERM` 改写 `EINVAL` |

## 仍未过的一项

春秋 Native check 的 SELinux 项仍报：

```
检测到可疑 SELinux 上下文/规则关键词：dsp_bypass system_server/self scrubbed verdict
```

- `dsp_bypass` 不在出厂策略里，APK 里也搜不到这个字面量（`.so` 字符串混淆）→
  要么是运行时注入的类型，要么是它自己的混淆关键词表
- `system_server/self` + `scrubbed verdict` 大概率就是我们**对 self 对整字清零**
  留下的痕迹（干净机 system_server→self 本来就允许一堆权限）

下一步方向：只对 self 对做「精确掩码」（先确认清掉了哪一位、响应里 allowed 的实际值），
其余规则对保持整字清零。
