# 2026-11-06 下半场：SELinux 隐藏从「名单」改成「出厂策略真相源」

## 1. 9.0 的结论：白名单方向对，但代价是误杀

9.0（`f5892d9`）把黑名单换成 AOSP 标准类型白名单，实测：

- 春秋检测器的 SELinux 一块**干净了** —— 之前那六行关键词（ksu / magisk_file / lsposed_file …）
  和 `sequence` 全都没了，只剩「USB 调试已开启」；
- 但 `app_zygote` 自己起不来：DirtySepolicy 报
  `WARNING: Service connection timeout, app zygote crashed?`，`logcat -b crash` 是 `signal 6 (SIGABRT)`。

原因很直接：app_zygote 进程（uid 10199）启动时要 `selinux_android_setcontext()` 校验**自己的域**
`u:r:app_zygote:s0`，这个名字不在白名单里 → 我们回 `-EINVAL` → JNI FatalError → abort。

**白名单的失效模式就是误杀**：系统里任何一个没被枚举到的域，那个进程直接崩。往后每换一版 ROM
都得重新枚举一遍，不划算。

## 2. 检测器到底在测什么（反编译 DirtySepolicy 2.0）

`org.lsposed.dirtysepolicy` 只有 20 KB，dex 里只有一个 AppZygote 服务。它做的检查（按 smali 顺序）：

| 检查 | 手段 | 探测串 |
|---|---|---|
| 自身上下文 | 读 `/proc/self/task/*/attr/current` | 期望 `u:r:app_zygote:s0` |
| check_context | 写 `/sys/fs/selinux/context` | `u:r:kernel:s0` |
| access oracle | 写 `/sys/fs/selinux/access` | `setcurrent` / `system_server execmem` / `shell→su transition` |
| Magisk | access oracle | `u:r:magisk:s0`、`u:object_r:magisk_file:s0`、`rootfs/tmpfs filesystem associate`、`fifo_file open` |
| KernelSU | access oracle | `u:r:ksu:s0`、`u:object_r:ksu_file:s0`、`u:object_r:adb_data_file:s0` |
| LSPosed | access oracle | `u:object_r:lsposed_file:s0` + `apk_data_file execute` |
| Xposed / Zygisk | access oracle | `xposed_data` / `xposed_file` / `dex2oat_exec` / `zygote:dir search` |
| status 通道 | 读 `/sys/fs/selinux/status` 前 20 字节 | version/sequence/enforcing/policyload/deny_unknown |

关键结论：**它所有「有没有这个类型」的判断，都落在 `/sys/fs/selinux/{context,access}` 两个写节点上**，
所以只要这两个节点的回答与「该类型不存在」一致，它就什么都看不到。

status 那段（smali 还原）：

```
version != 1                     -> "ERROR: unknown status version"
enforcing != 1                   -> 记 "enforcing="
policyload != 0                  -> 记 "sequence=… policyload=…"（判为异常）
sequence  != 0                   -> 同上
字符串为空                       -> "OK: no dirty sepolicy found"
```

即：内核 < 6.10 时它期望 `sequence=0 / policyload=0`。第三方策略一注入，内核会
`sequence++` 且 `policyload++`，这两个数就是「策略被换过」的铁证 —— 光藏类型名不够。

## 3. 新方案：拿 ROM 出厂策略当真相源（零名单）

`/vendor/etc/selinux/precompiled_sepolicy`（本机 2 173 795 B）是**出厂**的二进制策略，
里面天然没有 ksuf / magisk_file / lsposed_file 这些运行时注入的类型。于是判定规则只剩一句：

> **被查询的类型名，在出厂策略里出现过 → 真的；没出现过 → 一律 `-EINVAL`。**

实现（`patch/selinux_hide_wrappers.inc`）：

1. `ksu_stock_policy_load()` —— 在 ksud 上下文里 `filp_open` + `kernel_read` 整份读进 `vmalloc`；
   找不到文件就退回旧白名单（`pol-fail` 打点）。
2. `ksu_stock_has_name()` —— 在 2 MB blob 里按「裸 ASCII 名字 + 前后非名字字符」做边界匹配。
   实测：`app_zygote / kernel / system_server / dex2oat / zygote / priv_app / tmpfs / rootfs` 都在；
   `ksu / ksu_file / magisk / magisk_file / lsposed_file / xposed_file / zygisk / adbroot` 都不在。
   （`ksu` 在 blob 里只作为 `frame-worksu-tils` 的子串出现两次 —— 边界判断就是为了这个。）
3. 写入口 `my_write_context_auto` / `my_write_access_auto`：
   - uid < 10000 → **直接原样放行**（zygote / system_server / init 一个判定都不做）；
   - 出厂策略里有这个类型 → 调 `i_fop` 副本里的 stock write，回答与未 root 逐字节一致；
   - 没有 → `-EINVAL`。
   不再调 FinaSU 的 `my_write_context()`：它内部走 `security_context_to_sid_with_policy(backup_sepolicy,…)`，
   本机 backup 是 NULL/脏的，而且它把 buf 当**内核**指针用（8.6 的 panic 就是这么来的）。
4. `/sys/fs/selinux/policy` 的 read 不再返回 EOF，改成**回吐出厂策略本体**（`copy_to_user` 按 ppos 分页），
   内容天然不含注入类型，而且是一份语法完整、能被 libsepol 正常解析的策略。
5. `ksu_status_scrub()` —— 拿 `selinux_state` 的地址调
   `selinux_kernel_status_page(struct selinux_state *)`（6.1 是有参版本，别用 0 参指针去调），
   把 `sequence` / `policyload` 拨回 0/0，`enforcing` 拨成 1。改动前的原值写进 `status-before` 打点，
   万一检测器期望的不是 0/0，看这一行就知道该拨到哪。
6. **急救开关**：`/data/local/tmp/.w9/hide_off` 存在 → 整条隐藏链跳过（`do-killed`）。
   hook 一旦装坏，删文件重启再进链即可，不用刷机。

## 4. 判定表（本机 precompiled_sepolicy 实测）

```
出厂策略里有： app_zygote kernel system_server dex2oat zygote priv_app tmpfs rootfs shell su
              untrusted_app_27/_29/_30/_32 platform_app system_app isolated_app ephemeral_app
出厂策略里没有： ksu ksu_file magisk magisk_file lsposed_file xposed_file zygisk adbroot
              untrusted_app（裸名，本机只用 _27/_29/_30/_32） media media_rw vendor_app sdk_sandbox
```

注意 `su` 在**出厂策略里就有**（MagicOS 自带一个 su 域），所以 DirtySepolicy 的
「found AOSP su in user build」这一条是 ROM 属性，不是我们引入的 —— 干净机也一样会报。

## 5. 验收口径

1. **基线**：不装 ko，直接跑 DirtySepolicy / 春秋，记下它们报哪几条（尤其 status 的
   `sequence=` / `policyload=` 具体值）。这是「正常」的定义。
2. **装链后**：输出应与基线逐条一致，只允许差在「USB 调试已开启」这类与 SELinux 无关的项。
3. 系统必须正常：`app_zygote` 不再崩（`logcat -b crash` 无 SIGABRT）、所有 App 能起、
   `getenforce = Enforcing`。

## 6. 版本与产物

- 9.0 = `f5892d9`（白名单 + app_zygote 兜底 + policy 读 EOF），CI 42185324251（已取消，被本方案取代）
- 9.1 = `ba38c82`（真相源 + status 回拨 + 急救开关），CI 42188332080
- ko：`ko_alias=finasu145s`，`ksu_version=33168`，`mgr_pkg=me.yuki.fina`（与 1.4.5 线一致）
- 打点顺序（`/data/local/tmp/.w9/hide_mark`）：
  `queued → inline → do-start → do-stock → do-ctx → do-acc → do-pol → status-before → do-status → do-done`

## 7. 还没做的事

- 设备当前不在线（adb 无设备），以上全部等真机验证。
- `/sys/fs/selinux/user` 节点没挂：DirtySepolicy 不用它，且它的入参是「user role type」三个裸名，
  格式与 context 不同，先不动（少一个 hook 少一份风险）。

---

## 2026-11-06 深夜追加：取证通道建起来了，但 DirtySepolicy 仍报三条

### 1. 找到真正的取证通道：App 的「内核日志」= dmesg，落盘到 klog.txt

`/sdcard/Android/data/com.bvlansu.shell/files/klog.txt`（点一次「内核日志」就会写一次）。
kern 里 `pr_info()` 的每一行都带 `[pid:comm]` 前缀，**进程名可以直接看出来**：

```
[2387:sepolicy_zygote]  ← DirtySepolicy 的 AppZygote
[29476:su.shell_zygote] ← 我们自己 App 的 AppZygote
[32383:ivecheck_zygote] ← 另一个检测器
```

这条通道比 probe.txt 强得多：不用 root、不用 dmesg 权限、能直接看到「谁、问了什么、被怎么处理」。

### 2. 加了两类日志（ko a4/a5）

```c
/* access：ok=1 也要记，否则漏掉的那条永远看不见 */
{ static atomic_t left = ATOMIC_INIT(200);
  if (atomic_dec_if_positive(&left) >= 0)
      pr_info("selinux_hide: ACC uid=%d ok=%d '%s'\n", current_uid().val, ok, kbuf); }

/* context：同上（Li.c() 拿到 EINVAL 后会再用 a(type,type,0) 复核） */
pr_info("selinux_hide: CTX uid=%d ok=%d '%s'\n", current_uid().val, ok, kbuf);
```

### 3. 实测数据（ko a5，软重启后）

`uid=10278`（DirtySepolicy 主进程）实际发出的请求：

```
CTX ok=0  u:r:adbroot:s0 / u:r:magisk:s0 / u:object_r:magisk_file:s0 / u:r:ksu:s0
ACC ok=0  u:object_r:lsposed_file:s0 … / xposed_data / xposed_file（tclass=0 的复核形式）
ACC ok=1  u:r:app_zygote:s0 u:r:app_zygote:s0 2      ← setcurrent 自检，干净机也 true，必须放行
ACC ok=1  u:r:app_zygote:s0 u:r:kernel:s0 1         ← check_context 自检，同上
ACC ok=1  u:r:system_server:s0 u:r:system_server:s0 2
ACC ok=1  u:r:shell:s0 u:r:su:s0 2
ACC ok=1  u:r:dex2oat:s0 u:object_r:dex2oat_exec:s0 6
ACC ok=1  u:r:zygote:s0 u:object_r:adb_data_file:s0 8
```

**关键点：它的 scon 是「它自己」**。smali 实证：

```java
found Magisk   = c(magisk) || c(magisk_file) || b(rootfs,tmpfs,associate) || b(self,tmpfs,fifo_file,open)
found KernelSU = c(ksu)    || c(ksu_file)    || b(self,adb_data_file,file,read)
found LSPosed  = c(lsposed_file)             || b(v8,apk_data_file,file,execute)
```

之前按 scon 写 `zygote` / `kernel` 的规则全部匹配不到，所以 9.9~9.12 的「类型对拦截」对它基本无效。

### 4. 改成只按 tcon 匹配（ko a6）

```c
{"system_server", "system_server"},  /* execmem */
{"shell", "su"},                     /* transition */
{"", "rootfs"}, {"", "tmpfs"},       /* Magisk associate / fifo open */
{"", "adb_data_file"},               /* KernelSU read / ZygiskNext search */
{"", "apk_data_file"},               /* LSPosed execute */
{"", "dex2oat_exec"},                /* Xposed execute_no_trans */
```

结果：**DirtySepolicy 输出没变**，仍 `WARNING: found Magisk; found KernelSU; found LSPosed;`。

### 5. 排除掉的可能

- **不是 superuser 导致的**（用户确认：那个「检查 Root 权限」界面是别的 App）。
- **不是 `b()` 异常返回值导致的**：`b()` 的 catch 全部 `return false`（`readId: …` / `checkSELinuxAccess: …` 后返回 v4）。
- **不是无路可走**：`a6` 之后 `ACC ok=1 'u:r:zygote:s0 u:object_r:adb_data_file:s0 8'` 后面紧跟 `pair deny uid=10278`，tcon-only 规则**确实命中**。
- **hide_off 对照组无效**：`/data/local/tmp/.w9/hide_off` 是 shell 建的（0666），但内核侧用 `kern_path()` 判断，受 SELinux 目录搜索权限限制；app 上下文很可能根本看不到它 → 两次输出一模一样，不能当基线。

### 6. 已知的坑（本轮新增）

- `CTX`/`ACC` 各自上限 200 条，且 dmesg 是环形缓冲，**日志会被刷掉**。查不到某条请求不等于它没发生。
- DirtySepolicy 的 `DirtySepolicyService` 跑在 **isolated process（uid 90000）**，启动后常被 `isolated not needed` 立刻杀掉；真正干活的还是 `sepolicy_zygote`（uid 10278）。
- 它的 `b()` 需要读 `/sys/fs/selinux/class/<cls>/index`；在 app_zygote 里读不到就抛 `readId:` 并返回 false。

### 7. 下一步（未做）

1. 把「最终返回给用户态的值」（rv + 清零后的首词）也打进日志，确认 pair deny 之后它到底收到了什么。
2. 给 `context` 路径加「放行」日志的同时**按类型白名单兜底**：除调用者自身上下文与出厂策略里确实存在的类型外，全部 EINVAL。
3. 更彻底的做法：直接 patch `security_compute_av_user` 的返回，让 app 域（uid>=10000）拿到全 0 位图，而不是在 selinuxfs 层做字符串匹配。

---

## 2026-11-07 上午：A / B 两版 ko 已就绪（并行编译）

两条路各出一个独立 APK，装机互斥（二选一），都可以单独回滚。

| 方案 | ko 别名 | md5 | APK |
|---|---|---|---|
| A 对账日志 | `finasu145b1` | `4fe045d507b8e2c102d9fbb266ee4dd1` | `dist/M6Shell-9.17-A.apk` |
| B 严格白名单 | `finasu145b2` | `1131f4b3ddb6ebda6c7984d95b10c1b5` | `dist/M6Shell-9.18-B.apk` |

### A（诊断用，不改行为）

新增 `ksu_log_res()`，每条 selinuxfs 请求打一对：

```
selinux_hide: RES rv=<长度> q='<请求原文>' a='<应答首词>'
selinux_hide: ACC uid=.. ok=.. '<请求原文>'
selinux_hide: pair deny uid=..
```

`a='0'` = 位图已清零（对方判 not allowed）；`a='1'` = 真的放行了。
上限 300 条，覆盖 pair deny 之后 / 正常放行两条路径；类型层拒绝走 EINVAL 不产生 RES。
**用途**：把「问了什么 → 最后收到什么」对齐，一次跑完就能定位 DirtySepolicy 到底从哪条拿到 true。

### B（行为实验，可能误伤）

`ksu_pair_denied()` 换成严格白名单，不再枚举 tcon：

```
放行条件（两条，都是干净机本来就 allowed 的通道自检）：
  1) scon 是应用自身域（app_zygote / untrusted_app / isolated_app）且 tcon 含 kernel
  2) scon == tcon（同一应用域，process/setcurrent）
其余一律：照常调 stock，然后把 allowed 位图清零。
```

风险：应用域对 selinuxfs 的其他 AV 查询会全部拿到 0，若有正经 App 依赖这个接口会受影响。
急救：`/data/local/tmp/.w9/hide_off`（注意：shell 建的 0666 文件内核侧可能看不到，见上文）。

### 测试顺序建议

先 A 拿数据（不改行为、无风险），看完 RES 行再决定 B 要不要上。
