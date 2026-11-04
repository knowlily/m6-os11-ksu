# 2026-11-04 提速实测：墙钟埋点 + 三个"静默失败"坑

## 结论先行

| 跑次 | 结果 | 耗时 | 卡在哪 |
|---|---|---|---|
| 17:27（4.3） | 成功 | 51.9 s | 单轮，ksu 发 miss 两次 |
| 18:08（4.5） | 全败 ×3 | 278.4 s | 二进制 TLS 未对齐，Aborted；pgrep 自匹配白等 90s×3 |
| 18:21（4.6） | 立刻中止 | 2.6 s | FATAL 判定生效（同一份坏二进制） |
| 18:24（4.7） | 8 分钟后被判失败 | 329.4 s | sig_enforce 3 发全 miss → EKEYREJECTED；App 傻等 240 s |
| **18:47（4.8）** | **成功** | **45.9 s** | 一次 23.4 s 的 miss 拖累，其余全顺 |

## 1. 那 38 秒的真实去向（墙钟实测）

4.8 成功那一发的 `[wall]` 时间线：

```
start t=0.0
pressure_done t=2.7          ← 压力填充只 2.7 s（原以为是瓶颈，猜错了）
shot 1  2.7 → 6.7    hit round=1
shot 2  6.7 → 9.3    hit round=1
shot 3  9.3 → 32.7   MISS，churn 跑满 16 轮 65536 个 timer，再等 1.5 s
shot 4 32.7 → 34.0   hit round=1
shot 5 34.0 → 36.7   hit round=1  → [ksu] sig_enforce now=N
rootd 36.7
```

**单发内部（`[t] total`）只有 1.3~4.0 s**，fork + mmap 50000 vma 不是瓶颈（`ready` 0.3~1.2 s）。

**miss 才是**：一次 miss = churn 16 轮（65536 timer）+ 1.5 s 空等 ≈ 21~23 s。

统计今天三份 fire.log：**12 次命中全部在 round 0 或 1**；5 次 miss 全部跑满到 round 15 仍未 hit。

⇒ `CHURN_ROUNDS=16` 对命中率没有贡献，只把每次 miss 从 ~6 s 放大到 ~21 s。
建议降到 4（`PC98260_CHURN_ROUNDS`，App 侧 `churnRounds`），miss 代价降到 ~6 s，
用省下的时间换更多次尝试。

## 2. 三个静默失败坑（都已修）

### 2.1 静态二进制 TLS 段未对齐

```
error: "./exploit-1022o": executable's TLS segment is underaligned:
       alignment is 8 (skew 0), needs to be at least 64 for ARM64 Bionic
Aborted
```
clang 静态链接产出 `PT_TLS p_align=8`，Bionic 拒绝 exec。
⇒ `mr1021/build_exploit.sh` 固化：编完立刻 `python3 scripts/fix_tls_align.py $OUT 64` 并回显。

### 2.2 部署判重只看尺寸

修完 TLS 的二进制和修之前**字节数相同**（2456392），部署阶段判"未变化"直接跳过，
手机上跑的还是坏文件 —— 日志显示部署成功、实际没有。
⇒ 改成 md5 比对（本地 `md5Hex(bytes)`，设备端 `md5sum` 一次批量取）。

### 2.3 `pgrep -f 'exploit-1022'` 匹配到自己

包着这条命令的 `sh -c` 的 cmdline 里就含有 `exploit-1022`，于是 payload 秒退也永远 "ALIVE"，
每轮白等满 90 s。
⇒ 改 `pidof exploit-1022o`（comm 精确匹配）；并在 fire.log 出现 `Aborted|underaligned` 时判 FATAL，不重试。

### 2.4 外壳 rc 掩盖真实结果

`su98260 -c 'sh kgo.sh'` 的 rc 恒为 0，真正的结论在 `kgo.log` 的 `load_ko rc=4`。
App 只看外壳 rc → 以为成功 → 去轮询 `/proc/modules` 等满 240 s。
⇒ 解析 `load_ko rc=`，非 0 立刻带原因退出。

## 3. 新发现：`su98260` 只在 Permissive 窗口内可用

`rootd` 是无限 accept 循环、`chmod 0666`、认 uid 0/2000，本身没问题。真正的限制是 SELinux：

- kgo 阶段 `[kgo] start ... enforce=0` —— 这时能连
- 模块加载后 SELinux 回到 Enforcing → 之后所有 `su98260` 都返回
  `connect root daemon: Permission denied`（UNIX socket 的 connectto 被 label 拦）

所以 App 在装完模块之后做的「特性探测」**永远会失败**（日志里反复出现那行）。
「卸载模块」开关能亮，是因为内核真的注册了 handler（`ksu_kernel_umount_init`），不是因为探测成功。

⇒ 若要装完还能用 root 通道，得让 rootd 在 bind 前把 socket 的创建标签写成 shell 可连的类型
（`/proc/self/attr/fscreate`），或者把探测并进 kgo.sh 的有权窗口内。

## 4. 性能账（当前最好水平）

| 组成 | 耗时 |
|---|---|
| 部署 + 校验（md5 判重） | 2.0 s |
| 5 发 UAF（4 hit + 1 miss） | 34 s |
| kgo（ksud install + insmod + su probe） | ~8 s |
| 合计 | **45.9 s** |

若那次 miss 也算 hit（或 CHURN_ROUNDS 降下来后重试一发）→ 可进 **22 s** 左右。

## 5. 结果：CHURN_ROUNDS 16 → 4，总耗时 45.9 s → 23.0 s

```
total 22989ms
549ms   1 工作目录     275ms 1.5 ksud+uapi    918ms 2 部署二进制     21246ms 7 完成
[wall] start 0.0 → pressure_done 2.3
shot1 2.3→4.7  hit round=1
shot2 4.7→6.2  hit round=0
shot3 6.2→8.5  hit round=1
shot4 8.5→11.7 hit round=1
shot5 11.7→13.7 hit round=1 → [ksu] sig_enforce now=N
rootd 13.7 → kgo ~7.5 s → kernelsu Live (E)
```

**五发全部在 round 0/1 命中，没有一次 miss** —— 降轮次对命中率零影响，验证了上面的统计。

### 剩下的时间账（距离 15 s 还差 8 s）

| 段 | 耗时 | 说明 |
|---|---|---|
| 压力填充 | 2.3 s | 每次从 ~7 GB 压到 4.8 GB，必须真写内存 |
| 5 发 UAF | 11.4 s | 每发 ~2 s，已是现状下限 |
| kgo（ksud install + patcher 1.9 s + insmod + su probe） | ~7.5 s | patcher 解析 4580 个符号，insmod 660 KB |
| 其它（部署/校验/getenforce） | ~1.7 s | |

要再往下压只有两条路：把压力 hog 做成常驻进程（跨开火复用）、或 kgo 里跳过未变化的 `su` 重写。
