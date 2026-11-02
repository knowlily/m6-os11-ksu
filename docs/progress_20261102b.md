# 2026-11-02（下半场）：包名/签名、版本号对齐、单管理器加冕、churn 加压

承接 `progress_20261102.md`。这一轮把 App 变成可以对外发的正式包，并解决了「ko 版本号和管
理器对不上」「选 BakaSU 却把 KernelSU 一起加冕」「内存太闲导致 UAF 卡在等页面」三件事。

## 1. 包名与 release 签名

```
applicationId / namespace : com.knowlily.ksuapp → com.bvlansu.shell
源码目录                  : app/src/main/java/com/bvlansu/shell/
签名                      : release.jks（RSA 4096，validity 10000，alias=bvlansu）
口令                      : keystore.properties（项目根，不进仓库）
```

`apksigner verify --print-certs` 输出：

```
Signer #1 certificate DN: CN=BVLANSU, OU=Shell, O=BVLANSU, L=Suqian, ST=Jiangsu, C=CN
SHA-256: 3e5ea93c6091cd22cf55fbcc11d9081a00b9c60a4f2c0295ee12e43ceccf3b65
```

release 走 R8：**9.3 MB**（debug 是 11.7 MB）。

> `release.jks` 丢了就没法给同一包名做覆盖升级，务必另存备份。

## 2. ko 版本号对齐各家管理器

管理器首页会同时显示「版本 30001-6」和「管理器版本 v1.4.3 (33156-6)」，两者对不上时看着像
装错了。CI 新增输入 `ksu_version` + `patch/set_version.py`，把 `KSU_VERSION` 改成管理器自己
的号（**不动 uapi 版本**，也不动 `KSU_VERSION_FULL` / `KSU_VERSION_TAG`）。

各家 `kernel/Kbuild` 的写法不一样，三处都要覆盖：

```make
tiann / FinaSU / Next : $(eval KSU_VERSION=$(shell expr 30000 + $(KSU_GIT_VERSION)))
                        ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
SukiSU                : ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
BakaSU                : KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + 700)
```

目标值：

| 管理器 | KSU_VERSION |
|---|---|
| SukiSU | 41100 |
| KernelSU-Next | 33355 |
| FinaSU | 33156 |
| KernelSU | 32680 |
| BakaSU | 35252 |

### ★ 坑：正则 `[^)]*` 会把括号吃掉

```python
re.sub(r"\$\(eval KSU_VERSION=[^)]*\)", ...)      # 错
```

原始行是 `$(eval KSU_VERSION=$(shell expr 30000 + $(KSU_GIT_VERSION)))`，`[^)]*` 停在
`$(KSU_GIT_VERSION` 的右括号上，替换后剩下一串多余的 `)))`：

```
$(eval KSU_VERSION=33156)))        → make: *** missing separator
```

改成**整行替换**（`^\s*\$\(eval KSU_VERSION=.*$`）才对。

## 3. 一份 ko 只加冕一个管理器

之前 5 家共用「多管理器包名」补丁 `apply_mgr_pkgs.py`（运行期 `mgr_pkgs=a,b,c`）。真机现象：
**选 BakaSU 点火，BakaSU 和官方 KernelSU 两个都变成「工作中」**。

原因在 BakaSU 的认管理器方式和别家不同：

```c
/* tiann / Next / FinaSU：2 参，按包名 */
static void crown_manager(const char *apk, struct list_head *uid_data)

/* BakaSU：3 参，按签名 */
static void crown_manager(const char *apk, struct list_head *uid_data, u8 signature_index)
{
    ...
    ksu_register_manager(np->uid, signature_index);   /* is_manager_apk() 签名白名单 */
}
```

BakaSU 是 KernelSU 衍生版，官方 KernelSU 的签名在它的兼容白名单里 ⇒ 签名扫描顺手把它也加冕。
补丁原先对 3 参分支是主动跳过的（硬替换会 `too many arguments`），洞就留在这儿。

修法两条：

1. **包名闸门**——在 BakaSU 的 `crown_manager` 入口插：

```c
{
    char _m6_pkg[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_path(_m6_pkg, apk) < 0 || !ksu_pkg_match(_m6_pkg))
        return;
}
```

2. **编译期默认包名**——CI 新增输入 `mgr_pkg`，往 `kernel/Kbuild` 追加
   `ccflags-y += -DM6_MGR_PKG=\"<包名>\"`；`ksu_pkg_match()` 在没传 `mgr_pkgs` 时对比
   `M6_MGR_PKG` 而不是源码默认的 `me.weishu.kernelsu`。这样即使 insmod 参数丢了，一份 ko
   也只认自己那家。

## 4. ★ 坑：按行号插代码插进了 C 字符串字面量

为了不让「C 字符串里混进真换行」再进 CI，加了 `_c_string_guard()`。但插入调用时是按**行号**
找 `s.rstrip() + ` 定位的，那行恰好在三引号**内部**，结果 Python 语句被写进了 C 代码：

```c
}                     ← 文件原来最后一个函数结束
                      ← 空行
        _c_string_guard(s)          ← ★ 这行混进来，C 语法从这儿断
/* 2026-10-21: setresuid kprobe …… */
#include <linux/kprobes.h>
#include <linux/binfmts.h>          ← 编译器认为在函数体里
```

五家同时报错，行号还各不相同（388 / 376 / 371 / 644），但都是我们那段 include 区的第一行：

```
../arch/arm64/include/asm/exec.h:12:1: error: invalid storage class specifier in function declarator
```

`static inline` 出现在函数体里才有这个错 —— 顺着 include 链就能定位到「注入代码前面多了一行」。
**这条同时背锅了 sig_enforce**：当时以为是新加的 `extern bool sig_enforce` 块把文件搞崩，
回退之后照样报错，才回头查到 guard 这行。

教训：往生成器里插代码，一定要用 AST 取字面量的值做校验（`isinstance(n.value, str)` 找含
marker 的最长字符串），别用行号。

## 5. churn 参数：内存太闲时冲不动

真机点火失败日志（`fire.log`）：

```
[uaf] captured=2048 chosen=0xffffff8aba2f0e38 raw=249856
[triple] slab=0xffffff8aba2f0000 idx=1011/1012/1013
[exec] armed 1011/1012/1013
[killer] SIGKILL tgid=17818 old=17825 errno=3
[churn] round=63 total=65536
[stream] waiting page_freed pfn=0xb3a2f0 (cap 120000 ms)
```

前面每一步都对，卡在最后等受害页归还 buddy。对照内存：

```
等待时  MemAvailable = 6996904 kB
100 秒后 MemAvailable = 7324000 kB      ← 反而更多
```

7 GB 空闲，64 轮（65536 页 ≈ 256 MB）的换页量跟没冲一样。加大到：

```
PC98260_CHURN_PER_CPU=512
PC98260_CHURN_ROUNDS=2400      # 约 240 万页 ≈ 9.4 GB 换页量
PC98260_WAIT_CAP_S=180
PC98260_BUDGET_S=900
```

## 6. 本轮 CI 输入速查

```bash
gh workflow run build-ko-os11.yml -R knowlily/m6-os11-ksu \
  -f ksu_repo=LyraVoid/FinaSU -f ksu_ref=v1.4.2 \
  -f ksu_tarball=https://codeload.github.com/LyraVoid/FinaSU/tar.gz/refs/tags/v1.4.2 \
  -f ko_alias=finasu142t -f target=os11 \
  -f ksu_version=33156 -f mgr_pkg=me.yuki.fina \
  -F no_modversions=true -F ksu_debug=true
```

五家 `ko_alias` 对应：

```
finasu142t  33156  me.yuki.fina
sukisu430t  41100  com.sukisu.ultra
ksu331t     32680  me.weishu.kernelsu
next342t    33355  kqvdie.zeykvw.hpbcyd
basu420t    35252  com.resukisu.resukisu
```

## 7. 结果

- 五份 ko 全部编译通过，GOT(311/312/313) 全 0，版本号与包名逐份核对过
- release APK 9.3 MB，`com.bvlansu.shell` 已装机
- 用户确认：BakaSU 单管理器加冕正常、版本号显示正常、提权可用

## 8. 仍然没做的

- **`sig_enforce` 恢复没有落地**。exploit 装载未签名模块时把它清成 0，sysfs
  （`/sys/module/module/parameters/sig_enforce`）是 0444 只读，只能内核侧写回。试过在
  `ksu_sp_hooks_init()` 里直接 `sig_enforce = true;`，但当时被上面那个 guard 事故掩盖，没验
  成。要重做的话：放进**独立 .c 文件**（如 `kernel/hook/arm64/ksu_sp_extra.c`）再挂到 Kbuild，
  不要动 `syscall_hook.c` 的结构。
