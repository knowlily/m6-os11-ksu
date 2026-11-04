#!/usr/bin/env python3
"""在 kernel/core/init.c 里注册 kernel_umount feature handler。

## 现象
管理器「设置」页第一张卡片「卸载模块（总开关）」灰掉，文案「内核不支持此特性 ·
当前：未知或未保存 · 重启后：开启」；`ksud feature list` 里 kernel_umount 是
[NOT_SUPPORTED]，`ksud feature get kernel_umount` 报 ksuctl failed: EPERM。

## 根因（已核实到产物层面）
`kernel/feature/kernel_umount.c` 的 `ksu_kernel_umount_init()` 只做一件事：
    ksu_register_feature_handler(&kernel_umount_handler);
而 FinaSU v1.4.2 的 `kernel/core/init.c`：

  * feature 初始化序列里（module_blacklist / sulog / adb_root / lsm /
    selinux_hide / shell_su_adb_only / avc_spoof / mvf / uts_view / netisolate）
    **没有** ksu_kernel_umount_init()；
  * 唯一的调用点藏在 `ksu_setuid_hook_init()` 里，后者整体被
    `#ifdef CONFIG_KSU_HOOK_SUSFS_INLINE` 包着 —— 本机用 manual/tracepoint 后端，
    这个宏不成立，于是永远不执行。

结果：`ksu_kernel_umount_init` 属于「无调用者的全局函数」，LTO 直接把它丢掉。
实测产物 nm 里能查到 kernel_umount_feature_get/set、ksu_handle_umount、
ksu_kernel_umount_exit，**唯独没有 ksu_kernel_umount_init** —— 与推断一致。
没有 handler → `ksu_get_feature()` 回 supported=false → 管理器判定「内核不支持」。

## 修法
在 feature 初始化块里显式调用一次。handler 本身只是个开关
（`ksu_kernel_umount_enabled`，默认 true），真正干活的是 setuid hook 里的
`ksu_handle_umount()`，那条路径已经编进产物（字符串 "handle umount for uid"
和 "kernel_umount: set to" 都在 k9.ko 里查得到），所以补上注册即可。

幂等：已经调过就直接退出，方便 CI 反复跑。
"""
import sys
from pathlib import Path

INIT = Path("kernel/core/init.c")
HDR = '#include "feature/kernel_umount.h"'
CALL = "ksu_kernel_umount_init();"

# 优先挂在 mvf 之后（现代 FinaSU），退化时依次往前找锚点
ANCHORS = ["ksu_mvf_init();", "ksu_avc_spoof_init();", "ksu_sulog_init();"]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    init = root / INIT
    if not init.is_file():
        print(f"!! {init} 不存在 —— 这份源码树结构不一样，跳过")
        return 0

    src = init.read_text(encoding="utf-8", errors="surrogateescape")
    if CALL in src:
        print("kernel_umount: 已经有 ksu_kernel_umount_init() 调用，跳过")
        return 0

    if HDR not in src:
        anchor = '#include "feature/sulog.h"'
        if anchor in src:
            src = src.replace(anchor, anchor + "\n" + HDR, 1)
        else:
            anchor = '#include "policy/feature.h"'
            if anchor not in src:
                print("!! 找不到可用的 include 锚点，放弃")
                return 1
            src = src.replace(anchor, anchor + "\n" + HDR, 1)
        print(f"kernel_umount: 插入 {HDR}")

    vm = "kernelsu_init(void)"
    head, sep, tail = src.partition(vm)
    if not sep:
        print("!! 找不到 kernelsu_init()，放弃")
        return 1

    done = False
    for anchor in ANCHORS:
        if anchor in tail:
            tail = tail.replace(
                anchor,
                anchor
                + "\n    // 上游漏了注册：kernel_umount 的 handler 没人登记，"
                "管理器会显示「内核不支持此特性」\n    " + CALL,
                1,
            )
            print(f"kernel_umount: 在 {anchor} 之后插入 {CALL}")
            done = True
            break
    if not done:
        print("!! feature 初始化锚点一个都没匹配到，放弃")
        return 1

    init.write_text(head + sep + tail, encoding="utf-8", errors="surrogateescape")

    # 自检：调用点必须在 kernelsu_init 内、且只出现一次
    out = init.read_text(encoding="utf-8", errors="surrogateescape")
    n = out.count(CALL)
    print(f"---- 自检 ----\n{CALL} 出现 {n} 次；include {'有' if HDR in out else '缺'}")
    return 0 if n == 1 and HDR in out else 1


if __name__ == "__main__":
    sys.exit(main())
