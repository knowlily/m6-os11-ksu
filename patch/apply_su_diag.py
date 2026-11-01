#!/usr/bin/env python3
"""给 SukiSU/UAPI6 的 kernel/feature/sucompat.c 打「su 诊断」补丁。

目的：`su` 执行失败时，不用 dmesg（要 root）也能从
      /sys/module/kernelsu/parameters/su_diag 读出失败点。

产出参数（都可读，0444）：
  su_diag      = [entry_cnt, last_uid, allow, path_hit, ksud_open_err, exec_ret]
                 allow:  0=被 allow-list 拒   1=允许   2=su_force_allow 放行
  su_force_allow (0644, 可装载时传参 su_force_allow=1) 跳过 allow-list 检查

装完可以用：
  adb shell cat /sys/module/kernelsu/parameters/su_diag
"""
import pathlib
import sys

MARK = "ksu_su_diag"

GLOBALS_OLD = "bool ksu_su_compat_enabled __read_mostly = true;\n"
GLOBALS_NEW = GLOBALS_OLD + """
/* ---- m6-os11-ksu: su 诊断（只读参数，shell 也能 cat） ---- */
static int ksu_su_diag[6] = { 0, 0, 0, 0, 0, 0 };
module_param_array_named(su_diag, ksu_su_diag, int, NULL, 0444);
static bool ksu_su_force_allow = false;
module_param_named(su_force_allow, ksu_su_force_allow, bool, 0644);
"""

ALLOW_OLD = """    if (!ksu_is_allow_uid_for_current(current_uid().val))
        goto do_orig_execve;
"""
ALLOW_NEW = """    ksu_su_diag[0]++;
    ksu_su_diag[1] = (int)current_uid().val;
    if (ksu_su_force_allow) {
        ksu_su_diag[2] = 2;
    } else if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        ksu_su_diag[2] = 0;
        goto do_orig_execve;
    } else {
        ksu_su_diag[2] = 1;
    }
"""

HIT_OLD = """    if (likely(memcmp(path, su_path, sizeof(su_path))))
        goto do_orig_execve;

    pr_info("sys_execve su found\\n");
"""
HIT_NEW = """    if (likely(memcmp(path, su_path, sizeof(su_path))))
        goto do_orig_execve;

    ksu_su_diag[3]++;
    pr_info("sys_execve su found\\n");
"""

KS_OLD = """    if (IS_ERR(ksud_file)) {
        pr_err("open ksud err: %ld\\n", PTR_ERR(ksud_file));
        put_unused_fd(tmp_fd);
        goto do_orig_execve;
    }
"""
KS_NEW = """    if (IS_ERR(ksud_file)) {
        ksu_su_diag[4] = (int)PTR_ERR(ksud_file);
        pr_err("open ksud err: %ld\\n", PTR_ERR(ksud_file));
        put_unused_fd(tmp_fd);
        goto do_orig_execve;
    }
    ksu_su_diag[4] = 0;
"""

RET_OLD = """    return ret;

do_orig_execve:
"""
RET_NEW = """    ksu_su_diag[5] = (int)ret;
    return ret;

do_orig_execve:
"""

EDITS = [
    ("globals", GLOBALS_OLD, GLOBALS_NEW, 1),
    ("allow-check", ALLOW_OLD, ALLOW_NEW, 1),
    ("path-hit", HIT_OLD, HIT_NEW, 1),
    ("ksud-open", KS_OLD, KS_NEW, 1),
    ("exec-ret", RET_OLD, RET_NEW, 1),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_diag.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "feature" / "sucompat.c"
    if not src.is_file():
        print(f"[su-diag] !! 找不到 {src}", file=sys.stderr)
        return 1

    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-diag] 已打过补丁，跳过")
        return 0

    for name, old, new, want in EDITS:
        got = text.count(old)
        if got != want:
            print(f"[su-diag] !! 锚点 '{name}' 命中 {got} 次（期望 {want}），放弃", file=sys.stderr)
            return 1
        text = text.replace(old, new, want)
        print(f"[su-diag] ok: {name}")

    src.write_text(text, encoding="utf-8")
    print(f"[su-diag] 写回 {src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
