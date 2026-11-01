#!/usr/bin/env python3
"""su 诊断补丁 v2：除了 sysfs 参数，再把 6 个计数器每 2 秒写进
   /data/local/tmp/.w9/su_diag.txt（本机 SELinux 拒绝 shell 读 sysfs 参数，
   所以文件才是可用通道）。

计数器含义：
  [0] 进入 ksu_handle_execve_sucompat_common 的次数
  [1] 最后一次的 uid
  [2] allow 判定：0=被 allow-list 拒 / 1=允许 / 2=su_force_allow 放行
  [3] 路径命中 "/system/bin/su" 的次数
  [4] filp_open("/data/adb/ksud") 的错误码（0=成功）
  [5] 最终 execveat 返回值
"""
import pathlib
import sys

MARK = "ksu_su_diag"

INC_OLD = "#include <linux/ptrace.h>\n"
INC_NEW = INC_OLD + "#include <linux/workqueue.h>\n#include <linux/jiffies.h>\n"

GLOBALS_OLD = "bool ksu_su_compat_enabled __read_mostly = true;\n"
GLOBALS_NEW = GLOBALS_OLD + """
/* ---- m6-os11-ksu: su 诊断 ---- */
#define KSU_SU_DIAG_PATH "/data/local/tmp/.w9/su_diag.txt"
static int ksu_su_diag[6] = { 0, 0, 0, 0, 0, 0 };
module_param_array_named(su_diag, ksu_su_diag, int, NULL, 0444);
static bool ksu_su_force_allow = false;
module_param_named(su_force_allow, ksu_su_force_allow, bool, 0644);

static void ksu_su_diag_dump(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_su_diag_work, ksu_su_diag_dump);

static void ksu_su_diag_dump(struct work_struct *w)
{
\tchar buf[160];
\tint n;
\tloff_t pos = 0;
\tstruct file *f;

\tn = snprintf(buf, sizeof(buf), "%d %d %d %d %d %d\\n",
\t\t     ksu_su_diag[0], ksu_su_diag[1], ksu_su_diag[2],
\t\t     ksu_su_diag[3], ksu_su_diag[4], ksu_su_diag[5]);
\tf = filp_open(KSU_SU_DIAG_PATH, O_WRONLY | O_TRUNC, 0);
\tif (!IS_ERR(f)) {
\t\tkernel_write(f, buf, (size_t)n, &pos);
\t\tfilp_close(f, NULL);
\t}
\tschedule_delayed_work(&ksu_su_diag_work, 2 * HZ);
}
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

INIT_OLD = """    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\\n");
    }
"""
INIT_NEW = INIT_OLD + """    schedule_delayed_work(&ksu_su_diag_work, 2 * HZ);
"""

EXIT_OLD = """void __exit ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
"""
EXIT_NEW = """void __exit ksu_sucompat_exit()
{
    cancel_delayed_work_sync(&ksu_su_diag_work);
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
"""

EDITS = [
    ("includes", INC_OLD, INC_NEW, 1),
    ("globals", GLOBALS_OLD, GLOBALS_NEW, 1),
    ("allow-check", ALLOW_OLD, ALLOW_NEW, 1),
    ("path-hit", HIT_OLD, HIT_NEW, 1),
    ("ksud-open", KS_OLD, KS_NEW, 1),
    ("exec-ret", RET_OLD, RET_NEW, 1),
    ("init", INIT_OLD, INIT_NEW, 1),
    ("exit", EXIT_OLD, EXIT_NEW, 1),
]


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: apply_su_diag2.py <KernelSU-source-dir>", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1]) / "kernel" / "feature" / "sucompat.c"
    if not src.is_file():
        print("[su-diag2] !! 找不到 %s" % src, file=sys.stderr)
        return 1

    text = src.read_text(encoding="utf-8")
    if MARK in text:
        print("[su-diag2] 已打过补丁，跳过")
        return 0

    for name, old, new, want in EDITS:
        got = text.count(old)
        if got != want:
            print("[su-diag2] !! 锚点 '%s' 命中 %d 次（期望 %d），放弃" % (name, got, want),
                  file=sys.stderr)
            return 1
        text = text.replace(old, new, want)
        print("[su-diag2] ok: %s" % name)

    src.write_text(text, encoding="utf-8")
    print("[su-diag2] 写回 %s" % src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
