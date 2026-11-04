#include <asm/fixmap.h>
#include <asm-generic/fixmap.h>

/* ===== DIRECTSTORE: 4/3 参数自适应包装 =====
 * 本内核里 write_op[] 的调用方可能给内核缓冲区（老式 selinuxfs），
 * 也可能给 __user 指针；两种都不能崩，所以先 copy_from_user，
 * 失败（access_ok 拒了）就说明是内核地址，退回 memcpy。
 */
typedef ssize_t (*ksu_ctx4_fn)(struct file *file, const char __user *buf, size_t size, loff_t *ppos);

/* 3 参 <-> 4 参之间不能直接强转（-Wcast-function-type 会报错），走 union */
static inline ssize_t ksu_call_orig(write_op_fn fn, struct file *file, const char __user *buf, size_t size,
                                    loff_t *ppos)
{
    union {
        write_op_fn f3;
        ksu_ctx4_fn f4;
    } u;
    u.f3 = fn;
    return u.f4(file, buf, size, ppos);
}

/* ===== 关键：write_op[] 和 sel_handle_status_ops 都在 .data..ro_after_init，
 * 直接 memcpy 会触发 "write to read-only memory" 然后 panic（23:24 那次就是这么挂的）。
 * 必须先 set_memory_rw 把所在页改成可写，再写。set_memory_rw 不是导出符号，
 * 通过 kallsyms 在运行时取。
 */
typedef int (*ksu_setmem_fn)(unsigned long addr, int numpages);
static ksu_setmem_fn ksu_set_memory_rw;

/* 两级写：
 *   1) 先试 fixmap 直写（和 ksu_patch_text 同一套：phys_from_virt → set_fixmap → copy_to_kernel_nofault，
 *      但不做 dcache 刷新）——这是官方绕过 ro_after_init 的正路
 *   2) fixmap 之后立刻读回校验；值没变就再退 set_memory_rw（本 ROM 对镜像地址回 -22，大概率没用）
 */
static int ksu_fixmap_write(void *dst, const void *src, size_t n)
{
    int err = 0;
    unsigned long p = (unsigned long)dst;
    unsigned long phy = phys_from_virt(p, &err);
    unsigned long want = *(const unsigned long *)src;
    unsigned long off = p & ~PAGE_MASK;
    unsigned long fmap_back, lin_back, va_back;

    if (err) {
        pr_err("selinux_hide: phys_from_virt(0x%lx) failed: %d\n", p, err);
        return err;
    }

    /* A) fixmap 写 + fixmap 回读 + 镜像别名回读 */
    void *map = set_fixmap_offset(FIX_TEXT_POKE0, phy);
    int ret = (int)copy_to_kernel_nofault(map, src, n);
    fmap_back = *(volatile unsigned long *)map;
    clear_fixmap(FIX_TEXT_POKE0);
    va_back = *(volatile unsigned long *)dst;
    pr_info("selinux_hide: fixmap dst=0x%lx phy=0x%lx ret=%d want=0x%lx fmap_back=0x%lx va_back=0x%lx\n", p, phy,
            ret, want, fmap_back, va_back);
    if (!ret && va_back == want)
        return 0;

    /* B) 线性映射别名写（__va(phy)）+ 回读；copy_to_kernel_nofault 不会 panic */
    void *lin = (void *)((unsigned long)__va(phy));
    int ret2 = (int)copy_to_kernel_nofault(lin, src, n);
    lin_back = *(volatile unsigned long *)lin;
    va_back = *(volatile unsigned long *)dst;
    pr_info("selinux_hide: linear dst=0x%lx lin=0x%lx off=0x%lx ret=%d want=0x%lx lin_back=0x%lx va_back=0x%lx\n", p,
            (unsigned long)lin, off, ret2, want, lin_back, va_back);
    if (!ret2 && va_back == want)
        return 0;

    return -EIO;
}

/* 对照组：对「我们自己模块里的一个静态变量」做同样的 fixmap 写，
 * 用来区分「机制坏」和「目标页被保护/phys 算错」。
 */
static unsigned long ksu_selftest_slot;

static void ksu_fixmap_selftest(void)
{
    unsigned long val = 0xa5a5c3c3deadbeefUL;
    unsigned long before = ksu_selftest_slot;
    int r = ksu_fixmap_write(&ksu_selftest_slot, &val, sizeof(val));
    pr_info("selinux_hide: SELFTEST slot=0x%lx before=0x%lx after=0x%lx want=0x%lx ret=%d\n",
            (unsigned long)&ksu_selftest_slot, before, ksu_selftest_slot, val, r);
}

static int ksu_ro_write(void *dst, const void *src, size_t n)
{
    unsigned long a = (unsigned long)dst;
    unsigned long first = a & PAGE_MASK;
    unsigned long last = (a + n - 1) & PAGE_MASK;
    int pages = (int)((last - first) / PAGE_SIZE) + 1;
    int r;

    r = ksu_fixmap_write(dst, src, n);
    if (!r)
        return 0;

    if (!ksu_set_memory_rw) {
        pr_err("selinux_hide: set_memory_rw unavailable, refuse to patch RO page\n");
        return -ENOSYS;
    }
    r = ksu_set_memory_rw(first, pages);
    if (r) {
        pr_err("selinux_hide: set_memory_rw(0x%lx,%d) failed: %d\n", first, pages, r);
        return r;
    }
    memcpy(dst, src, n);
    pr_info("selinux_hide: ro_write dst=0x%lx want=0x%lx got=0x%lx pages=%d\n", a, *(const unsigned long *)src,
            *(volatile unsigned long *)dst, pages);
    return 0;
}

ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    if (likely(current_uid().val < 10000)) {
        return orig_context_write ? ksu_call_orig(orig_context_write, file, ubuf, size, ppos) : -EINVAL;
    }
    if (!backup_sepolicy) {
        pr_err("selinux_hide: backup_sepolicy NULL, fall back to original\n");
        return ksu_call_orig(orig_context_write, file, ubuf, size, ppos);
    }
    if (!backup_sepolicy) {
        pr_err("selinux_hide: backup_sepolicy NULL, fall back to original\n");
        return ksu_call_orig(orig_access_write, file, ubuf, size, ppos);
    }
    if (size == 0 || size > 4096)
        return -EINVAL;
    char *kbuf = kmalloc(size + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;
    int from_user = 1;
    if (copy_from_user(kbuf, ubuf, size)) {
        memcpy(kbuf, ubuf, size);
        from_user = 0;
    }
    kbuf[size] = 0;
    ssize_t ret = my_write_context(file, kbuf, size);
    if (ret > 0 && from_user) {
        if (copy_to_user((char __user *)ubuf, kbuf, ret))
            ret = -EFAULT;
    }
    pr_info("selinux_hide: DIRECTSTORE ctx-auto uid=%d size=%zu user=%d ret=%zd\n", current_uid().val, size,
            from_user, ret);
    kfree(kbuf);
    return ret;
}

ssize_t my_write_access_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    if (likely(current_uid().val < 10000)) {
        return orig_access_write ? ksu_call_orig(orig_access_write, file, ubuf, size, ppos) : -EINVAL;
    }
    if (size == 0 || size > 4096)
        return -EINVAL;
    char *kbuf = kmalloc(size + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;
    int from_user = 1;
    if (copy_from_user(kbuf, ubuf, size)) {
        memcpy(kbuf, ubuf, size);
        from_user = 0;
    }
    kbuf[size] = 0;
    ssize_t ret = my_write_access(file, kbuf, size);
    pr_info("selinux_hide: DIRECTSTORE acc-auto uid=%d size=%zu user=%d ret=%zd\n", current_uid().val, size,
            from_user, ret);
    kfree(kbuf);
    return ret;
}

