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

static int ksu_ro_write(void *dst, const void *src, size_t n)
{
    unsigned long a = (unsigned long)dst;
    unsigned long first = a & PAGE_MASK;
    unsigned long last = (a + n - 1) & PAGE_MASK;
    int pages = (int)((last - first) / PAGE_SIZE) + 1;
    int r;

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
    pr_info("selinux_hide: ro_write dst=0x%lx val=0x%lx pages=%d ok\n", a, *(const unsigned long *)src, pages);
    return 0;
}

ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    if (likely(current_uid().val < 10000)) {
        return orig_context_write ? ksu_call_orig(orig_context_write, file, ubuf, size, ppos) : -EINVAL;
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

