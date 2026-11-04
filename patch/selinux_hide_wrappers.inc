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

