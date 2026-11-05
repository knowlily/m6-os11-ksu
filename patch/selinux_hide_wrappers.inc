#include <asm/fixmap.h>
#include <asm-generic/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/mm.h>

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

/* ===== 写内核只读页的三条路 =====
 * 本机实测：memcpy 裸写罗data -> panic；set_memory_rw -> -EINVAL；
 * phys_from_virt+fixmap -> copy 返回 0 但回读是旧值（写被拦）。
 * 主路改成 PTE-path：翻掉页表项里的 AP[2] 只读位，写完再翻回。
 * 思路来自 MagicRoot 的 ksm-g84-base.ko（同一颗内核 g84ffa64b710b）：
 * 它的日志串 "KSU-PATCH: fixmap write NOT effective" / "pte-path SUCCESS"。
 */
typedef int (*ksu_setmem_fn)(unsigned long addr, int numpages);
typedef void (*ksu_flush_range_fn)(unsigned long start, unsigned long end);

static ksu_setmem_fn ksu_set_memory_rw;
static ksu_flush_range_fn ksu_flush_tlb_range;

#define KSU_AP_RO_BIT (1UL << 7)
#define KSU_PTE_TYPE_MASK 3UL
#define KSU_PTE_TYPE_BLOCK 1UL

static void ksu_tlb_flush(unsigned long va)
{
    unsigned long s = va & PAGE_MASK;
    if (ksu_flush_tlb_range)
        ksu_flush_tlb_range(s, s + PAGE_SIZE);
    else
        local_flush_tlb_all();
}

static int ksu_pte_write(void *dst, const void *src, size_t n)
{
    unsigned long va = (unsigned long)dst;
    unsigned long want = *(const unsigned long *)src;
    unsigned long got, ent, old_ent;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int flipped;

    pgd = pgd_offset(&init_mm, va);
    if (pgd_none(*pgd)) {
        pr_err("selinux_hide: pte-path pgd none va=0x%lx\n", va);
        return -ENOENT;
    }
    ent = pgd_val(*pgd);
    if ((ent & KSU_PTE_TYPE_MASK) == KSU_PTE_TYPE_BLOCK) {
        pr_err("selinux_hide: pte-path 1G block va=0x%lx ent=0x%lx (unsupported)\n", va, ent);
        return -ENOENT;
    }
    if (pgd_bad(*pgd)) {
        pr_err("selinux_hide: pte-path pgd bad va=0x%lx ent=0x%lx\n", va, ent);
        return -ENOENT;
    }

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -ENOENT;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud)) {
        pr_err("selinux_hide: pte-path pud none va=0x%lx\n", va);
        return -ENOENT;
    }
    ent = pud_val(*pud);
    if ((ent & KSU_PTE_TYPE_MASK) == KSU_PTE_TYPE_BLOCK) {
        pr_err("selinux_hide: pte-path 1G block va=0x%lx ent=0x%lx (unsupported)\n", va, ent);
        return -ENOENT;
    }
    if (pud_bad(*pud)) {
        pr_err("selinux_hide: pte-path pud bad va=0x%lx ent=0x%lx\n", va, ent);
        return -ENOENT;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        pr_err("selinux_hide: pte-path pmd none va=0x%lx\n", va);
        return -ENOENT;
    }
    ent = pmd_val(*pmd);

    /* 关键：2M 块映射时 pmd_bad() 为真，必须先判块再判 bad，否则永远走不到这里 */
    if ((ent & KSU_PTE_TYPE_MASK) == KSU_PTE_TYPE_BLOCK) {
        old_ent = ent;
        flipped = 0;
        if (ent & KSU_AP_RO_BIT) {
            set_pmd(pmd, __pmd(ent & ~KSU_AP_RO_BIT));
            flipped = 1;
            ksu_tlb_flush(va);
        }
        memcpy(dst, src, n);
        got = *(volatile unsigned long *)dst;
        if (flipped) {
            set_pmd(pmd, __pmd(old_ent));
            ksu_tlb_flush(va);
        }
        pr_info("selinux_hide: pte-path BLOCK va=0x%lx ent=0x%lx want=0x%lx got=0x%lx flipped=%d\n", va, old_ent,
                want, got, flipped);
        return got == want ? 0 : -EIO;
    }
    if (pmd_bad(*pmd)) {
        pr_err("selinux_hide: pte-path pmd bad va=0x%lx ent=0x%lx\n", va, ent);
        return -ENOENT;
    }

    pte = pte_offset_kernel(pmd, va);
    if (!pte || !pte_present(*pte)) {
        pr_err("selinux_hide: pte-path pte missing va=0x%lx\n", va);
        return -ENOENT;
    }
    old_ent = pte_val(*pte);
    flipped = 0;
    if (old_ent & KSU_AP_RO_BIT) {
        set_pte(pte, __pte(old_ent & ~KSU_AP_RO_BIT));
        flipped = 1;
        ksu_tlb_flush(va);
    }
    memcpy(dst, src, n);
    got = *(volatile unsigned long *)dst;
    if (flipped) {
        set_pte(pte, __pte(old_ent));
        ksu_tlb_flush(va);
    }
    pr_info("selinux_hide: pte-path PTE va=0x%lx ent=0x%lx want=0x%lx got=0x%lx flipped=%d\n", va, old_ent, want, got,
            flipped);
    return got == want ? 0 : -EIO;
}

static int ksu_fixmap_write(void *dst, const void *src, size_t n)
{
    int err = 0;
    unsigned long p = (unsigned long)dst;
    unsigned long phy = phys_from_virt(p, &err);
    unsigned long want = *(const unsigned long *)src;
    unsigned long fmap_back;
    void *map;
    int ret;

    if (err)
        return err;

    map = set_fixmap_offset(FIX_TEXT_POKE0, phy);
    ret = (int)copy_to_kernel_nofault(map, src, n);
    fmap_back = *(volatile unsigned long *)map;
    clear_fixmap(FIX_TEXT_POKE0);

    pr_info("selinux_hide: fixmap dst=0x%lx phy=0x%lx ret=%d want=0x%lx back=0x%lx\n", p, phy, ret, want,
            fmap_back);
    return (!ret && fmap_back == want) ? 0 : -EIO;
}

static unsigned long ksu_selftest_slot;

static void ksu_fixmap_selftest(void)
{
    unsigned long val = 0xa5a5c3c3deadbeefUL;
    int r = ksu_fixmap_write(&ksu_selftest_slot, &val, sizeof(val));
    pr_info("selinux_hide: SELFTEST slot=0x%lx now=0x%lx want=0x%lx ret=%d\n", (unsigned long)&ksu_selftest_slot,
            ksu_selftest_slot, val, r);
}

static int ksu_ro_write(void *dst, const void *src, size_t n)
{
    unsigned long first = (unsigned long)dst & PAGE_MASK;
    unsigned long last = ((unsigned long)dst + n - 1) & PAGE_MASK;
    int pages = (int)((last - first) / PAGE_SIZE) + 1;
    int r;

    r = ksu_pte_write(dst, src, n);
    if (!r)
        return 0;

    r = ksu_fixmap_write(dst, src, n);
    if (!r)
        return 0;

    if (!ksu_set_memory_rw) {
        pr_err("selinux_hide: all write paths failed\n");
        return -ENOSYS;
    }
    r = ksu_set_memory_rw(first, pages);
    if (r)
        return r;
    memcpy(dst, src, n);
    return (*(volatile unsigned long *)dst == *(const unsigned long *)src) ? 0 : -EIO;
}

ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    char *kbuf;
    int from_user = 1;
    ssize_t ret;

    if (likely(current_uid().val < 10000))
        return orig_context_write ? ksu_call_orig(orig_context_write, file, ubuf, size, ppos) : -EINVAL;
    if (!backup_sepolicy)
        return ksu_call_orig(orig_context_write, file, ubuf, size, ppos);
    if (size == 0 || size > 4096)
        return -EINVAL;

    kbuf = kmalloc(size + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;
    if (copy_from_user(kbuf, ubuf, size)) {
        memcpy(kbuf, ubuf, size);
        from_user = 0;
    }
    kbuf[size] = 0;
    ret = my_write_context(file, kbuf, size);
    if (ret > 0 && from_user) {
        if (copy_to_user((char __user *)ubuf, kbuf, ret))
            ret = -EFAULT;
    }
    pr_info("selinux_hide: ctx-auto uid=%d size=%zu user=%d ret=%zd\n", current_uid().val, size, from_user, ret);
    kfree(kbuf);
    return ret;
}

ssize_t my_write_access_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    char *kbuf;
    int from_user = 1;
    ssize_t ret;

    if (likely(current_uid().val < 10000))
        return orig_access_write ? ksu_call_orig(orig_access_write, file, ubuf, size, ppos) : -EINVAL;
    if (!backup_sepolicy)
        return ksu_call_orig(orig_access_write, file, ubuf, size, ppos);
    if (size == 0 || size > 4096)
        return -EINVAL;

    kbuf = kmalloc(size + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;
    if (copy_from_user(kbuf, ubuf, size)) {
        memcpy(kbuf, ubuf, size);
        from_user = 0;
    }
    kbuf[size] = 0;
    ret = my_write_access(file, kbuf, size);
    pr_info("selinux_hide: acc-auto uid=%d size=%zu user=%d ret=%zd\n", current_uid().val, size, from_user, ret);
    kfree(kbuf);
    return ret;
}
