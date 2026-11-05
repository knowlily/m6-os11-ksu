#include <asm/fixmap.h>
#include <asm-generic/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/delay.h>

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

/* ===== FOPS-PATH：不碰内核镜像，改 inode->i_fop（inode 是堆上的，可写） =====
 * 内核镜像页有 stage-2 级写保护（patch_text/memcpy/set_memory_rw/fixmap/翻AP[2] 全试过，
 * 都是 ret=0 但回读旧值）。但 selinuxfs 的 struct inode 是运行时 kmalloc 出来的，
 * inode->i_fop 只是个普通指针字段。把 /sys/fs/selinux/{context,access} 的 inode 上的
 * i_fop 换成我们自己的 struct file_operations 副本（放在模块 .bss），就绕开了整个镜像。
 */
ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos);
ssize_t my_write_access_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos);

static __maybe_unused struct file_operations ksu_ctx_ops;
static __maybe_unused struct file_operations ksu_acc_ops;
static const struct file_operations *ksu_ctx_orig;
static const struct file_operations *ksu_acc_orig;
static __maybe_unused int ksu_fops_state; /* 0=未装 1=已装 */

static struct inode *ksu_path_inode(const char *path, struct file **out)
{
    struct file *f = filp_open(path, O_RDONLY, 0);
    struct inode *in;
    if (IS_ERR(f)) {
        pr_err("selinux_hide: fops open %s failed %ld\n", path, PTR_ERR(f));
        return NULL;
    }
    in = file_inode(f);
    if (!in || !in->i_fop) {
        filp_close(f, NULL);
        return NULL;
    }
    if (out)
        *out = f;
    return in;
}

static int ksu_fops_patch(const char *path, struct file_operations *copy, const struct file_operations **orig,
                          void *new_write)
{
    struct file *f = NULL;
    struct inode *in = ksu_path_inode(path, &f);
    const struct file_operations *cur;

    if (!in)
        return -ENOENT;
    cur = in->i_fop;
    memcpy(copy, cur, sizeof(*copy));
    if (new_write) {
        /* 内核里 write_op_fn 是老的 3 参签名，而 fops.write 是 4 参，两者强转会 -Werror，用 union 过渡 */
        union {
            void *p;
            ssize_t (*f4)(struct file *, const char __user *, size_t, loff_t *);
        } u;
        u.p = new_write;
        copy->write = u.f4;
    } /* new_write==NULL：只换指针、不动 write，做 A/B 对照 */
    *orig = cur;
    WRITE_ONCE(in->i_fop, copy);
    filp_close(f, NULL);
    pr_info("selinux_hide: fops %s: inode=0x%lx orig_fop=0x%lx ours=0x%lx\n", path, (unsigned long)in,
            (unsigned long)cur, (unsigned long)copy);
    return 0;
}

static int ksu_fops_restore(const char *path, const struct file_operations *orig)
{
    struct file *f = NULL;
    struct inode *in;

    if (!orig)
        return 0;
    in = ksu_path_inode(path, &f);
    if (!in)
        return -ENOENT;
    WRITE_ONCE(in->i_fop, orig);
    filp_close(f, NULL);
    pr_info("selinux_hide: fops %s restored to 0x%lx\n", path, (unsigned long)orig);
    return 0;
}

/* status 页是普通内核页（可写），直接改字段，不用 hook */
typedef struct page *(*ksu_status_page_fn)(void);

static __maybe_unused int ksu_status_scrub(void)
{
    ksu_status_page_fn fn;
    struct page *pg;
    u32 *sp;

    fn = (ksu_status_page_fn)find_kernel_symbol_exact("selinux_kernel_status_page");
    if (!fn) {
        pr_err("selinux_hide: status_scrub: no selinux_kernel_status_page\n");
        return -ENOSYS;
    }
    pg = fn();
    if (!pg) {
        pr_err("selinux_hide: status_scrub: page null\n");
        return -ENOENT;
    }
    sp = (u32 *)page_address(pg);
    if (!sp || sp[0] != 1) {
        pr_err("selinux_hide: status_scrub: bad page 0x%lx\n", (unsigned long)sp);
        return -EINVAL;
    }
    pr_info("selinux_hide: status before ver=%u seq=%u enf=%u pl=%u dn=%u\n", sp[0], sp[1], sp[2], sp[3], sp[4]);
    sp[1] = 1;
    sp[3] = 0;
    pr_info("selinux_hide: status after seq=%u pl=%u\n", sp[1], sp[3]);
    return 0;
}

/* 老路：镜像写（本机全部无效，保留做对照日志） */
static int ksu_ro_write_old(void *dst, const void *src, size_t n)
{
    int r = ksu_pte_write(dst, src, n);
    if (!r)
        return 0;
    r = ksu_fixmap_write(dst, src, n);
    if (!r)
        return 0;
    return -EIO;
}

/* ===== 延迟执行：module init 阶段 filp_open 会卡死（6.9/7.7 都死在 init_module） ===== */
/* 落盘打点：内核 dmesg 在这台机器上 root 也读不到，改成写文件当面包屑 */
static void ksu_mark(const char *what, long v)
{
    struct file *f;
    char buf[96];
    int n;

    n = snprintf(buf, sizeof(buf), "%s v=%ld up=%d\n", what, v, (int)(ktime_get_boottime_seconds()));
    f = filp_open("/data/local/tmp/.w9/hide_mark", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(f)) {
        pr_err("selinux_hide: mark open failed %ld\n", PTR_ERR(f));
        return;
    }
    kernel_write(f, buf, n, &f->f_pos);
    vfs_fsync(f, 0); /* panic 也不丢：不然会只剩一堆 \0 */
    filp_close(f, NULL);
}

static void ksu_fops_apply(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_fops_work, ksu_fops_apply);
static int ksu_fops_queued;

/* A/B 开关：0 = 只把 i_fop 指向模块里的副本（write 仍是原函数），1 = 换成我们的 hook */
#ifndef KSU_FOPS_WRAP
#define KSU_FOPS_WRAP 0
#endif

static void ksu_fops_do(void)
{
    int r1, r2;

    ksu_mark("do-start", (long)system_state);
    r1 = ksu_fops_patch("/sys/fs/selinux/context", &ksu_ctx_ops, &ksu_ctx_orig,
                        KSU_FOPS_WRAP ? (void *)my_write_context_auto : NULL);
    ksu_mark("do-ctx", r1);
    r2 = ksu_fops_patch("/sys/fs/selinux/access", &ksu_acc_ops, &ksu_acc_orig,
                        KSU_FOPS_WRAP ? (void *)my_write_access_auto : NULL);
    ksu_mark("do-acc", r2);
    ksu_fops_state = (r1 == 0 || r2 == 0) ? 1 : 0;
    ksu_mark("do-done", ksu_fops_state);
    pr_info("selinux_hide: fops do ctx=%d acc=%d state=%d\n", r1, r2, ksu_fops_state);
}

static void ksu_fops_apply(struct work_struct *w)
{
    int i;

    for (i = 0; i < 200 && system_state != SYSTEM_RUNNING; i++)
        msleep(50);
    ksu_mark("work-start", (long)system_state);
    ksu_fops_do();
}

/* 调度：按"要写进去的那个指针"判断是哪个文件 */
static int ksu_ro_write(void *dst, const void *src, size_t n)
{
    const void *want = *(const void **)src;

    /* 主路：排队到 workqueue 里做（不要在 init/持锁上下文里碰 VFS） */
    if (want == (const void *)my_write_context_auto || want == (const void *)my_write_access_auto ||
        want == (const void *)my_sel_open_handle_status) {
        if (!ksu_fops_queued) {
            ksu_fops_queued = 1;
            ksu_mark("queued", (long)system_state);
            if (system_state == SYSTEM_RUNNING) {
                /* ksud 上下文里就地做：能写 /data/local/tmp，也不用等 workqueue */
                ksu_mark("inline", (long)system_state);
                ksu_fops_do();
            } else {
                pr_info("selinux_hide: not running(%d), defer 8s\n", (int)system_state);
                schedule_delayed_work(&ksu_fops_work, 8 * HZ);
            }
        }
        return 0;
    }

    if (want == (const void *)orig_context_write) {
        ksu_fops_restore("/sys/fs/selinux/context", ksu_ctx_orig);
        ksu_ctx_orig = NULL;
        return 0;
    }
    if (want == (const void *)orig_access_write) {
        ksu_fops_restore("/sys/fs/selinux/access", ksu_acc_orig);
        ksu_acc_orig = NULL;
        return 0;
    }
    pr_info("selinux_hide: ro_write unknown want=0x%lx slot=0x%lx\n", (unsigned long)want, (unsigned long)dst);
    return ksu_ro_write_old(dst, src, n);
}

ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    /*
     * 关键（8.5 的教训）：stock 的 my_write_context() 内部是 memdup_user_nul(buf)，
     * 它要的是【用户指针】。8.5 先 copy_from_user 到内核缓冲再传进去 → memdup_user_nul
     * 从内核地址拷 → EFAULT → security_check_context() 失败 → zygote 里
     * selinux_android_setcontext() 失败 → 所有 App 起不来（SIGABRT）。
     * 所以这里直接把用户指针透传给 stock hook，不做任何拷贝。
     *
     * 另一个坑：fops 路线没有走 sel_handle_status_ops 的槽位替换，orig_context_write
     * 可能是 NULL，必须回落到 i_fop 副本里的原始 write。
     */
    if (likely(current_uid().val < 10000) || !backup_sepolicy || !ksu_ctx_orig || !ksu_ctx_orig->write)
        return (ksu_ctx_orig && ksu_ctx_orig->write)
                   ? ksu_ctx_orig->write(file, ubuf, size, ppos)
                   : (orig_context_write ? ksu_call_orig(orig_context_write, file, ubuf, size, ppos) : -EINVAL);

    return my_write_context(file, (char __user *)ubuf, size);
}

ssize_t my_write_access_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    if (likely(current_uid().val < 10000) || !backup_sepolicy || !ksu_acc_orig || !ksu_acc_orig->write)
        return (ksu_acc_orig && ksu_acc_orig->write)
                   ? ksu_acc_orig->write(file, ubuf, size, ppos)
                   : (orig_access_write ? ksu_call_orig(orig_access_write, file, ubuf, size, ppos) : -EINVAL);

    return my_write_access(file, (char __user *)ubuf, size);
}
