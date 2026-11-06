#include <asm/fixmap.h>
#include <asm-generic/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/mm_types.h>

static void ksu_mark(const char *what, long v); /* 下面到处用，先声明 */

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
    if (cur == copy) { /* 已经装过（重复 enable），别再把自己的副本当 orig */
        filp_close(f, NULL);
        return 0;
    }
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
    ksu_mark("restore", 0);
    pr_info("selinux_hide: fops %s restored to 0x%lx\n", path, (unsigned long)orig);
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

/* hook 打点：前 24 次把「进来的原始串 + 判定结果」写进 hide_mark。
 * 真机没有 dmesg（klogctl 对 shell/root 都拒绝），这是唯一能看见 hook 内部的路。 */
static int ksu_hook_logs;

static void ksu_hook_log(const char *kind, const char *buf, size_t size, int ok)
{
    if (ksu_hook_logs >= 24)
        return;
    ksu_hook_logs++;
    ksu_mark(kind, (long)size);
    if (buf)
        ksu_mark(buf, (long)ok);
}

/* ===== 真相源：ROM 出厂策略 =====
 * 判定「这个 SELinux 类型该不该存在」不再靠名单，而是拿 ROM 出厂的那份二进制策略当标准：
 *   · 出厂策略里有的名字（untrusted_app_32 / app_zygote / vendor_* / su …）→ 原样放行
 *   · 出厂策略里没有的名字（ksu / magisk_file / lsposed_file / 以后任何运行时注入的类型）
 *     → 一律 -EINVAL，和「这台机器上根本没这个类型」的回答完全一致
 * 好处：零维护、不误杀（白名单漏一个域就崩进程的坑彻底消失），且回答与出厂状态逐字节一致。
 * 代价：一次 2 MB 左右的 vmalloc + 每次查询扫一遍（几十次查询量级，毫秒级）。
 *
 * 拿不到出厂策略时（文件缺失/被拒），退回旧的白名单，保证不会「什么都不藏」。
 */
#define KSU_POL_MAX (32u << 20) /* 出厂策略实测 2.1 MB，上限纯保险 */

static char *ksu_stock_pol;
static size_t ksu_stock_pol_len;
static int ksu_stock_pol_state; /* 0=还没试 1=已载入 -1=拿不到 */

static const char *const ksu_stock_pol_paths[] = {
    "/vendor/etc/selinux/precompiled_sepolicy",
    "/system_ext/etc/selinux/precompiled_sepolicy",
    "/product/etc/selinux/precompiled_sepolicy",
    "/system/etc/selinux/precompiled_sepolicy",
};

static ssize_t ksu_read_file_all(struct file *f, char *buf, size_t len)
{
    loff_t pos = 0;
    size_t total = 0;

    while (total < len) {
        ssize_t n = kernel_read(f, buf + total, len - total, &pos);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    return (ssize_t)total;
}

static int ksu_stock_policy_load(void)
{
    size_t i;

    if (ksu_stock_pol_state)
        return ksu_stock_pol_state > 0 ? 0 : -ENOENT;

    for (i = 0; i < ARRAY_SIZE(ksu_stock_pol_paths); i++) {
        struct file *f = filp_open(ksu_stock_pol_paths[i], O_RDONLY, 0);
        loff_t size;
        char *buf;
        ssize_t n;

        if (IS_ERR(f)) {
            pr_info("selinux_hide: stock %s err=%ld\n", ksu_stock_pol_paths[i], PTR_ERR(f));
            continue;
        }
        size = i_size_read(file_inode(f));
        if (size < 65536 || size > (loff_t)KSU_POL_MAX) {
            pr_info("selinux_hide: stock %s size=%lld skip\n", ksu_stock_pol_paths[i], (long long)size);
            filp_close(f, NULL);
            continue;
        }
        buf = vmalloc((size_t)size);
        if (!buf) {
            pr_err("selinux_hide: stock vmalloc(%lld) failed\n", (long long)size);
            filp_close(f, NULL);
            break;
        }
        n = ksu_read_file_all(f, buf, (size_t)size);
        filp_close(f, NULL);
        if (n != (ssize_t)size) {
            pr_err("selinux_hide: stock %s short read %zd/%lld\n", ksu_stock_pol_paths[i], n, (long long)size);
            vfree(buf);
            continue;
        }
        ksu_stock_pol = buf;
        ksu_stock_pol_len = (size_t)size;
        ksu_stock_pol_state = 1;
        ksu_mark("pol-ok", (long)size);
        pr_info("selinux_hide: stock policy %s loaded %lld bytes\n", ksu_stock_pol_paths[i],
                (long long)size);
        return 0;
    }

    ksu_stock_pol_state = -1;
    ksu_mark("pol-fail", 0);
    return -ENOENT;
}

/* 类型名允许的字符集（策略文件里名字是裸 ASCII 连排的，靠前后字符判边界） */
static int ksu_pol_name_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
           c == '.';
}

/* 返回 1=出厂策略里有这个名字，0=没有，-1=没有出厂策略可查 */
static int ksu_stock_has_name(const char *t, size_t n)
{
    size_t i;

    if (ksu_stock_pol_state <= 0 || !ksu_stock_pol || !n || n > 128)
        return -1;

    for (i = 0; i + n <= ksu_stock_pol_len; i++) {
        if (ksu_stock_pol[i] != t[0])
            continue;
        if (memcmp(ksu_stock_pol + i, t, n))
            continue;
        if (i > 0 && ksu_pol_name_char((unsigned char)ksu_stock_pol[i - 1]))
            continue;
        if (i + n < ksu_stock_pol_len && ksu_pol_name_char((unsigned char)ksu_stock_pol[i + n]))
            continue;
        return 1;
    }
    return 0;
}

/* ===== status 页：给 app 一个「出厂状态」的假页 =====
 * /sys/fs/selinux/status 是 5×u32：version/sequence/enforcing/policyload/deny_unknown。
 * 第三方策略一注入，内核会 sequence++ 且 policyload++，检测器拿这两个数当「策略被换过」的铁证。
 *
 * 6.1 的 stock 实现（security/selinux/selinuxfs.c）：
 *   sel_open_handle_status()  -> filp->private_data = selinux_kernel_status_page(fsi->state)
 *   sel_read_handle_status()  -> BUG_ON(!status); simple_read_from_buffer(page_address(private_data))
 *   sel_mmap_handle_status()  -> BUG_ON(!status); remap_pfn_range(page_to_pfn(private_data))
 * 也就是说 read/mmap 都只看 private_data。所以最省事也最安全的做法：
 * 自己 alloc_page 一张填好出厂值的页，把 status 的 i_fop 换成「open 塞假页、read/mmap 保持 stock」。
 *
 * 不走「直接改真页」那条路：那需要调 selinux_kernel_status_page(&selinux_state)，
 * 而 selinux_state 的地址要靠 kallsyms 解析 —— 9.1 实测在这里直接把机器送重启了
 * （hide_mark 停在 do-pol，do-status 没写出来）。假页方案不依赖任何内核内部符号。
 */
static struct file_operations ksu_status_ops;
static const struct file_operations *ksu_status_orig;
static struct page *ksu_fake_status;

static int ksu_status_open(struct inode *inode, struct file *filp)
{
    /* 系统域看真页；app uid 看假页（出厂值：seq=0 policyload=0 enforcing=1 deny_unknown=1） */
    if (likely(current_uid().val < 10000) || !ksu_fake_status) {
        if (ksu_status_orig && ksu_status_orig->open)
            return ksu_status_orig->open(inode, filp);
        return 0;
    }
    filp->private_data = ksu_fake_status;
    return 0;
}

static int ksu_status_fake(void)
{
    struct file *f = NULL;
    struct inode *in;
    u32 *sp;

    if (!ksu_fake_status) {
        ksu_fake_status = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!ksu_fake_status) {
            pr_err("selinux_hide: fake status alloc failed\n");
            return -ENOMEM;
        }
        sp = (u32 *)page_address(ksu_fake_status);
        sp[0] = 1; /* version */
        sp[1] = 0; /* sequence：出厂值 */
        sp[2] = 1; /* enforcing */
        sp[3] = 0; /* policyload：没有加载过第三方策略 */
        sp[4] = 1; /* deny_unknown */
        ksu_mark("status-fake", (long)(((sp[1] & 0xffff) << 16) | (sp[3] & 0xffff)));
    }

    in = ksu_path_inode("/sys/fs/selinux/status", &f);
    if (!in) {
        pr_err("selinux_hide: no status inode\n");
        return -ENOENT;
    }
    if (in->i_fop == &ksu_status_ops) { /* 已经装过 */
        filp_close(f, NULL);
        return 0;
    }
    ksu_status_orig = in->i_fop;
    memcpy(&ksu_status_ops, in->i_fop, sizeof(ksu_status_ops));
    ksu_status_ops.open = ksu_status_open;
    WRITE_ONCE(in->i_fop, &ksu_status_ops);
    filp_close(f, NULL);
    pr_info("selinux_hide: status fops orig=0x%lx ours=0x%lx page=0x%lx\n", (unsigned long)ksu_status_orig,
            (unsigned long)&ksu_status_ops, (unsigned long)ksu_fake_status);
    ksu_mark("status-installed", 0);
    return 0;
}

/* 急救开关：模块每次都是临时加载的，但 hook 一旦装坏就可能起不来。
 * /data/local/tmp/.w9/hide_off 存在就整条隐藏链跳过，恢复出问题的机器不用刷机。 */
static int ksu_hide_killed(void)
{
    struct file *f = filp_open("/data/local/tmp/.w9/hide_off", O_RDONLY, 0);

    if (IS_ERR(f))
        return 0;
    filp_close(f, NULL);
    return 1;
}

static void ksu_fops_apply(struct work_struct *w);
static DECLARE_DELAYED_WORK(ksu_fops_work, ksu_fops_apply);
static int ksu_fops_queued;

/* ===== 策略文件读取拦截（.read / .mmap）=====
 * 有些检测器不走 security_check_context()，而是直接把 /sys/fs/selinux/policy
 * 那份二进制策略读下来 grep 类型名。这个 hook 让 app uid 根本读不到策略。
 * 同一套 i_fop 替换（8.7 已验证只换指针是安全的）。
 */
static __maybe_unused struct file_operations ksu_pol_ops;
static const struct file_operations *ksu_pol_orig;

ssize_t my_pol_read(struct file *f, char __user *ubuf, size_t n, loff_t *ppos)
{
    loff_t pos;

    if (current_uid().val < 10000)
        return (ksu_pol_orig && ksu_pol_orig->read) ? ksu_pol_orig->read(f, ubuf, n, ppos) : -EINVAL;

    /* app uid 读到的是「出厂策略」本身：内容天然不含 ksu/magisk/lsposed 这些注入类型，
     * 而且是一份语法完整、能被 libsepol 正常解析的策略 —— 比返回 EOF 更接近真机。 */
    if (ksu_stock_pol_state <= 0 || !ksu_stock_pol) {
        pr_info("selinux_hide: policy read -> EOF (no stock) uid=%d\n", current_uid().val);
        return 0;
    }
    pos = *ppos;
    if (pos < 0 || pos >= (loff_t)ksu_stock_pol_len)
        return 0;
    if ((loff_t)n > (loff_t)ksu_stock_pol_len - pos)
        n = (size_t)((loff_t)ksu_stock_pol_len - pos);
    if (copy_to_user(ubuf, ksu_stock_pol + pos, n))
        return -EFAULT;
    *ppos = pos + (loff_t)n;
    return (ssize_t)n;
}

int my_pol_mmap(struct file *f, struct vm_area_struct *vma)
{
    if (current_uid().val >= 10000) {
        pr_info("selinux_hide: block policy mmap uid=%d\n", current_uid().val);
        return -EACCES;
    }
    return (ksu_pol_orig && ksu_pol_orig->mmap) ? ksu_pol_orig->mmap(f, vma) : -EINVAL;
}

static int ksu_fops_patch_policy(void)
{
    struct file *f = NULL;
    struct inode *in = ksu_path_inode("/sys/fs/selinux/policy", &f);
    const struct file_operations *cur;
    int ret = 0;

    if (!in)
        return -ENOENT;
    cur = in->i_fop;
    ksu_pol_orig = cur;
    memcpy(&ksu_pol_ops, cur, sizeof(ksu_pol_ops));
    ksu_pol_ops.read = my_pol_read;
    ksu_pol_ops.mmap = my_pol_mmap;
    WRITE_ONCE(in->i_fop, &ksu_pol_ops);
    filp_close(f, NULL);
    pr_info("selinux_hide: policy fops orig=0x%lx ours=0x%lx\n", (unsigned long)cur,
            (unsigned long)&ksu_pol_ops);
    return ret;
}

/* A/B 开关：0 = 只把 i_fop 指向模块里的副本（write 仍是原函数），1 = 换成我们的 hook */
#ifndef KSU_FOPS_WRAP
#define KSU_FOPS_WRAP 1
#endif

static void ksu_fops_do(void)
{
    int r1, r2, rp, rs = -1;

    ksu_mark("do-start", (long)system_state);
    if (ksu_hide_killed()) {
        ksu_mark("do-killed", 0);
        pr_info("selinux_hide: hide_off present, skip all hooks\n");
        return;
    }
    /* 真相源必须先到位：hook 一旦装上，判定就靠它 */
    rp = ksu_stock_policy_load();
    ksu_mark("do-stock", rp);
    r1 = ksu_fops_patch("/sys/fs/selinux/context", &ksu_ctx_ops, &ksu_ctx_orig,
                        KSU_FOPS_WRAP ? (void *)my_write_context_auto : NULL);
    ksu_mark("do-ctx", r1);
    r2 = ksu_fops_patch("/sys/fs/selinux/access", &ksu_acc_ops, &ksu_acc_orig,
                        KSU_FOPS_WRAP ? (void *)my_write_access_auto : NULL);
    ksu_mark("do-acc", r2);
    {
        int r3 = ksu_fops_patch_policy();
        ksu_mark("do-pol", r3);
        ksu_fops_state = (r1 == 0 || r2 == 0 || r3 == 0) ? 1 : 0;
    }
    /* 策略一旦被注入，status 的 sequence/policyload 就是「被换过」的铁证：给 app 换成出厂值的假页 */
    rs = ksu_status_fake();
    ksu_mark("do-status", rs);
    ksu_mark("do-done", ksu_fops_state);
    pr_info("selinux_hide: fops do ctx=%d acc=%d stock=%d status=%d state=%d\n", r1, r2, rp, rs,
            ksu_fops_state);
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
        ksu_mark("queued", (long)system_state);
        if (system_state == SYSTEM_RUNNING) {
            /* ksud 上下文里就地做：能写 /data/local/tmp，也不用等 workqueue */
            ksu_mark("inline", (long)system_state);
            ksu_fops_do();
        } else if (!ksu_fops_queued) {
            /* 只有「还没到 RUNNING」时才排队；重复 enable 不必再排 */
            ksu_fops_queued = 1;
            pr_info("selinux_hide: not running(%d), defer 8s\n", (int)system_state);
            schedule_delayed_work(&ksu_fops_work, 8 * HZ);
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

/*
 * 兜底白名单：只有「拿不到出厂策略」时才用（ksu_stock_pol_state < 0）。
 * 这条路天生脆弱 —— 漏一个域，那个进程的 selinux_android_setcontext() 就会
 * 拿到 -EINVAL 然后 SIGABRT（9.0 的 app_zygote 就是这么死的），所以它只当保险丝。
 */
static const char *const ksu_ok_types[] = {
    /* 普通 App 域 */
    "untrusted_app", "priv_app", "platform_app", "system_app", "isolated_app",
    "ephemeral_app", "shared_relro",
    /* 系统替 App 起的辅助域（漏一个就会让 selinux_android_setcontext 失败 → SIGABRT） */
    "app_zygote", "webview_zygote", "sdk_sandbox", "system_server",
    "media", "media_rw", "shell", "su",
};

static int ksu_type_allowed_whitelist(const char *t, size_t n)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ksu_ok_types); i++) {
        size_t m = strlen(ksu_ok_types[i]);
        if (n >= m && !memcmp(t, ksu_ok_types[i], m))
            return 1;
    }
    return 0;
}

/* 主判定：出厂策略说没有，就是没有 */
static int ksu_type_allowed(const char *t, size_t n)
{
    int hit = ksu_stock_has_name(t, n);

    if (hit >= 0)
        return hit;
    return ksu_type_allowed_whitelist(t, n);
}

/* 关键字兜底：这几个名字是「注入型」的典型，任何情况下都不该从 app 那里看得到。
 * 真相源应该已经挡住它们了，这里是第二道闸 —— 也用来分辨
 * 「hook 根本没被调用」和「真相源判错了」（真机没有 dmesg，只能靠行为差异取证）。 */
static const char *const ksu_extra_hidden[] = {"ksu", "magisk", "lsposed", "xposed", "zygisk", "adbroot"};

static int ksu_hit_extra_hidden(const char *buf, size_t size)
{
    size_t i, t;

    for (t = 0; t < ARRAY_SIZE(ksu_extra_hidden); t++) {
        size_t n = strlen(ksu_extra_hidden[t]);

        if (n > size)
            continue;
        for (i = 0; i + n <= size; i++)
            if (!memcmp(buf + i, ksu_extra_hidden[t], n))
                return 1;
    }
    return 0;
}

/* 返回 1 = 放行；0 = 里面出现了出厂策略里不存在的类型（判定为「该类型不存在」） */
static int ksu_ctx_allowed(const char *buf, size_t size)
{
    const char *p = buf, *end = buf + size;

    if (ksu_hit_extra_hidden(buf, size))
        return 0;

    while (p < end) {
        const char *sp = memchr(p, ' ', (size_t)(end - p));
        const char *tok_end = sp ? sp : end;
        const char *c1 = memchr(p, ':', (size_t)(tok_end - p));

        if (c1) {
            const char *c2 = memchr(c1 + 1, ':', (size_t)(tok_end - (c1 + 1)));
            if (c2) {
                const char *t = c2 + 1;
                size_t tn = 0;

                while (t + tn < tok_end && t[tn] != ':' && t[tn] != '\n' && t[tn] != '\t')
                    tn++;
                if (tn && !ksu_type_allowed(t, tn))
                    return 0;
            }
        }
        p = tok_end;
        while (p < end && (*p == ' ' || *p == '\n' || *p == '\t'))
            p++;
    }
    return 1;
}

/*
 * context / access 两个节点的写入口。
 *
 * 原则：**能放行就交给原函数**（i_fop 副本里那份 stock write，它自己会 copy_from_user），
 * 我们只做「这个名字出厂策略里有没有」的判定，不重写任何语义：
 *   · uid < 10000（zygote / system_server / init / servicemanager …）→ 一律原样放行，
 *     这些进程起不来整机就废了，不能有一点点额外风险；
 *   · 出厂策略里有的类型 → 原样放行，回答与未 root 的手机逐字节一致；
 *   · 出厂策略里没有的（ksu / magisk / lsposed / 以后任何注入的类型）→ -EINVAL。
 *
 * 之所以不再调 my_write_context()：它内部是 security_context_to_sid_with_policy(backup, …)，
 * 这里的 backup_sepolicy 在本机是 NULL/脏的，而且它把 buf 当【内核】指针用（8.6 就是这么 panic 的）。
 * 我们只要「不存在」这个回答，根本不需要它的策略副本。
 */
/* 哨兵：证明 context/access 的写路径到底有没有进我们的 hook。
 * 干净机对不存在的类型只会回 -EINVAL(22)；这里对 hermesprobe 回 -EPERM(1)，
 * 两者不可能撞车，所以探针看到 1 就等于「hook 真的被调用了」。 */
static int ksu_is_sentinel(const char *buf, size_t size)
{
    static const char tag[] = "hermesprobe";
    size_t n = sizeof(tag) - 1, i;

    if (n > size)
        return 0;
    for (i = 0; i + n <= size; i++)
        if (!memcmp(buf + i, tag, n))
            return 1;
    return 0;
}
ssize_t my_write_context_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    const struct file_operations *orig = ksu_ctx_orig;

    if (!orig || !orig->write)
        return orig_context_write ? ksu_call_orig(orig_context_write, file, ubuf, size, ppos) : -EINVAL;

    if (likely(current_uid().val < 10000))
        return orig->write(file, ubuf, size, ppos);

    {
        char *kbuf;
        int ok;

        if (size == 0 || size > 4096)
            return -EINVAL;
        kbuf = kmalloc(size + 1, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;
        if (copy_from_user(kbuf, ubuf, size)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kbuf[size] = 0;
        if (ksu_is_sentinel(kbuf, size)) { /* 哨兵：证明写路径可达 */
            kfree(kbuf);
            return -EPERM;
        }
        ok = ksu_ctx_allowed(kbuf, size);
        ksu_hook_log("HCTX", kbuf, size, ok);
        /* context 路径也要留痕：Li.c() 拿到 EINVAL 后会再用 a(type,type,0) 复核，
         * 只有两边都看到，才能确认某个类型是真的「不存在」。 */
        {
            static atomic_t ksu_ctx_log_left = ATOMIC_INIT(200);

            if (atomic_dec_if_positive(&ksu_ctx_log_left) >= 0)
                pr_info("selinux_hide: CTX uid=%d ok=%d '%s'\n",
                        current_uid().val, ok, kbuf);
        }
        if (!ok)
            pr_info("selinux_hide: context deny uid=%d '%s'\n", current_uid().val, kbuf);
        kfree(kbuf);
        if (!ok)
            return -EINVAL;
    }
    return orig->write(file, ubuf, size, ppos);
}

/*
 * ===== 访问判定的规则层拦截 =====
 * 关键：/sys/fs/selinux/access 的请求体只有「scon tcon tclass」三个字段，
 * 权限是位图编号，字符串里根本没有 execmem / search 这类词 —— 所以按关键字匹配永远不命中。
 * 只能按 (scon, tcon) 类型对拦。下面是 DirtySepolicy 在真机上实测仍返回 ALLOWED=true 的三条，
 * 加上 KSU/root 常见探针：
 *   system_server -> system_server  (process/execmem)
 *   zygote        -> system_file     (dir/search)
 *   *             -> apk_data_file   (file/execute)
 *   zygote        -> adb_data_file   (file/read)
 *   shell         -> su              (process/transition)
 * 干净机上这些都是 denied，所以 app 来问直接回 -EACCES（它的 b() 对非 EINVAL 错误也返回 false）。
 */
struct ksu_pair_sig {
    const char *scon;
    const char *tcon;
};

static const struct ksu_pair_sig ksu_pair_sigs[] = {
    /* 说明：探测器的 scon 经常是「它自己的上下文」（v7 = app_zygote 或 untrusted_app），
     * 按 scon 匹配会全部漏掉。所以除两条固定的以外，一律只按 tcon 匹配。
     * 这些 tcon 在正常 app 的查询里几乎不出现（只有检测器会问），副作用可接受。 */
    {"system_server", "system_server"},   /* process/execmem */
    {"shell", "su"},                      /* process/transition */
    {"", "rootfs"},                       /* filesystem/associate —— Magisk */
    {"", "tmpfs"},                        /* fifo_file/open    —— Magisk */
    {"", "adb_data_file"},                /* file/read, dir/search —— KernelSU / ZygiskNext */
    {"", "apk_data_file"},                /* file/execute      —— LSPosed */
    {"", "dex2oat_exec"},                 /* execute_no_trans  —— Xposed */
};static int ksu_has_sub(const char *buf, size_t size, const char *needle)
{
    size_t n = strlen(needle), i;

    if (n > size)
        return 0;
    for (i = 0; i + n <= size; i++)
        if (!memcmp(buf + i, needle, n))
            return 1;
    return 0;
}
/* 把 stock 写回的 allowed 位图清零：对方拿到的是一条合法响应，只是权限全判否，
 * 形状和干净机一致（干净机上这些类型对本来就不允许）。
 * file->private_data 是 simple_transaction_get() 分配的
 *   struct simple_transaction_argresp { ssize_t size; char data[]; };
 * 64 位上 data 从 +8 开始，内容是 "%x %x %x %x %x %x\n"，第一个词就是 allowed。 */
static void ksu_zero_allowed(struct file *file, ssize_t rv)
{
    char *ar = (char *)file->private_data;
    char *d;
    ssize_t i;

    if (!ar || rv <= 9)
        return;
    d = ar + sizeof(ssize_t);
    for (i = 0; i < rv - (ssize_t)sizeof(ssize_t) && d[i] != ' ' && d[i] != '\n'; i++)
        d[i] = '0';
}
static int ksu_pair_denied(const char *buf, size_t size)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ksu_pair_sigs); i++) {
        const char *scon = ksu_pair_sigs[i].scon;
        const char *tcon = ksu_pair_sigs[i].tcon;

        if (scon[0] && !ksu_has_sub(buf, size, scon))
            continue;
        if (tcon[0] && !ksu_has_sub(buf, size, tcon))
            continue;
        return 1;
    }
    return 0;
}
/* 对账日志：把「问了什么 -> 最终返回什么」成对打出来。
 * access 的应答体是 simple_transaction_argresp：ssize_t size + char data[]，
 * data 第一段就是 allowed 位图（十六进制），清零后应当全 0。 */
static atomic_t ksu_res_log_left = ATOMIC_INIT(300);
static void ksu_log_res(const char *q, struct file *file, ssize_t rv)
{
    char first[16];
    const char *d;
    int i;

    if (rv <= 0 || !file->private_data) {
        pr_info("selinux_hide: RES rv=%zd q='%s' a='<none>'\n", rv, q);
        return;
    }
    d = (const char *)file->private_data + sizeof(ssize_t);
    for (i = 0; i < (int)sizeof(first) - 1 && i < rv; i++) {
        char c = d[i];

        if (c == ' ' || c == '\n' || c == '\0')
            break;
        first[i] = c;
    }
    first[i] = 0;
    pr_info("selinux_hide: RES rv=%zd q='%s' a='%s'\n", rv, q, first);
}
ssize_t my_write_access_auto(struct file *file, const char __user *ubuf, size_t size, loff_t *ppos)
{
    const struct file_operations *orig = ksu_acc_orig;

    if (!orig || !orig->write)
        return orig_access_write ? ksu_call_orig(orig_access_write, file, ubuf, size, ppos) : -EINVAL;

    if (likely(current_uid().val < 10000))
        return orig->write(file, ubuf, size, ppos);

    {
        char *kbuf;
        int ok;

        if (size == 0 || size > 4096)
            return -EINVAL;
        kbuf = kmalloc(size + 1, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;
        if (copy_from_user(kbuf, ubuf, size)) {
            kfree(kbuf);
            return -EFAULT;
        }
        kbuf[size] = 0;
        if (ksu_is_sentinel(kbuf, size)) {
            kfree(kbuf);
            return -EPERM;
        }
        ok = ksu_ctx_allowed(kbuf, size);
        ksu_hook_log("HACC", kbuf, size, ok);
        /* 放行也要留痕：只记 deny 的话，漏掉的那条永远看不见（dmesg -> klog.txt 可读）。 */
        {
            static atomic_t ksu_acc_log_left = ATOMIC_INIT(200);

            if (atomic_dec_if_positive(&ksu_acc_log_left) >= 0)
                pr_info("selinux_hide: ACC uid=%d ok=%d '%s'\n",
                        current_uid().val, ok, kbuf);
        }
        if (ok && ksu_pair_denied(kbuf, size)) { /* 规则层：照常算，但把 allowed 位图清零 */
            ssize_t rv2;

            pr_info("selinux_hide: pair deny uid=%d\n", current_uid().val);
            rv2 = orig->write(file, ubuf, size, ppos);
            if (rv2 > 0) {
                ksu_zero_allowed(file, rv2);
                if (atomic_dec_if_positive(&ksu_res_log_left) >= 0)
                    ksu_log_res(kbuf, file, rv2);
                kfree(kbuf);
                return rv2;
            }
            kfree(kbuf);
            return -EINVAL; /* 兜底：EINVAL 对方当「不存在」，同样静默 */
        }
        if (!ok) {
            pr_info("selinux_hide: access deny uid=%d '%s'\n", current_uid().val, kbuf);
            kfree(kbuf);
            return -EINVAL;
        }
        {
            ssize_t rv3 = orig->write(file, ubuf, size, ppos);

            if (rv3 > 0 && atomic_dec_if_positive(&ksu_res_log_left) >= 0)
                ksu_log_res(kbuf, file, rv3);
            kfree(kbuf);
            return rv3;
        }
    }
}
