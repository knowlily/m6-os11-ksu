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

/* ===== status 页：把 sequence / policyload 拨回出厂值 =====
 * /sys/fs/selinux/status 是 mmap 出去的 5×u32：version/sequence/enforcing/policyload/deny_unknown。
 * 第三方策略一加载，sequence++ 且 policyload++，检测器一眼就能看出「策略被换过」。
 * 这个页是 alloc_page 出来的堆页（可写），直接把这两个字段拨回出厂值即可，不用 hook。
 *
 * 注意 6.1 的签名是 selinux_kernel_status_page(struct selinux_state *state)，
 * 不是无参 —— 拿 selinux_state 的地址传进去，别用 0 参函数指针去调（会拿垃圾当指针）。
 */
typedef struct page *(*ksu_status_page_fn)(void *state);

static int ksu_status_scrub(void)
{
    ksu_status_page_fn fn = (ksu_status_page_fn)find_kernel_symbol_exact("selinux_kernel_status_page");
    void *state = (void *)find_kernel_symbol_exact("selinux_state");
    struct page *pg;
    u32 *sp;

    if (!fn) {
        pr_err("selinux_hide: no selinux_kernel_status_page\n");
        return -ENOSYS;
    }
    if (!state) {
        pr_err("selinux_hide: no selinux_state\n");
        return -ENOSYS;
    }
    pg = fn(state);
    if (!pg) {
        pr_err("selinux_hide: status page null\n");
        return -ENOENT;
    }
    sp = (u32 *)page_address(pg);
    if (!sp || sp[0] != 1) {
        pr_err("selinux_hide: bad status page ver=%u\n", sp ? sp[0] : 0xffffffff);
        return -EINVAL;
    }
    /* 把「改之前」的值落盘：万一检测器期望的不是 0/0，看这行就知道该拨到哪 */
    ksu_mark("status-before", (long)(((sp[1] & 0xffff) << 16) | (sp[3] & 0xffff)));
    pr_info("selinux_hide: status seq=%u pl=%u enf=%u dn=%u\n", sp[1], sp[3], sp[2], sp[4]);
    /*
     * < 6.10 的内核上，出厂手机的 status 页是 sequence=0 / policyload=0
     * （第三方策略一注入就变成 1/1，检测器拿这两个数当「策略被换过」的铁证）。
     * enforcing 只在建页那一刻取过值，若建页时正好在 permissive 窗口里就会永久留 0，
     * 所以这里一并拨成 1 —— 这条链跑完本来就是 Enforcing。
     */
    sp[1] = 0;
    sp[2] = 1;
    sp[3] = 0;
    ksu_mark("status-after", (long)(((sp[1] & 0xffff) << 16) | (sp[3] & 0xffff)));
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
    /* 策略一旦被注入，status 页的 sequence/policyload 就是「被换过」的铁证，最后拨回去 */
    rs = ksu_status_scrub();
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

/* 返回 1 = 放行；0 = 里面出现了出厂策略里不存在的类型（判定为「该类型不存在」） */
static int ksu_ctx_allowed(const char *buf, size_t size)
{
    const char *p = buf, *end = buf + size;

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
        ok = ksu_ctx_allowed(kbuf, size);
        if (!ok)
            pr_info("selinux_hide: context deny uid=%d '%s'\n", current_uid().val, kbuf);
        kfree(kbuf);
        if (!ok)
            return -EINVAL;
    }
    return orig->write(file, ubuf, size, ppos);
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
        ok = ksu_ctx_allowed(kbuf, size);
        if (!ok)
            pr_info("selinux_hide: access deny uid=%d '%s'\n", current_uid().val, kbuf);
        kfree(kbuf);
        if (!ok)
            return -EINVAL;
    }
    return orig->write(file, ubuf, size, ppos);
}
