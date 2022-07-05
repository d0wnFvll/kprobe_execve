#define pr_fmt(fmt) "%s: " fmt, __func__

#if LINUX_VERSION_CODE < LINUX_VERSION(5, 9, 0)
#error "Kernel versions less then 5.9.0 not supported"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include "argv.h"

#define MAX_SYMBOL_LEN  64
static char symbol[MAX_SYMBOL_LEN] = "bprm_execve";

static struct kprobe kp = {
    .symbol_name = symbol,
};

static int __kprobes kprobe_pre_bprm(struct kprobe *p, struct pt_regs *regs) {
#ifdef CONFIG_X86
    pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
        p->symbol_name, p->addr, regs->ip, regs->flags);
#elif /* !CONFIG_X86 */
#error "Only x86 supported"
#endif /* CONFIG_X86 */
    return 0;
}

static void __kprobes kprobe_post_bprm(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags) {
#ifdef CONFIG_X86
    char const __user *filename;
    char *argv;
    struct linux_binprm *bprm;

    argv = kzalloc(PAGE_SIZE, GFP_NOFS);
    bprm = (struct linux_binprm *)regs->di;
    filename = bprm->filename;

    if(argv_dump_page(bprm, (unsigned long)bprm->p, argv)) {
        argv = argv_print_bprm(bprm, argv);
        if(argv) {
            pr_info("<%s> p->addr = 0x%p, flags = 0x%lx, file = %s, %s\n",
                p->symbol_name, p->addr, regs->flags, filename, argv);

            kfree(argv);
        }
    }
#elif /* !CONFIG_X86 */
#error "Only x86 supported"
#endif /* CONFIG_X86 */
    
}

static int __init kprobe_init(void) {
    int ret;
    kp.pre_handler = kprobe_pre_bprm;
    kp.post_handler = kprobe_post_bprm;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);
    pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");

