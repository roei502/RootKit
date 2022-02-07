#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");


static int __init print_hello(void) {
 printk(KERN_INFO "Hello World\n");
 return 0;
}

static void __exit exit_func(void) {
 printk(KERN_INFO "Goodbye, World!\n");
}

module_init(print_hello);
module_exit(exit_func);