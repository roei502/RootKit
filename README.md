# RootKit

###### Environment:
Linux john-virtual-machine 5.4.0-99-generic #112~18.04.1-Ubuntu SMP Thu Feb 3 14:09:57 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux




#### Q1:	
<img src="https://github.com/roei502/RootKit/blob/main/1/img/q1.png" width="450" height="200">


#### Q2:	
Lets create the file we want to hide:
```bash
echo 1 > /home/john/git/RootKit/2/test/hideme
```
to understand how the ls command works, lets find out which systemcalls it invokes to get its output
```bash
strace -s 4096 -o /home/john/git/RootKit/2/output/strace_ls_command.out ls -la /home/john/git/RootKit/2/test/
```
we can see there that the openat syscall is called with our directory, and is returning a new fd(=3)

then, getdents is called with our fd to get all the directory's entries.

<img src="https://github.com/roei502/RootKit/blob/main/2/img/q2_strace.png" width="800" height="250">

this is the function we want to hook.

the highlevel of the code is:
1. write the hook_getdents function.

   a. call the original getdents function that return all the linux_dirent structs of the directory.
   
   b. go over all the structs and search for the "magic prefix". if found, make this struct disappear.
   
   c. return the new pointer to the modified list.
   
2. find the syscall table.
3. change the pointer of the real getdents to our function.

     a. in the default sceneria we cant do it because the syscall table is ro.
  
    we need to be able to write to ro pages.
    
     https://infosecwriteups.com/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c?gif=true
     
     see section "Hooking a syscall".
     
     change the permissions.
     
  b. change the pointer of getdents in the syscall table to our function.
  
  c. restore to the original permissions.
  
finally:

<img src="https://github.com/roei502/RootKit/blob/main/2/img/q2_answer.png">

as you can see, i also hooked the getdents64. its the same way as hooking the getdents.

#### Q3:

using strace and the man page we can see that the information about ipv4 sockets are from /proc/net/tcp

lets understand what is this file and what functionallity is behind this file.

the line that creates the file:

```c
static int __net_init tcp4_proc_init_net(struct net *net)
{
	if (!proc_create_net_data("tcp", 0444, net->proc_net, &tcp4_seq_ops,
			sizeof(struct tcp_iter_state), &tcp4_seq_afinfo))
		return -ENOMEM;
	return 0;
}
```

lets see that ops are called with this file

```c
static const struct seq_operations tcp4_seq_ops = {
	.show		= tcp4_seq_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
}
```

and if we will see the function tcp4_seq_show

```c
static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	struct sock *sk = v;
	
	seq_setwidth(seq, TMPSZ - 1);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	...
```
this heades is the same header when reading /proc/net/tcp, we are in the right place.

this is the function we want to hook. we will check if the struct of the sock (sk) has one of our parameters, if it does return and dont output to the file.

we need to figure out how to make the hook.

the first thing i did is trying to replace the function called when reading /proc/net/tcp

the easiest thing to do is to remove the "tcp" entry using the function remove_proc_entry. now the there is no such file /proc/net/tcp

then just register our functionallity using proc_create_net_data just like the kernel does when init whith our costumed structs.

this solition works but its not the best, the changes of the files are not atomic so there will be time when /proc/net/tcp will not exists.

after searching online for kernel hooking i found 
https://www.kernel.org/doc/html/v4.17/trace/ftrace-uses.html

we can register a callback function that is called when someone trying to call tcp4_seq_show, and then we can chage the function he is going to call from the original tcp4_seq_show to our hooked_tcp4_seq_show. and then we will be completely hidden.

<img src="https://github.com/roei502/RootKit/blob/main/3/img/q3.png">

#### Q4:	

first thing as the others, lets strace the ps command to see how it works

```bash
strace -s 4096 -o /home/john/git/RootKit/4/output/strace_ps.out ps -fade
```

we can see that the ps command using the getdents syscall to get all the dirs in /proc

then reading the /proc/<pid>/stat and /proc/<pid>/status to get the information

if we can just hide our directory from the getdents, the ps command will not output our process.

its the same funcionallity as q2.

the process works the same becuase we did not touch him.
   
<img src="https://github.com/roei502/RootKit/blob/main/4/img/q4.png">

#### Q5:	
   
how do we get all the moudles when we call lsmod? lets strace
   
```bash
strace -s 4096 -o /home/john/git/RootKit/5/output/strace_lsmod.out lsmod
```
   
the lsmod just printing the /proc/modules file.

the same is written in man lsmod
   
what function does the kernel calls when tring to read /proc/modules?

lets search where is the /proc/modules is created, and then we will search for the fucntion itself.
   
```c
Searching 65692 files for "proc_create.*\("modules"" (regex)

/home/john/git/linux/kernel/module.c:
 4401  static int __init proc_modules_init(void)
 4402  {
 4403: 	proc_create("modules", 0, NULL, &proc_modules_operations);
 4404  	return 0;
 4405  }
```

we will find the function in module.c:
   
```bash
static int m_show(struct seq_file *m, void *p) {.....}
```
   
we could hook this function just as we did in q3.
   
but there is a better soultion. if we will look in the module.h file, we can see that all the modules are stored in a list.
   
```c
struct module {
	enum module_state state;
	/* Member of list of modules */
	struct list_head list;
	/* Unique handle for this module */
	char name[MODULE_NAME_LEN];
   .....}
```
   
we can remove our module from this list, then when lsmod / other function is called, the kernel will go over that list, and we will not be there.
   
but there is a problem with that. if we will look at the function that remove modules (found syscall from stracing rmmod), we will see:
   
```c
...
struct module *mod;
mod = find_module(name);
...
```
   
the find_module going over the list and search by name, if we are not on the list he cant find us. 
   
but the module is not in the list but still running, so we can create our triggers to hide and unhide the module, so we have full controll over it if we know the triggers.
   
<img src="https://github.com/roei502/RootKit/blob/main/5/img/q5.png">
