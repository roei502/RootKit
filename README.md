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
   
```bash
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
   
```bash
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
   
```bash
...
struct module *mod;
mod = find_module(name);
...
```
   
the find_module going over the list and search by name, if we are not on the list he cant find us. 
   
but the module is not in the list but still running, so we can create our triggers to hide and unhide the module, so we have full controll over it if we know the triggers.
   
<img src="https://github.com/roei502/RootKit/blob/main/5/img/q5.png">
