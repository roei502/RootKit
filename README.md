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
