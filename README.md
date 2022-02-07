# RootKit

###### Environment:
Linux ubuntu-amd64 5.13.0-28-generic #31~20.04.1-Ubuntu SMP Wed Jan 19 14:08:10 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux




#### Q1:	
<img src="https://github.com/roei502/RootKit/blob/main/1/img/q1.png" width="450" height="200">


#### Q2:	
Lets create the file we want to hide:
echo 1 > /tmp/hideme
to see how the ls command works, lets check all the systemcalls that the ls command is doing to get its output
strace -s 4096 -o /home/john/git/RootKit/2/output/strace_ls_command.out ls -la /tmp

we can see there that the opennat syscall is called with our directory, and returning new fd(=3)
then, getdents64 is called with out fd, to get all the directory entries.
<img src="https://github.com/roei502/RootKit/blob/main/2/img/q2_strace.png" width="1000" height="300">

this is the function we want to hook.
