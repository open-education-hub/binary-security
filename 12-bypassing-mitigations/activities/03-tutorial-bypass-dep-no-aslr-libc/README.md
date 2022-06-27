This exploit works with ASLR disabled. To disable ASLR (it's enabled by default on Linux) use:

```
setarch x86_64 -R /bin/bash
```

We find the non-randomized address of the `puts` function in the standard C library by using GDB:

```
$ gdb ./vuln
Reading symbols from ./vuln...done.
(gdb) start
Temporary breakpoint 1 at 0x40059e: file vuln.c, line 13.
Starting program: /home/razvan/projects/ctf/sss/sss-exploit-internal.git/sessions/12-bypassing-mitigations/activities/03-tutorial-bypass-dep-no-aslr-libc/vuln

Temporary breakpoint 1, main () at vuln.c:13
13              puts("Hello");
(gdb) p puts
$1 = {int (const char *)} 0x7ffff7a64a30 <_IO_puts>
```
