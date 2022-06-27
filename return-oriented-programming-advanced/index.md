---
linkTitle: Return Oriented Programming Advanced
type: docs
weight: 10
---

# Return Oriented Programming Advanced

## Table of Contents

* [Return Oriented Programming Advanced](#return-oriented-programming-advanced)
   * [Calling Conventions in the ROP Context](#calling-conventions-in-the-rop-context)
   * [ROP gadgets on x86_64](#rop-gadgets-on-x86_64)
   * [Libc leaks](#libc-leaks)
   * [Challenges](#challenges)
      * [01. Challenge - Using ROP to Leak and Call system](#01-challenge---using-rop-to-leak-and-call-system)
      * [02. Challenge - Handling Low Stack Space](#02-challenge---handling-low-stack-space)
      * [03. Challenge - Stack Pivoting](#03-challenge---stack-pivoting)
      * [04. Challenge - mprotect](#04-challenge---mprotect)
   * [Further Reading](#further-reading)


In this lab we are going to dive deeper into *Return Oriented Programming* and setbacks that appear in modern exploitation. Topics covered:

  * ROP for syscalls and 64 bits
  * Dealing with ASLR in ROP
  * Dealing with low space in the overflown buffer
  * Combining ROP and shellcodes

As the basis of the lab we will use a program based on a classical CTF challenge called *ropasaurusrex* and gradually make exploitation harder.

## Calling Conventions in the ROP Context

As you know, the calling convention for 32 bits uses the stack. This means that setting up parameters is as easy as just writing them in the payload.

We can see how a function call is generated in this [Compiler Explorer example](https://gcc.godbolt.org/z/MPG5MhEnE).

 Syscalls are special, the arguments are passed using the registers and `int 0x80` or the equivalent `call DWORD PTR gs:0x10` is used such that more work is needed: `pop ?; ret` gadgets are needed to load the registers with the desired values.

In the assembly below you see a disassembly of the calling of a system call `read(0, 0x8048000, 0x100)`, with the system call in the `eax` register and the system call arguments in the other registers:

```asm
mov eax, 0x3
mov ebx, 0
mov ecx, 0x08048000
mov edx, 0x100
int 0x80
```

The calling convention for 64 bit processors (`x86_64`) is different and mainly uses registers instead of the stack, see this [Compiler Explorer example](https://gcc.godbolt.org/z/1Ys6M3Pdc).

Syscalls on 64 bits are conceptually the same as on 32 bits, but it uses different registers, different syscall codes and the `syscall` mnemonic is used for making a system call:

```asm
mov rax, 0
mov rdi, 0
mov rsi, 0x08048000
mov rdx, 0x100
syscall
```

## ROP gadgets on x86_64

On `x86_64` the ROP payloads will have to be built differently than on `x86` because of the different calling convention. Having the function arguments stored in registers means that you don't need to do stack cleanup anymore, but you will need gadgets with **specific registers** to pop the arguments into.

For example to do the `read(0, buf, size)` *libc call* to do this call your payload will need to look like:
```
pop rdi; ret
0
pop rsi, ret
buf_addr
pop rdx; ret
size
call read@plt
```

## Libc leaks

You might have already encountered in other tasks the need to leak values or addresses. Most of the time, if you want to get a shell, you won't have a convenient `system@plt` symbol present in your binary, and ASLR will most often be activated; so you will have to compute it relative to another libc symbol at runtime.

For this we will need to know what libc library the program is loading. For a local executable we can just run `ldd`:

```
$ ldd rop
    linux-vdso.so.1 (0x00007ffd0834b000)
    libc.so.6 => /usr/lib/libc.so.6 (0x00007fec18eb6000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fec190aa000)
```

For remote tasks you can might get an attached `libc.so`, or you can use the [Libc database](https://libc.blukat.me/) to find the correct libc based on some leaked offsets.


How to compute and use the `system` function address using pwntools:
```python
from pwn import *

libc = ELF("/usr/lib/libc.so.6") # from `ldd rop`
p = process('rop')

...
# read the leaked address of the write@got function from the program
write_leak = u64(p.recv(8))
# compute the starting address of the libc library
# setting libc.address to this value will offset all future symbol accesses
libc.address = write_leak - libc.symbols['write']

# use the address of system in the payload
payload = ... + p64(libc.symbols['system'])
```

## Challenges

**NOTE**: All tasks from this session are 64 bit binaries, so take that into consideration when you build the ROP chains.

### 01. Challenge - Using ROP to Leak and Call system

Use the `01-leak-call-system/src` executable file in order to spawn a shell.

You can now call the functions in the binary but `system` or any other appropriate function is missing and ASLR is enabled. How do you get past this? You need an information leak! To leak information we want to print it to standard output and process it.
We use calls to `printf`, `puts` or `write` for this. In our case we can use the `write` function call.

> If you have a string representation of a number you can unpack it using the `unpack`/`u64` function in pwntools. It is the reverse of the `pack`/`p64` function.

First, trigger the information leak by calling the `write` function and leaking an address from libc.

> You can use the GOT table storing libc addresses.

You need to read the output from the above `write` call. Use `p.recv(8)` in the Python script to read the 8 bytes output of the `write` call in the ROP chain.

> Remember that you need gadgets to pop values into rdi, rsi, rdx for the `write` call.

Find the address of the `system` call.

> Remember the libc leaks section above

Call `system`.

> You can't write the `system` address in the ROP chain as it is different each time and the ROP chain is statically defined. You can use the GOT table again. Write an entry in the GOT table with the newly found address and call the function for that entry. It will evolve into a call to `system`.
>
> To write an entry in the GOT table use the `read` call in the ROP chain. You will feed to `read` the computed address below.
>
> For the actual parameter use the `"sh"` string already present in the vulnerable binary. Use searchmem in GDB to find the `"sh"` string in the executable.

### 02. Challenge - Handling Low Stack Space

The previous binary had the luxury of plenty of stack space to be overflown. It is often the case that we don't have enough space for a long ROP chain. Let's handle that.

For the current task, switch to the `02-low-stack-space/src` sub-folder. The extra constraint here is that huge ropchains are no longer an option.

Find out how much space you have in the overflow and assess the situation.

> Use `gdb` and the cyclic pattern to get the information required.

Now follow the steps below.

First trigger the info leak as before.

> Use `write` and leak the address of a GOT value. Use this to compute the address of the `system` call.

You can only construct a partial ropchain. A longer one won't fit. So after calling `write`, call `main` again.

> Note that using `sendline` means sending out a newline character (`'\n'`) at the end of the message. If you want to strictly send out a message without a newline, use `send`.
>
> Find the address of `main` by looking at the argument for the `__libc_start_main` function. Check the disassembling of the program and see what is the parameter passed to the `__libc_start_main call`.
>
> After calling `main` again you will get back to the initial situation where you can exploit the buffer overflow.

Insert `"sh"` string.

> This time you don't have the `"sh"` string in the binary, but you can find it in **the libc binary itself** so you can compute it the same way you compute the `system` address. In pwntools:
> ```python
>
> sh = next(libc.search(b"/bin/sh\x00"))
> ```

Call `system`.

### 03. Challenge - Stack Pivoting

Let's assume that `main` function had additional constraints that made it impossible to repeat the overflow. How can we still solve it? The method is called stack pivoting. In short, this means making the stack pointer refer another (writable) memory area that has enough space, a memory area that we will populate with the actual ROP chain.

> Read more about stack pivoting [here](http://neilscomputerblog.blogspot.ro/2012/06/stack-pivoting.html).

Tour goal is to fill the actual ROP chain to a large enough memory area. We need a two stage exploit:

  * In the first stage, prepare the memory area where to fill the second stage ROP chain; then fill the memory area with the second stage ROP chain.
  * In the second stage, create the actual ROP chain and feed it to the program and profit.

Follow the steps below.

Use pmap or vmmap in `pwndbg` to discover the writable data section of the process. Select an address in that section (**don't** use the start address). This is where you fill the 2nd stage data (the actual ROP chain).

> Who not use the start address? Because `pop` instructions (which decrease the `rsp`) will go outside the memory region.

Create a first stage payload that calls `read` to store the 2nd stage data to the newly found memory area. After that pivot the stack pointer to the memory area address.

> At a given address in the executable you have a call to `read` followed by a `leave; ret` gadget. This sequence of instructions allows you to read data and then pivot the stack.
>
> The leave instruction fills the stack pointer (`rsp`) with the address of the frame pointer (`rbp`). It's equivalent to:
> ```asm
> mov rsp, rbp
> pop rbp
> ```
Write the actual ROP chain as a second stage payload like when we didn't have space constraints. The 2nd stage will be stored to the memory area and the stack pointer will point to that.

> **Important!** Be careful when and where the stack pivoting takes place. After the `mov rsp, rbp` part of the `leave` instruction happens your stack will be pivoted, so the following `pop rbp` will happen **on the new stack**. Take this offset into account when building the payload.

### 04. Challenge - mprotect

Combine everything you've learned until now and develop a complex payload to call `mprotect` to change the permissions on a memory region to read+write+execute and then instert a *shellcode* to call `system("/bin/sh")`.


## Further Reading

  * https://syscalls.kernelgrok.com/
  * http://articles.manugarg.com/systemcallinlinux2_6.html
  * https://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries#the-procedure-linkage-table-plt
  * https://github.com/Gallopsled/pwntools-tutorial/tree/master/walkthrough

