---
linkTitle: Shellcodes Advanced
type: docs
weight: 10
---

<details open>
    <summary>Table of contents</summary>
    
   * [Introduction](#introduction)
   * [Tutorials](#tutorials)
      * [01. Tutorial: preventing stack operations from overwriting the shellcode](#01-tutorial-preventing-stack-operations-from-overwriting-the-shellcode)
      * [02. Tutorial: NOP sleds](#02-tutorial-nop-sleds)
      * [03. Tutorial: null-free shellcodes](#03-tutorial-null-free-shellcodes)
      * [04. Tutorial: shellcodes in pwntools](#04-tutorial-shellcodes-in-pwntools)
      * [05. Tutorial: alphanumeric shellcode](#05-tutorial-alphanumeric-shellcode)
   * [Challenges](#challenges)
      * [06. Challenge: NOP sled redo](#06-challenge-nop-sled-redo)
      * [07. Challenge: No NOPs allowed!](#07-challenge-no-nops-allowed)
      * [08. Challenge: multiline output](#08-challenge-multiline-output)
      * [09: Challenge: execve blocking attempt](#09-challenge-execve-blocking-attempt)
   * [Further Reading](#further-reading)
      * [Input restrictions](#input-restrictions)

</details>

# Introduction

In [the previous session](../shellcodes), we learned about **shellcodes**, a form of **code injection** which allowed us to hijack the control flow of a process and make it do our bidding. The three steps for a succesful shellcode attack are:

 * **develop**: obtain the machine code for the desired functionality
 * **inject**: place the shellcode into the process' address space
 * **trigger**: divert control flow to the beginning of our shellcode

The first step seems pretty straightforward, but there are a lot of things that could go wrong with the last two. For example, we cannot inject a shellcode in a process that doesn't read input or reads very little (though remember that if we can launch the target program we can place the shellcode inside its environment or command line arguments); we cannot trigger our shellcode if we cannot overwrite some code-pointer (e.g. a saved return) or if we do not know the precise address at which it ends up in the process' memory and we cannot use such an attack if there isn't some memory region where we have both write and execute permissions.

Some of these hurdles can occur naturally, while others are intentionally created as preventive measures (e.g. on modern platforms, any memory area can be either writable or executable, but not both, a concept known as [W^X](https://en.wikipedia.org/wiki/W%5EX)). Anyway, it is useful to think about these problems and how to work around them, then put that knowledge into practice.

# Tutorials

## 01. Tutorial: preventing stack operations from overwriting the shellcode

When performing a shellcode attack we often needed to write some stuff in memory so that it has a valid address. For example, to perform an `execve("/bin/sh", ["/bin/sh", NULL], NULL)` syscall, we need to place the string `"/bin/sh"` in  memory and fill the `rdi` register (first argument of a syscall) with that address. In theory we could write it in any writable area but, as you might have noticed in the previous session, it's usually simpler to just use the stack.

```asm
    mov rax, `/bin/sh`
    push rax

```

results in fewer machine-code bytes than:

```asm
    mov rax, `/bin/sh`
    mov rbx, 0x00404000
    mov qword [rbx], rax
```

plus, `push`-ing has the side effect of placing our address in the `rsp` register which we could later `mov` somewhere else, avoiding the need of explicitly referring to some address (which might be difficult to predict, or even random, in the case of ASLR).

In cases where our shellcode is also injected on the stack this leads to the complicated situation in which the stack serves as both a code and data region. If we aren't careful, our data pushes might end up overwriting the injected code and ruining our attack.

Run `make` then use the `exploit.py` script (don't bother with how it works, for now); it will create a shellcode, pad it and feed it to the program, then open a new terminal window with a `gdb` instance breaked at the end of the `main` function. You can then explore what happens step by step and you will notice that, as the shellcode pushes the data it needs onto the stack it eventually comes to overwrite itself, resulting in some garbage.

The problem is that, after executing `ret` at the end of `main` and getting hijacked to jump to the beginning of our shellcode, `rip` ends up at `0x7ffca44f2280`, while `rsp` ends up at `0x7ffca44f22c0` (addresses on your machine will probably differ). The instruction pointer is only 64 bytes **below** the stack pointer.

 * as instructions get executed, the instruction pointer is *incremented*
 * as values are pushed onto the stack, the stack pointer is *decremented*

Thus the difference will shrink more and more with each instruction executed. The total length of the shellcode is 48 bytes so that means that after pushing 16 bytes onto the stack (64 - 48) any `push` will overwrite the end of our shellcode!

One obvious solution is to try and modify our shellcode to make it shorter, or to make it push less data onto the stack; this might work in some situations, but it's not a general fix.

Remember that after the vulnerable function returns, we control the execution of the program; so we can control what happens to the stack! Then we'll simply move the top of the stack to give us some space by adding this as the first instruction to our shellcode:

```asm
  sub rsp, 64
```

Now, right after jumping to our shellcode, `rip` and `rsp` will be the same, but they'll go on in opposite directions and everything will be well. Uncomment line 64 in `exploit.py`, run it again and see what happens.

If we're at the very low-edge of the stack and can't access memory below, we can use `add` to move the stack pointer way up, so that even if the pushed data comes towards our injected code, it will not reach it; after all, our shellcode is short and we're not pushing much.

## 02. Tutorial: NOP sleds

In the previous session, you probably had some difficulties with the [ninth task](../shellcodes#09-challenge-shellcode-after-saved-ret---no-leak), which asked you to perform a shellcode-on-stack attack without having a leak of the overflown buffer's address. You can determine it using `gdb` but, as you've seen, things differ between `gdb` and non-`gdb` environments; the problem is even worse if the target binary is running on a remote machine.

The crux of the issue is the fact that we have to precisely guess **one** exact address where our shellcode begins. For example, our shellcode might end up looking like this in memory:

```
   0x7fffffffce28:  rex.WX adc QWORD PTR [rax+0x0],rax
   0x7fffffffce2c:  add    BYTE PTR [rax],al
   0x7fffffffce2e:  add    BYTE PTR [rax],al
=> 0x7fffffffce30:  push   0x68
   0x7fffffffce32:  movabs rax,0x732f2f2f6e69622f
   0x7fffffffce3c:  push   rax
   0x7fffffffce3d:  mov    rdi,rsp
   0x7fffffffce40:  push   0x1016972
```

The first instruction of our shellcode is the `push 0x68` at address `0x7fffffffce30`:

  * if we jump before it, we'll execute some garbage interpreted as code; in the above example, missing it by two bytes would execute `add    BYTE PTR [rax],al` which might SEGFAULT if `rax` doesn't happen to hold a valid writable address
  * if we jump after it, we'll have a malformed `"/bin/sh"` string on the stack, so the later `execve` call will not work.

Fortunately, we don't have to consider the entire address space, so our chances are better than 1 in 2<sup>64</sup>:

  * the stack is usually placed at a fixed address (e.g. 0x7fffffffdd000), so we have a known-prefix several octets wide
  * due to alignment concerns, the compiler emits code that places buffers and other local data at nice, rounded addresses (ending in `0`, or `c0`, `00` etc.), so we have a known-suffix several bits wide

On your local machine, using `gdb` to look at the buffer's address will then allow you to use just a bit of bruteforce search to determine the address outside of `gdb`.

But what if we could increase our chances to jump to the beginning of our shellcode? So that we don't have to guess **one** exact address, but just hit some address range? This is where "NOP sleds" come in.

A "NOP sled" is simply a string of `NOP` instructions added as a prefix to a shellcode. The salient features of a `NOP` instruction that make it useful for us are:

  * it does nothing
  * it's one byte long

Thus if we chain a bunch of these together and prepend them to our shellcode, we can jump inside the middle of the "NOP sled" at any position and it will be alright: each subsequent `NOP` instruction will be executed, doing nothing, then our shellcode will be reached.

Our shellcode will end up looking like this in the process memory:

```
   0x7fffffffd427:  mov BYTE PTR [rax], al
   0x7fffffffd429:  nop
   0x7fffffffd42a:  nop
   0x7fffffffd42b:  nop
   0x7fffffffd42c:  nop
   0x7fffffffd42d:  nop
   0x7fffffffd42e:  nop
   0x7fffffffd42f:  nop
=> 0x7fffffffd430:  push   0x68
   0x7fffffffd432:  movabs rax,0x732f2f2f6e69622f
   0x7fffffffd43c:  push   rax
```

Again, our first "useful" instruction is the `push 0x68` at `0x7fffffffd430`. Jumping after it and skipping its execution is still problematic, but notice that we can now jump **before** it, missing it by several bytes with no issue. If we jump to `0x7fffffffd42c` for example, we'll reach a `nop`, then execution will pass on to the next `nop` and so on; after executing 4 nops, our shellcode will be reached and everything will be as if we had jumped directly to `0x7fffffffd430` in the first place. There is now a continuous range of 8 addresses where it's ok to jump to.

But 8 is such a small number; the longer the NOP sled, the better our chances. The only limit is how much data we can feed into the program when we inject our shellcode.

  * Run `make`, then inspect the `vuln` binary in `gdb` and determine the location of the vulnerable buffer.
  * Modify line 14 of the `exploit.py` script with the address you've found, then run the script. Most likely, it will not work: the address outside of `gdb` is different.
  * Uncomment line 17 of the script, then run it again.
  * You should now have a shell!

If this doesn't work, play a bit with the address left on line 14; increment it by 256, then decrement it by 256. You're aiming to get **below** the actual address at some offset smaller than the NOP sled length which, in this example, is 1536.

## 03. Tutorial: null-free shellcodes

Up until now, all the vulnerable programs attacked used `read` as a method of getting the input. This allows us to feed them any string of arbitrary bytes. In practice, however, there are many cases in which the input is treated as a 0-terminated *string* and processed by functions like `strcpy`.

This means that our shellcode cannot contain a 0 byte because, as far as functions like `strcpy` are concerned, that signals the end of the input. However, shellcodes are likely to contain 0 bytes. For example, remember that we need to set `rax` to a value indicating the syscall we want; if we wish to `execve` a new shell, we'll have to place the value `59` in `rax`:

```asm
  mov rax, 0x3b
```

Due to the nature of x86 instructions and the size of the `rax` register, that `0x3b` might be considered an 8-byte wide constant, yielding the following machine code: `48 b8 59 00 00 00 00 00 00 00`.

As you can see, there are quite a lot of zeroes. We could get rid of them if we considered `0x3b` to be a 1-byte wide constant; unfortunately there's no instruction to place into `rax` an immediate 1-byte value. However, there is an instruction to place an immediate 1-byte value in `al`, the lowest octet of `rax`. But we need the other seven octets to be 0... Fortunately, we can do a trick by xor-ing the register with itself! This will make every bit 0, plus the `xor` instruction itself doesn't contain 0 bytes. So we can replace the code above with:

```asm
  xor rax, rax
  mov al, 0x3b
```

Which assembles to `48 31 c0 b0 3b`. Not only are there no 0 bytes, we've also reduced the size of the code!

Takeaways:

  * xor-ing a register with itself is a good way of obtaining some zeroes in memory without using zeroes in machine code
  * working with the lower parts of registers avoids immediate values with leading-zeroes

We can apply these insights in other situations to avoid zeroes in our code. For example, instead of

```asm
    mov rax, `/bin/sh\0`
    push rax
```

We can write:

```asm
    xor rax, rax
    push rax
    mov rax, `//bin/sh`
    push rax
```

Note that extra-slashes in a path don't make any difference.

The `vuln.c` program reads data properly into a buffer, then uses `strcpy` to move data into a smaller buffer, resulting in an overflow. Run `make`, then the `exploit.py` script; just like before, it will start a new terminal window with a `gdb` instance in which you can explore what happens. The attack will fail because the injected shellcode contains 0 bytes so `strcpy` will only stop copying well before the end of the shellcode.

Comment line 55 and uncomment line 56, replacing the shellcode with a null-free version. Run `exploit.py` again. It should work!
 
## 04. Tutorial: shellcodes in pwntools

Once again, `pwntools` can come to our aid and help us with shellcode attacks. The most useful feature for this is the [shellcraft module](https://docs.pwntools.com/en/stable/shellcraft.html) which offers prebuilt shellcodes for various architectures.

For example, to obtain a shellcode which performs `execve("/bin/sh", {"/bin/sh", NULL}, NULL)` on an `x86_64` platform we can call:

```python
shellcraft.amd64.linux.sh()
```

Note that this will give you back text representing *assembly code* and **not** *machine code* bytes. You can then use the `asm` function to assemble it: 

```python
asm(shellcraft.amd64.linux.sh(), arch="amd64", os="linux"))
```
Remember the friendly features of pwntools! Instead of always specifying the OS and the architecture, we can set them in the global context, like this:

```python
context.arch="amd64"
context.os="linux"
```

Or - even simpler - we can indicate a particular binary and let pwntools deduce the OS and architecture: `context.binary = "./vuln"`. We can then invoke a much cleaner `asm(shellcraft.sh())`.

Besides the magic snippet to invoke a shell, there are other builtin code fragments, such as to cause a crash, an infinite loop, `cat` a file or call some other syscall. Play around with `shellcraft`, inspecting the output. You'll notice that all these shellcodes are free of zero bytes and newlines!

## 05. Tutorial: alphanumeric shellcode

It is commonly the case that user input is filtered to make sure it matches certain conditions. Most user input expected from a keyboard should not contain non-printable characters; a "name" should contain only letters, a PIN should contain only digits, etc.

The program might check its input against some conditions and, if rejected, bail in such a way so as to not trigger our injected code. This places the burden on us to develop shellcode that doesn't contain certain bytes. We've seen how we can avoid newlines and zero bytes to work around some input-reading functions. This concept can be pushed even further, heavily restricting our character set: on 32-bit platforms, we can write **alphanumeric shellcodes**!

But can we really? It's plausible that there are some clever tricks on the level of replacing `mov eax, 0x3b` with `xor eax, eax; mov al, 0x3b` that could make use of only alphanumeric characters, but all our shellcodes so far need to perform a syscall. Looking at the encoding of the `int 0x80` instruction seems pretty grim: `\xcd\x80`. Those are not even printable characters. So how can we perform a syscall?

Here it's important to step back and carefully consider our assumptions:

  * There is some memory region to which we have both write and execute access (otherwise we wouldn't attempt a code injection attack)
  * After our input is read, there is some check on it to make sure it doesn't contain certain characters.

Aha! We cannot **inject** some bytes, but nothing's stopping us from injecting something that **generates** those bytes! Generating is just an alternative way of *writing*, so instead of **injecting** our shellcode, we'll inject some code which **generates** the shellcode, then executes it!

This is, in fact, as complicated as it sounds, so we won't do it ourselves. We'll just observe how such a shellcode, produced by a specialized tool (`msfvenom`) works. So invoke the following command, which should give you a python-syntax buffer containing an alphanumeric shellcode that executes "/bin/sh":

`msfvenom -a x86 --platform linux -p linux/x86/exec -e x86/alpha_mixed BufferRegister=ECX -f python`

  * `-a x86`: specifies the architecture as 32-bit x86
  * `--platform linux`: specifies OS
  * `-p linux/x86/exec`: specifies a preset program (you can use `-` or `STDIN` for a custom initial shellcode, to be transformed)
  * `-e x86/alpha_mixed`: specifies encoding to be alphanumeric
  * `BufferRegister=ECX`: specifies an initial register which holds the address of the buffer; this is needed in order to have some way to refer to the region in which we're unpacking our code. Without this, a short non-alphanumeric preamble is added instead to automatically extract the buffer address
  * `-f python`: formats output using python syntax

`msfvenom` is actually capable of taking an arbitrary assembly snippet and transforming it into an alphanumeric "bootstrapper" which, once injected, unpacks the original shellcode and executes it.

# Challenges

## 06. Challenge: NOP sled redo

Redo the last three challenges (9, 10, 11) from [the previous session](../shellcodes) using NOP-sleds.

## 07. Challenge: No NOPs allowed!

This is similar to the previous tasks: you are left to guess a stack address. However, the `\x90` byte is filtered from input so you cannot use a NOP sled. But you should be able to adapt the concept. Remember the relevant features of the "NOP" instruction!

## 08. Challenge: multiline output

While perfectly ok with the byte 0, some functions (e.g. `fgets`) will stop reading when they encounter a newline character (`\n`). Thus, if our input is read by such a function, we need to make sure our shellcode contains no `\n` bytes.

For this challenge, the input will be read using the `gets` function, but you will need to craft a shellcode which prints to `stdout` the exact string:

```
first
second
third
```

## 09: Challenge: `execve` blocking attempt

If shellcodes are such a powerful threat, what if we attempted to block some shellcode-sepcific characters? Such as the bytes that encode a `syscall` function. Or the slash needed in a path; maybe it's not such a big loss to avoid these in legitimate inputs.

Can you still get a shell? For this task, **don't use** an existing encoder, but rather apply the encoding principles yourself.

# Further Reading

["Smashing The Stack For Fun And Profit", Aleph One](http://phrack.org/issues/49/14.html) - a legendary attack paper documenting SBOs and shellcodes. As it is written in '96, the examples in it will probably _not_ work (either out-of-the-box or with some tweaks). We recommend perusing it for its historical/cultural significance, but don't waste much time on the technical details of the examples.

## Input restrictions

The following articles deal with restrictions on the shellcode structure, such as forbidden characters or statistical properties of the input string. The examples presented will most likely not work as-they-are in a modern environment, so don't focus on the technical details, but rather on the methodology presented.

[*Writing ia32 alphanumeric shellcodes*, 2001 - rix](http://phrack.org/issues/57/15.html) - probably the first comprehensive presentation of how to automatically convert generic shellcodes to alphanumeric ones.

[*Building IA32 'Unicode-Proof' Shellcodes*, 2003 - obscou](http://phrack.org/issues/61/11.html) - rather than being concerned with input *restrictions*, this addresses ulterior transformations on input, namely converting an ASCII string to a UTF-16 one (as mentioned in the article's introduction, you could also imagine other possible transformations, such as case normalization).

[*Writing UTF-8 compatible shellcodes*, 2004 - Wana](http://phrack.org/issues/62/9.html)

[*English shellcode*, 2009 - Mason, Small, Monrose, MacManus](https://www.cs.jhu.edu/~sam/ccs243-mason.pdf) - delves into automatically generating shellcode which has the same statistical properties as English text.
