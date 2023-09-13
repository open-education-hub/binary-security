---
linkTitle: Dynamic Analysis
type: docs
weight: 10
---

# Dynamic Analysis

## Introduction

#### Objectives & Rationale 

The first part of this session will give you a walkthrough of the most common GDB principles that we are going to use in exploitation. In the second half, we are going to use these concepts in practice, to evade a basic key evaluation program.

Black Box type analysis works best when standard algorithms are used in the program, such as: MD5, SHA1,RSA . We can change the input to a more suggestive one and use the output to estimate what function was used to convert it.

Combined with behavioral analysis methods such as using sandboxes or strace/ltrace we can quickly map sections of code to functionalities.

With dynamic analysis, packed malware can be extracted from memory in unpacked form, enabling us to continue static analysis on the complete binary.

#### Prerequisites

In the current session we will use GDB extensively. We assume that you are familiar with its basic usage and will move on quickly to some of its more advanced features.

To brush up on the GDB basics, read this [Refresher](https://security.cs.pub.ro/summer-school/wiki/session/04-gdb "session:04-gdb").

The executable used in the demo is called sppb and is the challenge 1 binary.

###### Before GDB 

##### One thing you should always do before firing up GDB is to try to learn all the available information on the executable you\'re trying to debug through the techniques that have been presented so far.

For the purposes of this session it is a good idea to always run`objdump` on all the executable files before attaching GDB to them so that you have a better idea of what goes where.

``` {.code .bash}
$ objdump -M intel -d [executable]
```

### GDB Basic Commands

#### Getting help with GDB

Whenever you want to find out more information about GDB commands feel free to search for it inside [the documentation](http://www.gnu.org/software/gdb/documentation/ "http://www.gnu.org/software/gdb/documentation/") or by using the `help` command followed by your area of interest. For example searching for help for the `disassemble` command can be obtained by running the following command in GDB:

``` {.code .bash}
#print info about all help areas available
#identify the area of your question
(gdb) help
#print info about available data commands
#identify the command you want to learn more about
(gdb) help data
#print info about a specific command
#find out more about the command you are searching for
(gdb) help disassemble
```

#### Opening a program with GDB


A program can be opened for debugging in a number of ways. We can run
GDB directly attaching it to a program:

``` {.code .bash}
$ gdb [executable-file]
```

Or we can open up GDB and then specify the program we are trying to
attach to using the file or file-exec command:

``` {.code .bash}
$ gdb
(gdb) file [executable-file]
```

Furthermore we can attach GDB to a running service if we know its
process id:

``` {.code .bash}
$ gdb --pid [pid_number]
```


#### Disassembling


GDB allows disassembling of binary code using the `disassemble` command
(it may be shortened to `disas`). The command can be issued either on a
memory address or using labels.

``` {.code .bash}
(gdb) disassemble *main
Dump of assembler code for function main:
   0x080491c9 <+0>:     push   ebp
   0x080491ca <+1>:     mov    ebp,esp
   0x080491cc <+3>:     push   ebx
   0x080491cd <+4>:     sub    esp,0x4
=> 0x080491d0 <+7>:     mov    eax,ds:0x804c030
....Output ommited.....
(gdb) disassemble 0x080491c9
Dump of assembler code for function main:
   0x080491c9 <+0>:     push   ebp
   0x080491ca <+1>:     mov    ebp,esp
   0x080491cc <+3>:     push   ebx
   0x080491cd <+4>:     sub    esp,0x4
=> 0x080491d0 <+7>:     mov    eax,ds:0x804c030
```


#### Adding Breakpoints


Breakpoints are important to suspend the execution of the program being debugged in a certain place. Adding breakpoints is done with the `break`
command. A good idea is to place a breakpoint at the main function of the program you are trying to exploit. Given the fact that you have already run `objdump` and disassembled the program you know the address for the start of the main function. This means that we can set a
breakpoint for the start of our program in two ways:

``` {.code .bash}
(gdb) break *main (when the binary is not stripped of symbols)
(gdb) break *0x[main_address_obtained_with_objdump] (when aslr is off)
```

The general format for setting breakpoints in GDB is as follows:

``` {.code .bash}
(gdb) break [LOCATION] [thread THREADNUM] [if CONDITION]
```

*Issuing the `break` command with no parameters will place a breakpoint* *at the current address.*

*GDB allows using abbreviated forms for all the commands it supports. Learning these abbreviations comes with time and will greatly improve you work output. Always be on the lookout for using abbreviated commands.*

The abbreviated command for setting breakpoints is simply `b`.

#### Listing Breakpoints


At any given time all the breakpoints in the program can be displayed using the `info breakpoints` command:

``` {.code .bash}
(gdb) info breakpoints
```

*You can also issue the abbreviated form of the command*

``` {.code .bash}
(gdb) i b
```

#### Deleting Breakpoints

Breakpoints can be removed by issuing the `delete breakpoints` command followed by the breakpoints number, as it is listed in the output of the
`info breakpoints` command.

``` {.code .bash}
(gdb) delete breakpoints [breakpoint_number]
```

*You can also delete all active breakpoints by issuing the following the* `delete breakpoints` command with no parameters:*

``` {.code .bash}
(gdb) delete breakpoints
```

Once a breakpoint is set you would normally want to launch the program into execution. You can do this by issuing the `run` command. The program will start executing and stop at the first breakpoint you have
set.

``` {.code .bash}
(gdb) run
```

#### Execution flow

Execution flow can be controlled in GDB using the `continue`, `stepi`,`nexti` as follows:

``` {.code .bash}
(gdb) help continue
#Continue program being debugged, after signal or breakpoint.
#If proceeding from breakpoint, a number N may be used as an argument,
#which means to set the ignore count of that breakpoint to N - 1 (so that
#the breakpoint won't break until the Nth time it is reached).
(gdb) help stepi
#Step one instruction exactly.
#Argument N means do this N times (or till program stops for another reason).
(gdb) help nexti
#Step one instruction, but proceed through subroutine calls.
#Argument N means do this N times (or till program stops for another reason).
```

*You can also use the abbreviated format of the commands: `c`*
*(`continue`), `si` (`stepi`), `ni` (`nexti`).*

*If at any point you want to start the program execution from the* *beginning you can always reissue the `run` command.*

Another technique that can be used for setting breakpoints is using offsets.

As you already know, each assembly instruction takes a certain number of bytes inside the executable file. This means that whenever you are setting breakpoints using offsets you must always set them at instruction boundaries.

``` {.code .bash}
(gdb) break *main
Breakpoint 1 at 0x80491d0
(gdb) run
Starting program: sppb
 
Breakpoint 1, 0x80491d0 in main ()
(gdb) disassemble main
Dump of assembler code for function main:
   0x080491c9 <+0>:     push   ebp
   0x080491ca <+1>:     mov    ebp,esp
   0x080491cc <+3>:     push   ebx
   0x080491cd <+4>:     sub    esp,0x4
.....Output ommited.....
(gdb) break *main+4
Breakpoint 2 at 0x80491cd
```


### Examine and Print, your most powerful tools


GDB allows examining of memory locations be them specified as addresses or stored in registers. The `x` command (for *examine*) is arguably one
of the most powerful tool in your arsenal and the most common command you are going to run when exploiting.

The format for the `examine` command is as follows:

``` {.code .bash}
(gdb) x/nfu [address]
        n:  How many units to print
        f:  Format character
              a Pointer
              c Read as integer, print as character
              d Integer, signed decimal
              f Floating point number
              o Integer, print as octal
              s Treat as C string (read all successive memory addresses until null character and print as characters)
              t Integer, print as binary (t="two")
              u Integer, unsigned decimal
              x Integer, print as hexadecimal
        u:  Unit
              b: Byte
              h: Half-word (2 bytes)
              w: Word (4 bytes)
              g: Giant word (8 bytes)
              i: Instruction (read n assembly instructions from the specified memory address)
```

In contrast with the examine command, which reads data at a memory location the `print` command (shorthand `p`) prints out values stored in
registers and variables.

The format for the `print` command is as follows:

``` {.code .bash}
(gdb) p/f [what]
        f:  Format character
              a Pointer
              c Read as integer, print as character
              d Integer, signed decimal
              f Floating point number
              o Integer, print as octal
              s Treat as C string (read all successive memory addresses until null character and print as characters)
              t Integer, print as binary (t="two")
              u Integer, unsigned decimal
              x Integer, print as hexadecimal
              i Instruction (read n assembly instructions from the specified memory address)
```

For a better explanation please follow through with the following example:

``` {.code .bash}
#a breakpoint has been set inside the program and the program has been run with the appropriate commands to reach the breakpoint
#at this point we want to see which are the following 10 instructions
(gdb) x/10i 0x80491cd
   0x80491cd <main+4>:  sub    esp,0x4
   0x80491d0 <main+7>:  mov    eax,ds:0x804c030
   0x80491d5 <main+12>: push   0x0
   0x80491d7 <main+14>: push   0x1
   0x80491d9 <main+16>: push   0x0
   0x80491db <main+18>: push   eax
   0x80491dc <main+19>: call   0x8049080 <setvbuf@plt>
#let's examine the memory at 0x804a02a because we have a hint that this address holds one of the parameters of the scanf call  as it is afterwards placed on the stack (we'll explain later how we have reached this conclusion)
#the other parameter will be an address where the input will be stored
(gdb) x/s 0x804a02a
0x804a02a:      "%d"
# we now set a breakpoint for *main+56
(gdb) break *0x08049201
Breakpoint 3 at 0x08049201
(gdb) continue
Continuing.
 
Breakpoint 3, 0x08049201 in main ()
We then record the value of the eax register somewhere and use nexti(ni) and then we input an integer.
#let's examine the address which we recorded earlier corresponding to the eax register (it should've held the address for the integer we input)
#take note that in GDB registers are preceded by the "$" character very much like variables
(gdb) x/d 0xffffcf70 <- (your address)
0xffffcf70:     <your input>
#now let's print the contents of the eax register as hexadecimal
(gdb) p/x $eax
$1 = <your input>

The diference between p and x can be observed by issuing the following commands:
x/s 0x804a030
0x804a030:      "Your password is: %d. Evaluating it...\n"

p /s 0x804a030

$2 = 1920298841 which is the number in decimal format that "Your" can be translated to by its ascii codes (little endian so written as 0x72756F59).

In order to see the same result we must use the command p /s (char*)0x804a030 and dereference the pointer ourselves 
# as you can see the address holds the memory for the beginning of the string
# this shows you how "x" interprets data from memory while "p" merely prints out the contents in the required format
# you can think of it as "x" dereferencing while "p" not dereferencing
```


### GDB command file 



When exploiting, there are a couple of commands that you will issue periodically and doing that by hand will get cumbersome. GDB commands
files will allow you to run a specific set of commands automatically after each command you issue manually. This comes in especially handy
when you\'re stepping through a program and want to see what happens with the registers and stack after each instruction is ran, which is the
main target when exploiting.

The examine command only has sense when code is already running on the machine so inside the file we are going to use the display command which
translates to the same output.

In order to use this option you must first create your commands file. This file can include any GDB commands you like but a good start would
be printing out the content of all the register values, the next ten instructions that are going to be executed, and some portion from the
top of the stack.

The reason for examining all of the above after each instruction is ran will become more clear once the we go through the second section of the
session.

Command file template:

``` {.code .bash}
display/10i $eip
display/x $eax
display/x $ebx
display/x $ecx
display/x $edx
display/x $edi
display/x $esi
display/x $ebp
display/32xw $esp
```

In order to view all register values you could use the `x` command.
However the values of all registers can be obtained by running the`info all-registers` command:

``` {.code .bash}
(gdb) info all-registers
eax            0x8048630,134514224
ecx            0xbffff404,-1073744892
edx            0xbffff394,-1073745004
ebx            0xb7fc6ff4,-1208193036
esp            0xbffff330,0xbffff330
ebp            0xbffff368,0xbffff368
esi            0x0,0
edi            0x0,0
eip            0x80484e9,0x80484e9 <main+37>
eflags         0x286,[ PF SF IF ]
cs             0x73,115
ss             0x7b,123
ds             0x7b,123
es             0x7b,123
fs             0x0,0
gs             0x33,51
st0            *value not available*
st1            *value not available*
st2            *value not available*
st3            *value not available*
st4            *value not available*
st5            *value not available*
st6            *value not available*
st7            *value not available*
fctrl          0x37f,895
fstat          0x0,0
ftag           0xffff,65535
fiseg          0x0,0
fioff          0x0,0
foseg          0x0,0
---Type <return> to continue, or q <return> to quit---
fooff          0x0,0
fop            0x0,0
mxcsr          0x1f80,[ IM DM ZM OM UM PM ]
ymm0           *value not available*
ymm1           *value not available*
ymm2           *value not available*
ymm3           *value not available*
ymm4           *value not available*
ymm5           *value not available*
ymm6           *value not available*
ymm7           *value not available*
mm0            *value not available*
mm1            *value not available*
mm2            *value not available*
mm3            *value not available*
mm4            *value not available*
mm5            *value not available*
mm6            *value not available*
mm7            *value not available*
```

*One thing you might notice while using GDB is that addresses seem to be pretty similar between runs. Although with experience you will gain a better feel for where an address points to, one thing to remember at this point would be that stack addresses usually have the `0xbffff….` format. In order to run GDB with the commands file you have just generated, when launching GDB specify the `-x [command_file]` parameter.*

### Using GDB to modify variables 

GDB can be used to modify variables during runtime. In the case of exploitation this comes in handy as the program can be altered at
runtime with the purpose of changing the execution path to desired branches.

### PWNDBG


As you can see using GDB can be cumbersome, this is why we recommend using the pwndbg  plug-in. The tutorial as well as the repository of the project can be found here [Pwndbg](https://github.com/pwndbg/pwndbg "https://github.com/pwndbg/pwndbg") 

Give the fact that pwndbg is just a wrapper, all the functionality of GDB will be available when running gdb with the`pwndbg` plug-in. Some of the advantages of using pwngdb include:

1. Automatic preview of registers, code and stack after each instruction (you no longer need to create your own commands file)
2. Automatic dereferencing and following through of memory locations
3. Color coding

An alternative to pwndbg is [Gef](https://github.com/hugsy/gef "https://github.com/hugsy/gef").  However, this tutorial is designed with Pwndbg in mind.

#### PWNDBG Commands

`pdis` command gives a pretty output that is similar to what the `disas`
command in GDB prints:

``` {.code .bash}
Usage:  pdis 0x80491d0
```

If `pdis` is used with an address as a parameter, the output will be similar to what `x/Ni` prints out (where N is the number of instructions you want to disassemble) Usage: -pdis \[address\] [N] - where N is the number of instructions you want to be printed

The `stepi` command has the same effect as in GDB however, if you are running PWNDBG you will notice that after each step PWNDBG will automatically print register values, several lines of code from eip
register and a portion of the stack:

``` {.code .bash}
pwndbg> stepi

LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS ]────────────────────────────────────
*EAX  0xf7facd20 (_IO_2_1_stdout_) ◂— 0xfbad2084
 EBX  0x0
 ECX  0xa00af61b
 EDX  0xffffcfb4 ◂— 0x0
 EDI  0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
 ESI  0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
 EBP  0xffffcf78 ◂— 0x0
 ESP  0xffffcf70 —▸ 0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
*EIP  0x80491d5 (main+12) ◂— push   0 /* 'j' */
─────────────────────────────────────[ DISASM ]──────────────────────────────────────
   0x80491d0 <main+7>     mov    eax, dword ptr [stdout@GLIBC_2.0] <0x804c030>
 ► 0x80491d5 <main+12>    push   0
   0x80491d7 <main+14>    push   1
   0x80491d9 <main+16>    push   0
   0x80491db <main+18>    push   eax
   0x80491dc <main+19>    call   setvbuf@plt <setvbuf@plt>
 
   0x80491e1 <main+24>    add    esp, 0x10
   0x80491e4 <main+27>    mov    dword ptr [ebp - 8], 0
   0x80491eb <main+34>    push   0x804a010
   0x80491f0 <main+39>    call   puts@plt <puts@plt>
 
   0x80491f5 <main+44>    add    esp, 4
──────────────────────────────────[ SOURCE (CODE) ]──────────────────────────────────
In file: /home/kali/Desktop/dokermaker/binary-internal/sessions/05-dynamic-analysis/activities/01-02-challenge-sppb/src/sppb.c
    6   execve("/bin/sh", 0, 0);
    7 }
    8 
    9 int main()
   10 {
 ► 11   setvbuf(stdout, NULL, _IOLBF, 0);
   12   int readValue = 0;
   13 
   14   printf("Please provide password: \n");
   15   scanf("%d", &readValue);
   16 
──────────────────────────────────────[ STACK ]──────────────────────────────────────
00:0000│ esp 0xffffcf70 —▸ 0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
01:0004│     0xffffcf74 ◂— 0x0
02:0008│ ebp 0xffffcf78 ◂— 0x0
03:000c│     0xffffcf7c —▸ 0xf7de0fd6 (__libc_start_main+262) ◂— add    esp, 0x10
04:0010│     0xffffcf80 ◂— 0x1
05:0014│     0xffffcf84 —▸ 0xffffd024 —▸ 0xffffd1d9 ◂— '/home/kali/Desktop/sppb'
06:0018│     0xffffcf88 —▸ 0xffffd02c —▸ 0xffffd24d ◂— 'COLORFGBG=15;0'
07:001c│     0xffffcf8c —▸ 0xffffcfb4 ◂— 0x0
────────────────────────────────────[ BACKTRACE ]────────────────────────────────────
 ► f 0 0x80491d5 main+12
   f 1 0xf7de0fd6 __libc_start_main+262

```


You can always use the following commands to obtain context at any given
moment inside the debug process:

1. `context reg`
2. `context code`
3. `context stack`
4. `context all`

One additional PWNDBG command which can be used to show values in registers is the `telescope` command. The command dereferentiates pointer values until it gets to a value and prints out the entire trace. 

The command can be used with both registers and memory addresses:

``` {.code .bash}
pwndbg$ telescope $esp
00:0000│ esp 0xffffcf70 —▸ 0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
01:0004│     0xffffcf74 ◂— 0x0
02:0008│ ebp 0xffffcf78 ◂— 0x0
03:000c│     0xffffcf7c —▸ 0xf7de0fd6 (__libc_start_main+262) ◂— add    esp, 0x10
04:0010│     0xffffcf80 ◂— 0x1
05:0014│     0xffffcf84 —▸ 0xffffd024 —▸ 0xffffd1d9 ◂— '/home/kali/Desktop/sppb'
06:0018│     0xffffcf88 —▸ 0xffffd02c —▸ 0xffffd24d ◂— 'COLORFGBG=15;0'
07:001c│     0xffffcf8c —▸ 0xffffcfb4 ◂— 0x0
pwndbg> telescope 0xffffcf84
00:0000│  0xffffcf84 —▸ 0xffffd024 —▸ 0xffffd1d9 ◂— '/home/kali/Desktop/sppb'
01:0004│  0xffffcf88 —▸ 0xffffd02c —▸ 0xffffd24d ◂— 'COLORFGBG=15;0'
02:0008│  0xffffcf8c —▸ 0xffffcfb4 ◂— 0x0
03:000c│  0xffffcf90 —▸ 0xffffcfc4 ◂— 0xe38ae80b
04:0010│  0xffffcf94 —▸ 0xf7ffdb60 —▸ 0xf7ffdb00 —▸ 0xf7fc93e0 —▸ 0xf7ffd9a0 ◂— ...
05:0014│  0xffffcf98 —▸ 0xf7fc9410 —▸ 0x804832d ◂— 'GLIBC_2.0'
06:0018│  0xffffcf9c —▸ 0xf7fac000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e9d6c
07:001c│  0xffffcfa0 ◂— 0x1
```

In the example above, the memory address 0x8048630 was loaded into EAX. That is why examining the register or the memory location gives the same output.

For more information on various PWNdbg commands you can always visit the PWNdbg help through the `pwndbg` command It is always a better idea to use PWNdbg commands when available. However you should also know the basics of using GDB as well.


#### Altering variables and memory with PWNdbg and GDB


In addition to basic registers, GDB has a two extra variables which map onto some of the existing registers, as follows:

-   `$pc – $eip`

-   `$sp – $esp`

-   `$fp – $ebp`

In addition to these there are also two registers which can be used to view the processor state `$ps – processor status`

Values of memory addresses and registers can be altered at execution time. Because altering memory is a lot easier using PWNdbg we are going to
use it throughout today\'s session.

The easiest way of altering the execution flow of a program is editing the `$eflags` register just before jump instructions.

Using GDB the `$eflags` register can be easily modified:

``` {.code .bash}
pwndbg> reg eflags
EFLAGS 0x282 [ cf pf af zf SF IF df of ]
Set the ZF flag
pwndbg> set $eflags |= (1 << 6)
Clear the ZF flag
pwndbg> set $eflags &= ~(1 << 6)
```


Notice that the flags that are set are printed in all-caps when the`reg eflags` command is issued.

The `set` command  (GDB native) can be used to modify values that reside inside memory.

``` {.code .bash}
pwndbg> telescope 0x804a010
00:0000│  0x804a010 ◂— 'Please provide password: '
01:0004│  0x804a014 ◂— 'se provide password: '
02:0008│  0x804a018 ◂— 'rovide password: '
03:000c│  0x804a01c ◂— 'de password: '
04:0010│  0x804a020 ◂— 'assword: '
05:0014│  0x804a024 ◂— 'ord: '
06:0018│  0x804a028 ◂— 0x64250020 /* ' ' */
07:001c│  0x804a02c ◂— 0x0

pwndbg> set {char [14]} 0x804a010 = "No pass here"
Written 28 bytes to 0x8048630
pwndbg> telescope 0x8048630
00:0000│  0x804a010 ◂— 'No pass here'
01:0004│  0x804a014 ◂— 'ass here'
02:0008│  0x804a018 ◂— 'here'
03:000c│  0x804a01c ◂— 0x70200000
04:0010│  0x804a020 ◂— 'assword: '
05:0014│  0x804a024 ◂— 'ord: '
06:0018│  0x804a028 ◂— 0x64250020 /* ' ' */
07:001c│  0x804a02c ◂— 0x0
```

As you can see the string residing in memory at address `0x8048630` has been modified using the `set` command.

Pwngdb does not offer enhancements in modifying registry values. For modifying registry values you can use the GDB `set` command.

``` {.code}
pwngdb> p/x $eax
$10 = 0x1
pwngdb> set $eax=0x80
pwngdb> p/x $eax
$11 = 0x80
```


### Enough with GDB (for a while) 


The following section will describe the process of function calling in detail. Understanding function calling and stack operations during program execution is esential to exploitation.

### The Stack 

The stack is one of the areas of memory which gets the biggest attention in exploitation writing.


#### Stack Growth


The stack grows from high memory addresses to low memory addresses.

``` {.code .bash}
pwndbg>  pdis $eip

   0x80491db <main+18>    push   eax
   0x80491dc <main+19>    call   setvbuf@plt <setvbuf@plt>
 
   0x80491e1 <main+24>    add    esp, 0x10
   0x80491e4 <main+27>    mov    dword ptr [ebp - 8], 0
   0x80491eb <main+34>    push   0x804a010
 ► 0x80491f0 <main+39>    call   puts@plt <puts@plt>

pwndbg> p/x $esp
$1 = 0xffffcf6c
pwndbg> si
0x8049050 in puts@plt ()
pwndbg> p/x $esp
$5 = 0xffffcf68
```

As you can see from the example above the \$esp register had an initial value of `0xffffcf6c`. The next instruction that is about to be executed is a push (it pushes `0x0` on the stack). We execute the instruction and then reevaluate the value of `$esp`. As we can see `$esp` now points to `0xffffcf68` (`0xffffcf6c-0x4`).


#### Frame pointers and local function variables


Whenever the processor is entering the execution for a function, a special logical container is created on the stack for that function.

This container is called a function frame. The idea behind it is that the processor must know which area of the stack belongs to which function.

In order to achieve this logical segmentation a set of 2 instructions are automatically inserted by the compiler at the beginning of each function. Can you tell what they are based on the output below?

``` {.code .bash}
pwndbg> break main
Breakpoint 1 at 0x80484c8
pwndbg> run
[----------------------------------registers-----------------------------------]
 EAX  0xf7fa99e8 (environ) —▸ 0xffffd02c —▸ 0xffffd24d ◂— 'COLORFGBG=15;0'
 EBX  0x0
 ECX  0xb8a6a751
 EDX  0xffffcfb4 ◂— 0x0
 EDI  0x80490a0 (_start) ◂— xor    ebp, ebp
 ESI  0x1
 EBP  0xffffcf78 ◂— 0x0
 ESP  0xffffcf70 ◂— 0x1
 EIP  0x80491d0 (main+7) ◂— mov    eax, dword ptr [0x804c030]
[-------------------------------------code-------------------------------------]
   0x080491c9 <+0>:     push   ebp
   0x080491ca <+1>:     mov    ebp,esp
   0x080491cc <+3>:     push   ebx
   0x080491cd <+4>:     sub    esp,0x4
=> 0x080491d0 <+7>:     mov    eax,ds:0x804c030
   0x080491d5 <+12>:    push   0x0
   0x080491d7 <+14>:    push   0x1
   0x080491d9 <+16>:    push   0x0
   0x080491db <+18>:    push   eax

[------------------------------------stack-------------------------------------]
00:0000│ esp 0xffffcf70 ◂— 0x1
01:0004│     0xffffcf74 ◂— 0x0
02:0008│ ebp 0xffffcf78 ◂— 0x0
03:000c│     0xffffcf7c —▸ 0xf7dda905 (__libc_start_main+229) ◂— add    esp, 0x10
04:0010│     0xffffcf80 ◂— 0x1
05:0014│     0xffffcf84 —▸ 0xffffd024 —▸ 0xffffd1d9 ◂— '/home/kali/Desktop/sppb'
06:0018│     0xffffcf88 —▸ 0xffffd02c —▸ 0xffffd24d ◂— 'COLORFGBG=15;0'
07:001c│     0xffffcf8c —▸ 0xffffcfb4 ◂— 0x0

[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
 
Breakpoint 1, 0x080491d0 in main ()
pwndbg>  disass password_accepted


   0x080491b2 <+0>:     push   ebp                                                   
   0x080491b3 <+1>:     mov    ebp,esp                                               
   0x080491b5 <+3>:     push   0x0
   0x080491b7 <+5>:     push   0x0
   0x080491b9 <+7>:     push   0x804a008
   0x080491be <+12>:    call   0x8049070 <execve@plt>
   0x080491c3 <+17>:    add    esp,0xc
   0x080491c6 <+20>:    nop
   0x080491c7 <+21>:    leave  
   0x080491c8 <+22>:    ret 

```

What we did is we created a breakpoint for the start of the main function and then ran the program. As you can see the first 2 instructions that got executed were `push ebp` and `mov ebp,esp`.

We then set a breakpoint for another function called `pass_accepted`, continued execution and entered a password that we know is going to pass validation. Once the breakpoint is hit, we can see the same 2 instructions `push ebp` and `mov ebp,esp`.

The two instructions which can be noticed at the beginning of any function are the instructions required for creating the logical container for each function on the stack.

In essence what they do is save the reference of the old container (`push ebp`) and record the current address at the top of the stack as the beginning of the new container(`mov ebp,esp`).

For a visual explanation please see below:

<p align="center">
    <img src="https://security.cs.pub.ro/summer-school/wiki/_media/session/s5_frame_pointer_picture.jpg?w=300&tok=e38db5" alt="Sublime's custom image"/>
</p>

As you can see the EBP register always points to the stack address that corresponds to the beginning of the current function\'s frame. That is why it is most often referred to as the frame pointer.

In addition to the two instructions required for creating a new stack frame for a function, there are a couple more instructions that you will usually see at the beginning of a function

If you analyze the instructions at the beginning of main, you can spot these as being:

1.  An `and esp,0xfffffff0` instruction.

2.  A `sub` insctruction that subtracts a hex value from ESP.

The first of the two instructions has the purpose of aligning the stack to a specific address boundary. This is done to increase processor efficiency. In our specific case, the top of the stack gets aligned to a 16 byte multiple address.

One of the purposes of the stack inside functions is that of offering address space in which to place local variables. The second instruction preallocates space for local function variables.

Let\'s see how local variables are handled inside assembly code.

``` {.code .c}
#include <stdio.h>
int main()
{
        int a;
        a=1;
        return 0;
}
```

``` {.code .bash}
kali@kali:~/sss$ gdb test
GNU gdb (Ubuntu/Linaro 7.4-2012.02-0ubuntu2) 7.4-2012.02
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/dgioga/sss/test...(no debugging symbols found)...done.
pwndbg>  break main
Breakpoint 1 at 0x80483ba
pwndbg>  run
[----------------------------------registers-----------------------------------]
EAX: 0x1
EBX: 0xb7fc6ff4 --> 0x1a0d7c
ECX: 0xbffff414 --> 0xbffff576 ("/home/dgioga/sss/test")
EDX: 0xbffff3a4 --> 0xb7fc6ff4 --> 0x1a0d7c
ESI: 0x0
EDI: 0x0
EBP: 0xbffff378 --> 0x0
ESP: 0xbffff368 --> 0x80483d9 (<__libc_csu_init+9>:,add    ebx,0x1c1b)
EIP: 0x80483ba (<main+6>:,mov    DWORD PTR [ebp-0x4],0x1)
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80483b4 <main>:,  push   ebp
   0x80483b5 <main+1>:,mov    ebp,esp
   0x80483b7 <main+3>:,sub    esp,0x10
=> 0x80483ba <main+6>:,mov    DWORD PTR [ebp-0x4],0x1
   0x80483c1 <main+13>:,mov    eax,0x0
   0x80483c6 <main+18>:,leave
   0x80483c7 <main+19>:,ret
   0x80483c8:,nop
[------------------------------------stack-------------------------------------]
0000| 0xbffff368 --> 0x80483d9 (<__libc_csu_init+9>:,add    ebx,0x1c1b)
0004| 0xbffff36c --> 0xb7fc6ff4 --> 0x1a0d7c
0008| 0xbffff370 --> 0x80483d0 (<__libc_csu_init>:,push   ebp)
0012| 0xbffff374 --> 0x0
0016| 0xbffff378 --> 0x0
0020| 0xbffff37c --> 0xb7e3f4d3 (<__libc_start_main+243>:,mov    DWORD PTR [esp],eax)
0024| 0xbffff380 --> 0x1
0028| 0xbffff384 --> 0xbffff414 --> 0xbffff576 ("/home/dgioga/sss/test")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
 
Breakpoint 1, 0x080483ba in main ()
```

As you can see the operations that relate to the stack are:

1.  The old frame pointer is saved.

2.  EBP takes the value of ESP (the frame pointer is set to point to the current function\'s frame).

3.  `0x10` is subtracted from ESP (reserve space for local variables).

4.  The value `0x01` is placed at the address of EBP-0x4 (the local
    variable `a` takes the value 1).

#### Function parameters


The stack is also used to pass in parameters to functions.

In the process of calling a function we can define two entities. The callee (the function that gets called) and the caller (the function that calls).

When a function is called, the caller pushes the parameters for the callee on the stack. The parameters are pushed in reverse order.

When the callee wants to get access to the parameters it was called with, all it needs to do is access the area of the stack that is higher up in reference to the start of it\'s frame.

At this point it makes sense to remember the following cases:

1.  When EBP+value is referred to it is generally a referral to a parameter passed in to the current function.

2.  When EBP-value is referred to it is generally a referral to a local variable.

Lets see how this happens with the following code:

``` {.code .c}
#include <stdio.h>
 
int add(int a, int b)
{
        int c;
        c=a+b;
        return c;
}
 
int main()
{
        add(10,3);
        return 0;
}
```

``` {.code .bash}
pwndbg> pdis 0x080483ca
Dump of assembler code for function main:
   0x080483ca <+0>:,push   ebp                        #save the old frame pointer
   0x080483cb <+1>:,mov    ebp,esp                    #create the new frame pointer
   0x080483cd <+3>:,sub    esp,0x8                    #create space for local variables
   0x080483d0 <+6>:,mov    DWORD PTR [esp+0x4],0x3    #push the last parameter of the function that is to be called
   0x080483d8 <+14>:,mov    DWORD PTR [esp],0xa      #push the second to last(the first in this case) parameter of the function that is to be called
   0x080483df <+21>:,call   0x80483b4 <add>          #call the function
   0x080483e4 <+26>:,mov    eax,0x0
   0x080483e9 <+31>:,leave
   0x080483ea <+32>:,ret
End of assembler dump.
pwndbg> pdis 0x080483b4
Dump of assembler code for function add:
   0x080483b4 <+0>:,push   ebp                        #save the old frame pointer
   0x080483b5 <+1>:,mov    ebp,esp                    #create a new frame pointer
   0x080483b7 <+3>:,sub    esp,0x10                   #create space for local variables
   0x080483ba <+6>:,mov    eax,DWORD PTR [ebp+0xc]    #move the first parameter into the EAX register (ebp+saved_ebp(4 bytes)+return_addres(4 bytes)+last_parameter(4 bytes))
   0x080483bd <+9>:,mov    edx,DWORD PTR [ebp+0x8]    #move the second parameter into the EDX register (ebp+saved_ebp(4 bytes)+return_addres(4 bytes))
   0x080483c0 <+12>:,add    eax,edx                  #add the registers
   0x080483c2 <+14>:,mov    DWORD PTR [ebp-0x4],eax  #place the result inside the local variable (c)
   0x080483c5 <+17>:,mov    eax,DWORD PTR [ebp-0x4]  #place the result inside the eax register in order to return it
   0x080483c8 <+20>:,leave
   0x080483c9 <+21>:,ret
End of assembler dump.
```

As you can see the parameters were pushed in reverse order, and the rule regarding the reference to EBP holds.

If you don\'t understand why the offset for the parameters starts at EBP+0x08 and not EBP follow through with the next section.


#### Calling functions (call and ret)

When calling a function the callee places the return address on the stack. This address is nothing more than a bookmark so that execution can resume where it left off once the called function finishes
execution.

The last instruction in functions is usually a `ret` instruction that resumes execution to the callee.

For a better understanding of function calling and returning, from an execution flow point of view, please follow through with the following tip.

<span style="font-size:1rem; background:lightgrey;">The call instruction could be translated to the following instructions:</span>

1.  `push eip`
2.  `mov eip, address_of_called_function`

The ret instruction could be translated into:

1.  `pop eip`

The visual depiction of how the stack looks while a program is executing
can be found in section 2 but will be included here as well:

<p align="center">
    <img src="https://security.cs.pub.ro/summer-school/wiki/_media/session/stack-convention.png?w=600&tok=d710e1">
</p>



### Next lesson preview: Buffer Overflows 


Now that we have a complete overview of the stack we can step forward to stack based buffer overflows.

A buffer overflow takes place when there is a lack of checking regarding boundaries and usually result in complete control of the program\'s instruction pointer. This takes place when a buffer overflows its boundaries and overwrites the return address of a function.

A typical example of buffer overflows can be seen in the following picture:

<p align="center">
    <img src="https://security.cs.pub.ro/summer-school/wiki/_media/session/s5_buffer_overflow.jpg?w=500&tok=810778">
</p>

Challenges
----------

Use GDB and pwndbg to run the code provided in the Activities section.

### 01. Challenge - Explore The Simple Password Protected Bash 


The executable gets input from the user and evaluates it against a static condition. If it succeeds it then calls a `password_accepted` function that prints out a success message and spawns a shell.

Your task is to use GDB and pwndbg to force the executable to call the `password_accepted` function.

Gather as much info about the executable as possible through the techniques you have learned in previous sessions.

Think of modifying registers for forcing the executable to call thefunction (there is more than one way of doing this).

### 02. Challenge - Simple Password Protected Bash Destruction

What is the condition against which your input is evaluated in the executable contained in the executable `sppb`?

<span style="font-size:1rem; background:lightgrey;">The ultimate goal is to be able to craft an input for the binary so that
the `password_accepted` function is called (modifying registers while
running the program in GDB is just for training purposes).</span>



### 03. Challenge - Domino 

Analyze the binary, reverse engineer what it does and get a nice message
back.

### 04. Challenge - Call me 

Investigate the binary in `04-challenge-call-me/src/call_me` and find
out the flag

<details> 
  <summary>Hint</summary>
   There is something hidden you can toy around with.
</details>


<details> 
  <summary>Hint </summary>
   The challenge name is a hint.
</details>


### 05. Challenge - Snooze Me 


I wrote a simple binary that computes the answer to life, the universe and everything. It swear it works... eventually.

### 06. Challenge - Phone Home 


To protect their confidential data from those snooping cloud providers, the authors of `06-challenge-phone-home/src/phone_home` have used some obfuscation techniques.

Unfortunately, the key feature of the application is now unreachable due to a bug. Can you bypass the impossible condition?

### 07. Challenge - Chain encoder 

How do you reverse something made to be ireversible, you are welcome to find out in this challenge. 

### 08. Challenge - Simple cdkey

I found this software but i don't have the cd key, can you crack it for me?

------------------------------------------------------------------------

Except where otherwise noted, content on this wiki is licensed under the
following license: [CC Attribution-Share Alike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/deed.en)
