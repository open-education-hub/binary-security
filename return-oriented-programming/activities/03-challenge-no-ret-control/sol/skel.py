#!/usr/bin/env python

from pwn import *

def dw(i):
    return struct.pack("<I", i)


# TO DO: get GOT address
exit_got = 0x00000000

# TO DO: get secret function address
secret_function = 0x00000000

p = process("./../src/2-no-ret-control")
p.interactive()