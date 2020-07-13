from pwn import *

# TODO update binary name with task number
p = process('./rwslotmachineX')

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

gdb.attach(p)

p.interactive()
