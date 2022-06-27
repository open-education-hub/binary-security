from pwn import *

elf = ELF('buffers')

bss    = elf.get_section_by_name('.bss')
data   = elf.get_section_by_name('.data')
rodata = elf.get_section_by_name('.rodata')

bss_addr    = bss['sh_addr']
data_addr   = data['sh_addr']
rodata_addr = rodata['sh_addr']

bss_size = bss['sh_size']
data_size = data['sh_size']
rodata_size = rodata['sh_size']

# A (Alloc) = 1 << 1 = 2
# W (Write) = 1 << 0 = 1
bss_flags    = bss['sh_flags']
data_flags   = data['sh_flags']
rodata_flags = rodata['sh_flags']

print("Section info:")
print(".bss:    0x{:08x}-0x{:08x}, {}".format(bss_addr, bss_addr+bss_size, bss_flags))
print(".data:   0x{:08x}-0x{:08x}, {}".format(data_addr, data_addr+data_size, data_flags))
print(".rodata: 0x{:08x}-0x{:08x}, {}".format(rodata_addr, rodata_addr+rodata_size, rodata_flags))

print()

print("Variable info:")
print("g_buf_init_zero: 0x{:08x}".format(elf.symbols.g_buf_init_zero))
print("g_buf_init_vals: 0x{:08x}".format(elf.symbols.g_buf_init_vals))
print("g_buf_const:     0x{:08x}".format(elf.symbols.g_buf_const))
