from pwn import *

flag = "SSS_CTF{0bad3910f14d10569b8bfe11aa1081e970e72e}\x00"
flag = ''.join(chr((ord(x) - 13) & 0xff) for x in flag)
parts = unpack_many(flag, 32)

for i in range(len(parts)):
	print('strvec[%d] = 0x%x;' % (i, parts[i]))


def encrypt(data):
	res = map(ord, data)
	n = len(data)
	print(hexdump(data))
	for i in range(n / 2):
		res[i] = res[i] ^ res[n - i - 1]
		res[n - i - 1] = (res[n - i - 1] - 1) & 0xff
	return ''.join(map(chr, res))

binary = ELF("./phone_home")
context.arch = 'i386'

func_ea = binary.symbols["gen_flag"]
chunk = binary.read(func_ea, 4096)
func_sz = chunk.find(asm('ret')) + 1
print('Function size: 0x%x' % func_sz)

func = encrypt(chunk[:func_sz])
binary.write(func_ea, func)
print(hexdump(func))

binary.save("./phone_home")
