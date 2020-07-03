from pwn import *

flag = list("SSS_CTF{01013f4140fbce191755c53a53014326b06af7b8}")

seed = 0xcafebabe

def my_prng():
	global seed
	seed = (seed * 0xc0dec0de + 0x1337f00d) & 0xffffffff
	return seed

def swap(s, i, j):
	s[i], s[j] = s[j], s[i]

values = []

for i in range(len(flag)):
	values.append(my_prng() % len(flag))

for i in range(len(flag))[::-1]:
	swap(flag, i, values[i])

'''
for i in range(len(flag)):
	swap(flag, i, values[i])
'''

print(''.join(flag))
