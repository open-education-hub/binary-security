#!/usr/bin/python2

import hashlib

MSG = "Congratulations, you've finally cracked this task!\nUnfortunately, we don't have any flags yet...\n\0"
KEY = "scepter"

FILE = "secret.enc"

sha1_key = hashlib.sha1(KEY)
digest_key = sha1_key.digest()

def RC4(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    return ''.join(out)

shuffle_key = "".join([ digest_key[7 * i % 20] for i in range(len(digest_key))])
rc4_msg = RC4(MSG, KEY)

f = open(FILE, "wb")
f.write(shuffle_key)
f.write(rc4_msg)
f.close()
