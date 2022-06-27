#!/usr/bin/env python

f = open("../flag")
flag = f.readline().strip()
f.close()
char = '\n'

res = []
for i in range(0, len(flag)):
    res += [ord(flag[i]) - ord(char)]

print "{" + ", ".join("{}".format(r) for r in res) + "};"
