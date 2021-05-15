#!/bin/sh -e

# Very simple one:
#make -C ../src caller-pie caller-no-pie

# Expected from the solver:
gcc -m32 -fPIC -c -o ../src/caller1.o ../src/caller.c
gcc -m32 -pie -o ../src/caller-pie ../src/caller1.o ../src/flag1.o

gcc -m32 -fno-PIC -c -o ../src/caller2.o ../src/caller.c
gcc -m32 -no-pie -o ../src/caller-no-pie ../src/caller2.o ../src/flag2.o

../src/caller-pie
../src/caller-no-pie
