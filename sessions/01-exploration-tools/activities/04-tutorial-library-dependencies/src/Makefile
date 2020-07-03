CFLAGS = -Wall -m32
LDFLAGS = -m32
SKEL_BASE = ../../../skel

.PHONY: all clean deploy

all: libstrcmp.so

strcmp.o: strcmp.c
	gcc -Wall -m32 -fPIC -c $^

libstrcmp.so: strcmp.o
	gcc -Wall -m32 -fPIC -shared -o $@ $^ -ldl

libstrcmp.o: strcmp.c
	gcc -Wall -m32 -c -o $@ $^

run: libstrcmp.so
	LD_PRELOAD=./libstrcmp.so ../../02-tutorial-execution-tracing/src/crackme2

deploy:
	cp Makefile strcmp.c $(SKEL_BASE)/crackmes/crackme4

clean:
	-rm -f *.so *.o
