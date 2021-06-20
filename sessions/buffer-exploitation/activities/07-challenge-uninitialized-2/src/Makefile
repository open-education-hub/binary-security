CFLAGS = -O0 -Wall -fno-stack-protector -Wno-unused-function -Wno-uninitialized

.PHONY: all clean

all: uninitialized

uninitialized: uninitialized.o

uninitialized.o: uninitialized.c

clean:
	-rm -f *~
	-rm -f uninitialized.o
