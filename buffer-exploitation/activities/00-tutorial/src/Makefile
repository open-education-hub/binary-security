CFLAGS= -O0 -fno-stack-protector -no-pie
CC=gcc

all: buffers simple_read

buffers: buffers.c

simple_read: simple_read.c

.PHONY: clean
clean:
	rm -f buffers simple_read
