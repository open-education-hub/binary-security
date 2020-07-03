CFLAGS = -Wall -g
LDFLAGS = -static
LDLIBS = -lssl -lcrypto

.PHONY: all clean

all: call_me

call_me: call_me.o

call_me.o: call_me.c

clean:
	-rm -f *~
	-rm -f call_me.o
