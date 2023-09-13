CFLAGS = -Wall -fno-stack-protector -g -fno-PIC -m32 -mpreferred-stack-boundary=2
LDFLAGS = -zexecstack -no-pie -m32

.PHONY: all clean attack

all: vuln

vuln: vuln.o

clean:
	-rm -f vuln *.o
