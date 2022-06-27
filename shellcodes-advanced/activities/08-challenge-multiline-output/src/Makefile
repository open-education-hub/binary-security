CFLAGS = -Wall -fno-stack-protector -g -fno-PIC
LDFLAGS = -zexecstack -no-pie

.PHONY: all clean attack

all: vuln

vuln: vuln.o

clean:
	-rm -f vuln *.o
