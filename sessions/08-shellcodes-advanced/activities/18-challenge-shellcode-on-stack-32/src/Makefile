CFLAGS = -m32 -Wall -Wno-unused-function -g -fno-PIC -fno-stack-protector -mpreferred-stack-boundary=2
LDFLAGS = -m32 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

clean:
	-rm -f *.o *~
