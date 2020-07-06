CFLAGS = -m32 -Wall -g -fno-PIC -mpreferred-stack-boundary=2
LDFLAGS = -m32 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

clean:
	-rm -f *.o *~
	-rm -f vuln
