CFLAGS = -m64 -Wall -g -fno-PIC -mpreferred-stack-boundary=4
LDFLAGS = -m64 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

clean:
	-rm -f *.o *~
	-rm -f vuln
