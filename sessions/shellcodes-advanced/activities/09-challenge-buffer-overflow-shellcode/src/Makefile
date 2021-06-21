CFLAGS = -m64 -Wall -Wno-unused-function -g -fno-PIC -fno-stack-protector -mpreferred-stack-boundary=4
LDFLAGS = -m64 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

clean:
	-rm -f *.o *~
