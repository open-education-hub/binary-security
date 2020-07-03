CFLAGS = -m32 -Wall -fno-stack-protector -g -fno-PIC
LDFLAGS = -m32 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

clean:
	-rm -f vuln *.o *~

