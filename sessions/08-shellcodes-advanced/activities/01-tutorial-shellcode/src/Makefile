CFLAGS = -m32 -Wall -g -fno-PIC -mpreferred-stack-boundary=2
LDFLAGS = -m32 -zexecstack -no-pie

.PHONY: all clean

all: vuln shellcode.bin

vuln: vuln.o

shellcode.bin: shellcode.S
	nasm -o $@ $^

print: shellcode.bin
	@hexdump -v -e '"\\" 1/1 "x%02x"' $^ ; echo

clean:
	-rm -f *.o *~
	-rm -f shellcode.bin *~
