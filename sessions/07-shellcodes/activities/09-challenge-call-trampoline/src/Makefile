CFLAGS = -m32 -Wall -g -fno-PIC
LDFLAGS = -m32 -zexecstack -no-pie

.PHONY: all clean

all: vuln

vuln: vuln.o

shellcode.bin: shellcode.S
		nasm -o $@ $^

print: shellcode.bin
		@hexdump -v -e '"\\" 1/1 "x%02x"' $^ ; echo

clean:
		-rm -f vuln *.o shellcode.bin *~
