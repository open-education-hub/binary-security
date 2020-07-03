.PHONY: all clean

all: shellcode.bin

shellcode.bin: shellcode.S
	nasm -o $@ $^

print: shellcode.bin
	@hexdump -v -e '"\\" 1/1 "x%02x"' $^ ; echo

clean:
	-rm -f shellcode.bin *~
