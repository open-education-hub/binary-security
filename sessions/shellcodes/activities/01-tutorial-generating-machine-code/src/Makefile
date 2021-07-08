.PHONY: all clean

all: exit_shellcode.bin

exit_shellcode.bin: exit_shellcode.nasm
	nasm $< -o $@

clean:
	-rm -f exit_shellcode.bin
