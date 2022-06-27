CFLAGS = -Wall -fno-stack-protector -g -fno-PIC
LDFLAGS = -no-pie

.PHONY: all clean

all: vuln binsh_shellcode.bin

vuln: vuln.o
	$(CC) $(LDFLAGS) $< -o $@

vuln.o: vuln.c
	$(CC) $(CFLAGS) -c $< -o $@
	@# We need an executable .bss
	objcopy --set-section-flags .bss=code,alloc,data $@

binsh_shellcode.bin: binsh_shellcode.nasm
		nasm $< -o $@


clean:
	-rm -f vuln *.o binsh_shellcode.bin
