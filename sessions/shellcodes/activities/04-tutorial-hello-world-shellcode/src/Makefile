CFLAGS = -Wall -fno-stack-protector -g -fno-PIC
LDFLAGS = -zexecstack -no-pie

.PHONY: all clean

all: vuln hello_shellcode.bin

hello_shellcode.bin: hello_shellcode.nasm
		nasm $< -o $@

vuln: vuln.o
		$(CC) $(LDFLAGS) $< -o $@

vuln.o: vuln.c
		$(CC) $(CFLAGS) -c $< -o $@
		@# We need an executable .bss
		objcopy --set-section-flags .bss=code,alloc,data $@


clean:
	-rm -f vuln *.o hello_shellcode.bin
