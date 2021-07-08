CFLAGS = -Wall -fno-stack-protector -g -fno-PIC
LDFLAGS = -zexecstack -no-pie

.PHONY: all clean

all: vuln vuln2 exit_shellcode.bin

exit_shellcode.bin: exit_shellcode.nasm
		nasm $< -o $@

vuln: vuln.o
		$(CC) $(LDFLAGS) $< -o $@

vuln.o: vuln.c
		$(CC) $(CFLAGS) -c $< -o $@
		@# We need an executable .bss
		objcopy --set-section-flags .bss=code,alloc,data $@


vuln2: vuln2.o
		$(CC) $(LDFLAGS) $< -o $@

vuln2.o: vuln2.c
		$(CC) $(CFLAGS) -c $< -o $@
		@# We need an executable .bss
		objcopy --set-section-flags .bss=code,alloc,data $@


clean:
	-rm -f vuln vuln2 *.o exit_shellcode.bin
