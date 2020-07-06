BITS 32
	mov ebx, 42		; Exit code 42
	mov eax, 1		; __NR_exit
	int 0x80
