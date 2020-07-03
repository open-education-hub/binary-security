BITS 32
	push 0x0a21		; "\n!"
	push 0x646c726f		; "dlro"
	push 0x57202c6f		; "W, o"
	push 0x6c6c6548		; "lleH"
	mov edx, 14		; Message length is 14 bytes.
	mov ecx, esp		; Stack points to message.
	mov ebx, 1		; Print to standard output (fd = 1).
	mov eax, 4		; __NR_write
	int 0x80
