; Write "Hello, world!\n" to the standard output.
BITS 64
    ; We will execute the 'write(1, "Hello, world!\n", 14)' syscall

    ; We can't push 64 bit constants, but we can push 64 bit registers.
    ; What we're doing here is filling the registers with constants that consist
    ; of the ASCII-values of the character that make up our string.
    ; If you assessmble, then dissassemble this code, you'll notice that it's
    ; just a normal numerical constant assignment:
    ;
    ;   movabs rbx,0xa21646c726f
    ;
    ; The backtick notation is just a human-friendly syntactic feature of nasm.
    mov rbx, `orld!\n`
    push rbx
    mov rbx, 'Hello, w'
    push rbx

    ; After the two pushes, our string is on the stack, with the stack pointer
    ; pointing at its beginning, so we place it in the second-argument register.
    mov rsi, rsp

    ; strlen("Hello, world!\n") == 14
    mov rdx, 14

    ; stdout
    mov rdi, 1

    ; "write" syscall
    mov rax, 1
    syscall
