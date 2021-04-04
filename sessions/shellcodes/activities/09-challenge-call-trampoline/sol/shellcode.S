BITS 32

    jmp str
back:
    pop ecx ; call pushes the return address on the stack, which in our case is precisely the string address
    mov ebx, 1
    mov edx, 14
    mov eax, 4
    int 0x80
    mov ebx, 0
    mov eax, 1
    int 0x80

str:
    call back
    db 'Hello, world', 10
