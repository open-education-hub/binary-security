        jmp str
back:
        pop ecx ; call pushes the return address on the stack, which in our case is precisely the string address

        ...
str:
        call back
        db 'Hello, world'
