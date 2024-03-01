"use strict";(self.webpackChunkbinary_security=self.webpackChunkbinary_security||[]).push([[2678],{5680:(e,n,t)=>{t.d(n,{xA:()=>c,yg:()=>g});var a=t(6540);function i(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function o(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function l(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?o(Object(t),!0).forEach((function(n){i(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function r(e,n){if(null==e)return{};var t,a,i=function(e,n){if(null==e)return{};var t,a,i={},o=Object.keys(e);for(a=0;a<o.length;a++)t=o[a],n.indexOf(t)>=0||(i[t]=e[t]);return i}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)t=o[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var s=a.createContext({}),p=function(e){var n=a.useContext(s),t=n;return e&&(t="function"==typeof e?e(n):l(l({},n),e)),t},c=function(e){var n=p(e.components);return a.createElement(s.Provider,{value:n},e.children)},h="mdxType",d={inlineCode:"code",wrapper:function(e){var n=e.children;return a.createElement(a.Fragment,{},n)}},u=a.forwardRef((function(e,n){var t=e.components,i=e.mdxType,o=e.originalType,s=e.parentName,c=r(e,["components","mdxType","originalType","parentName"]),h=p(t),u=i,g=h["".concat(s,".").concat(u)]||h[u]||d[u]||o;return t?a.createElement(g,l(l({ref:n},c),{},{components:t})):a.createElement(g,l({ref:n},c))}));function g(e,n){var t=arguments,i=n&&n.mdxType;if("string"==typeof e||i){var o=t.length,l=new Array(o);l[0]=u;var r={};for(var s in n)hasOwnProperty.call(n,s)&&(r[s]=n[s]);r.originalType=e,r[h]="string"==typeof e?e:i,l[1]=r;for(var p=2;p<o;p++)l[p]=t[p];return a.createElement.apply(null,l)}return a.createElement.apply(null,t)}u.displayName="MDXCreateElement"},9520:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>s,contentTitle:()=>l,default:()=>d,frontMatter:()=>o,metadata:()=>r,toc:()=>p});var a=t(8168),i=(t(6540),t(5680));const o={},l="Shellcodes (Advanced)",r={unversionedId:"Exploitation Techniques/Shellcodes Advanced/Reading/README",id:"Exploitation Techniques/Shellcodes Advanced/Reading/README",title:"Shellcodes (Advanced)",description:'In the "Shellcodes" session, we learned about shellcodes, a form of code injection which allowed us to hijack the control flow of a process and make it do our bidding.',source:"@site/docs/Exploitation Techniques/Shellcodes Advanced/Reading/README.md",sourceDirName:"Exploitation Techniques/Shellcodes Advanced/Reading",slug:"/Exploitation Techniques/Shellcodes Advanced/Reading/",permalink:"/binary-security/Exploitation Techniques/Shellcodes Advanced/Reading/",draft:!1,tags:[],version:"current",frontMatter:{},sidebar:"sidebar",previous:{title:"Shellcodes Advanced",permalink:"/binary-security/Exploitation Techniques/Shellcodes Advanced/"},next:{title:"Return-Oriented Programming",permalink:"/binary-security/Exploitation Techniques/Return-Oriented Programming/"}},s={},p=[{value:"Introduction",id:"introduction",level:2},{value:"Tutorials",id:"tutorials",level:2},{value:"01. Tutorial: preventing stack operations from overwriting the shellcode",id:"01-tutorial-preventing-stack-operations-from-overwriting-the-shellcode",level:3},{value:"02. Tutorial: NOP sleds",id:"02-tutorial-nop-sleds",level:3},{value:"03. Tutorial: null-free shellcodes",id:"03-tutorial-null-free-shellcodes",level:3},{value:"04. Tutorial: shellcodes in pwntools",id:"04-tutorial-shellcodes-in-pwntools",level:3},{value:"05. Tutorial: alphanumeric shellcode",id:"05-tutorial-alphanumeric-shellcode",level:3},{value:"Challenges",id:"challenges",level:2},{value:"06. Challenge: <code>NOP</code>-sled Redo",id:"06-challenge-nop-sled-redo",level:3},{value:"07. Challenge: No <code>NOPs</code> Allowed",id:"07-challenge-no-nops-allowed",level:3},{value:"08. Challenge: Multi-line Output",id:"08-challenge-multi-line-output",level:3},{value:"09: Challenge: <code>execve</code> blocking attempt",id:"09-challenge-execve-blocking-attempt",level:3},{value:"Further Reading",id:"further-reading",level:2},{value:"Input restrictions",id:"input-restrictions",level:3}],c={toc:p},h="wrapper";function d(e){let{components:n,...t}=e;return(0,i.yg)(h,(0,a.A)({},c,t,{components:n,mdxType:"MDXLayout"}),(0,i.yg)("h1",{id:"shellcodes-advanced"},"Shellcodes (Advanced)"),(0,i.yg)("p",null,"In ",(0,i.yg)("a",{parentName:"p",href:"../../Shellcodes/Reading"},'the "Shellcodes" session'),", we learned about ",(0,i.yg)("strong",{parentName:"p"},"shellcodes"),", a form of ",(0,i.yg)("strong",{parentName:"p"},"code injection")," which allowed us to hijack the control flow of a process and make it do our bidding."),(0,i.yg)("h2",{id:"introduction"},"Introduction"),(0,i.yg)("p",null,"The three steps for a successful shellcode attack are:"),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("strong",{parentName:"li"},"develop"),": obtain the machine code for the desired functionality"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("strong",{parentName:"li"},"inject"),": place the shellcode into the process' address space"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("strong",{parentName:"li"},"trigger"),": divert control flow to the beginning of our shellcode")),(0,i.yg)("p",null,"The first step seems pretty straightforward, but there are a lot of things that could go wrong with the last two.\nFor example, we cannot inject a shellcode in a process that doesn't read input or reads very little (though remember that if we can launch the target program we can place the shellcode inside its environment or command-line arguments);\nwe cannot trigger our shellcode if we cannot overwrite some code-pointer (e.g.\na saved return) or if we do not know the precise address at which it ends up in the process' memory and we cannot use such an attack if there isn't some memory region where we have both write and execute permissions."),(0,i.yg)("p",null,"Some of these hurdles can occur naturally, while others are intentionally created as preventive measures (e.g.\non modern platforms, any memory area can be either writable or executable, but not both, a concept known as ",(0,i.yg)("a",{parentName:"p",href:"https://en.wikipedia.org/wiki/W%5EX"},"W^X"),").\nAnyway, it is useful to think about these problems and how to work around them, then put that knowledge into practice."),(0,i.yg)("h2",{id:"tutorials"},"Tutorials"),(0,i.yg)("h3",{id:"01-tutorial-preventing-stack-operations-from-overwriting-the-shellcode"},"01. Tutorial: preventing stack operations from overwriting the shellcode"),(0,i.yg)("p",null,"When performing a shellcode attack we often needed to write some stuff in memory so that it has a valid address.\nFor example, to perform an ",(0,i.yg)("inlineCode",{parentName:"p"},'execve("/bin/sh", ["/bin/sh", NULL], NULL)')," syscall, we need to place the string ",(0,i.yg)("inlineCode",{parentName:"p"},'"/bin/sh"')," in  memory and fill the ",(0,i.yg)("inlineCode",{parentName:"p"},"rdi")," register (first argument of a syscall) with that address.\nIn theory we could write it in any writable area but, as you might have noticed in the previous session, it's usually simpler to just use the stack."),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"    mov rax, `/bin/sh`\n    push rax\n\n")),(0,i.yg)("p",null,"results in fewer machine-code bytes than:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"    mov rax, `/bin/sh`\n    mov rbx, 0x00404000\n    mov qword [rbx], rax\n")),(0,i.yg)("p",null,"plus, ",(0,i.yg)("inlineCode",{parentName:"p"},"push"),"-ing has the side effect of placing our address in the ",(0,i.yg)("inlineCode",{parentName:"p"},"rsp")," register which we could later ",(0,i.yg)("inlineCode",{parentName:"p"},"mov")," somewhere else, avoiding the need of explicitly referring to some address (which might be difficult to predict, or even random, in the case of ASLR)."),(0,i.yg)("p",null,"In cases where our shellcode is also injected on the stack this leads to the complicated situation in which the stack serves as both a code and data region.\nIf we aren't careful, our data pushes might end up overwriting the injected code and ruining our attack."),(0,i.yg)("p",null,"Run ",(0,i.yg)("inlineCode",{parentName:"p"},"make")," then use the ",(0,i.yg)("inlineCode",{parentName:"p"},"exploit.py")," script (don't bother with how it works, for now);\nit will create a shellcode, pad it and feed it to the program, then open a new terminal window with a ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," instance break at the end of the ",(0,i.yg)("inlineCode",{parentName:"p"},"main")," function.\nYou can then explore what happens step by step and you will notice that, as the shellcode pushes the data it needs onto the stack it eventually comes to overwrite itself, resulting in some garbage."),(0,i.yg)("p",null,"The problem is that, after executing ",(0,i.yg)("inlineCode",{parentName:"p"},"ret")," at the end of ",(0,i.yg)("inlineCode",{parentName:"p"},"main")," and getting hijacked to jump to the beginning of our shellcode, ",(0,i.yg)("inlineCode",{parentName:"p"},"rip")," ends up at ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7ffca44f2280"),", while ",(0,i.yg)("inlineCode",{parentName:"p"},"rsp")," ends up at ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7ffca44f22c0")," (addresses on your machine will probably differ).\nThe instruction pointer is only 64 bytes ",(0,i.yg)("strong",{parentName:"p"},"below")," the stack pointer."),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"as instructions get executed, the instruction pointer is incremented"),(0,i.yg)("li",{parentName:"ul"},"as values are pushed onto the stack, the stack pointer is decremented")),(0,i.yg)("p",null,"Thus the difference will shrink more and more with each instruction executed.\nThe total length of the shellcode is 48 bytes so that means that after pushing 16 bytes onto the stack (64 - 48) any ",(0,i.yg)("inlineCode",{parentName:"p"},"push")," will overwrite the end of our shellcode!"),(0,i.yg)("p",null,"One obvious solution is to try and modify our shellcode to make it shorter, or to make it push less data onto the stack;\nthis might work in some situations, but it's not a general fix."),(0,i.yg)("p",null,"Remember that after the vulnerable function returns, we control the execution of the program;\nso we can control what happens to the stack!\nThen we'll simply move the top of the stack to give us some space by adding this as the first instruction to our shellcode:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"  sub rsp, 64\n")),(0,i.yg)("p",null,"Now, right after jumping to our shellcode, ",(0,i.yg)("inlineCode",{parentName:"p"},"rip")," and ",(0,i.yg)("inlineCode",{parentName:"p"},"rsp")," will be the same, but they'll go on in opposite directions and everything will be well.\nUncomment line 64 in ",(0,i.yg)("inlineCode",{parentName:"p"},"exploit.py"),", run it again and see what happens."),(0,i.yg)("p",null,"If we're at the very low-edge of the stack and can't access memory below, we can use ",(0,i.yg)("inlineCode",{parentName:"p"},"add")," to move the stack pointer way up, so that even if the pushed data comes towards our injected code, it will not reach it;\nafter all, our shellcode is short and we're not pushing much."),(0,i.yg)("h3",{id:"02-tutorial-nop-sleds"},"02. Tutorial: NOP sleds"),(0,i.yg)("p",null,"In the previous session, you probably had some difficulties with the 9th task in ",(0,i.yg)("a",{parentName:"p",href:"../../Shellcodes/Reading"},'the "Shellcodes" section'),", which asked you to perform a shellcode-on-stack attack without having a leak of the overflown buffer's address.\nYou can determine it using ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," but, as you've seen, things differ between ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," and non-",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," environments;\nthe problem is even worse if the target binary is running on a remote machine."),(0,i.yg)("p",null,"The crux of the issue is the fact that we have to precisely guess ",(0,i.yg)("strong",{parentName:"p"},"one")," exact address where our shellcode begins.\nFor example, our shellcode might end up looking like this in memory:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-text"},"   0x7fffffffce28:  rex.WX adc QWORD PTR [rax+0x0],rax\n   0x7fffffffce2c:  add    BYTE PTR [rax],al\n   0x7fffffffce2e:  add    BYTE PTR [rax],al\n=> 0x7fffffffce30:  push   0x68\n   0x7fffffffce32:  movabs rax,0x732f2f2f6e69622f\n   0x7fffffffce3c:  push   rax\n   0x7fffffffce3d:  mov    rdi,rsp\n   0x7fffffffce40:  push   0x1016972\n")),(0,i.yg)("p",null,"The first instruction of our shellcode is the ",(0,i.yg)("inlineCode",{parentName:"p"},"push 0x68")," at address ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7fffffffce30"),":"),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"if we jump before it, we'll execute some garbage interpreted as code;\nin the above example, missing it by two bytes would execute ",(0,i.yg)("inlineCode",{parentName:"li"},"add    BYTE PTR [rax],al")," which might SEGFAULT if ",(0,i.yg)("inlineCode",{parentName:"li"},"rax")," doesn't happen to hold a valid writable address"),(0,i.yg)("li",{parentName:"ul"},"if we jump after it, we'll have a malformed ",(0,i.yg)("inlineCode",{parentName:"li"},'"/bin/sh"')," string on the stack, so the later ",(0,i.yg)("inlineCode",{parentName:"li"},"execve")," call will not work.")),(0,i.yg)("p",null,"Fortunately, we don't have to consider the entire address space, so our chances are better than 1 in $2^64$."),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"the stack is usually placed at a fixed address (e.g. ",(0,i.yg)("inlineCode",{parentName:"li"},"0x7fffffffdd000"),"), so we have a known-prefix several octets wide"),(0,i.yg)("li",{parentName:"ul"},"due to alignment concerns, the compiler emits code that places buffers and other local data at nice, rounded addresses (ending in ",(0,i.yg)("inlineCode",{parentName:"li"},"0"),", or ",(0,i.yg)("inlineCode",{parentName:"li"},"c0"),", ",(0,i.yg)("inlineCode",{parentName:"li"},"00")," etc.), so we have a known-suffix several bits wide")),(0,i.yg)("p",null,"On your local machine, using ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," to look at the buffer's address will then allow you to use just a bit of brute-force search to determine the address outside of ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb"),"."),(0,i.yg)("p",null,"But what if we could increase our chances to jump to the beginning of our shellcode?\nSo that we don't have to guess ",(0,i.yg)("strong",{parentName:"p"},"one"),' exact address, but just hit some address range?\nThis is where "NOP sleds" come in.'),(0,i.yg)("p",null,'A "NOP sled" is simply a string of ',(0,i.yg)("inlineCode",{parentName:"p"},"NOP")," instructions added as a prefix to a shellcode.\nThe salient features of a ",(0,i.yg)("inlineCode",{parentName:"p"},"NOP")," instruction that make it useful for us are:"),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"it does nothing"),(0,i.yg)("li",{parentName:"ul"},"it's one byte long")),(0,i.yg)("p",null,'Thus if we chain a bunch of these together and prepend them to our shellcode, we can jump inside the middle of the "NOP sled" at any position and it will be alright: each subsequent ',(0,i.yg)("inlineCode",{parentName:"p"},"NOP")," instruction will be executed, doing nothing, then our shellcode will be reached."),(0,i.yg)("p",null,"Our shellcode will end up looking like this in the process memory:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-text"},"   0x7fffffffd427:  mov BYTE PTR [rax], al\n   0x7fffffffd429:  nop\n   0x7fffffffd42a:  nop\n   0x7fffffffd42b:  nop\n   0x7fffffffd42c:  nop\n   0x7fffffffd42d:  nop\n   0x7fffffffd42e:  nop\n   0x7fffffffd42f:  nop\n=> 0x7fffffffd430:  push   0x68\n   0x7fffffffd432:  movabs rax,0x732f2f2f6e69622f\n   0x7fffffffd43c:  push   rax\n")),(0,i.yg)("p",null,'Again, our first "useful" instruction is the ',(0,i.yg)("inlineCode",{parentName:"p"},"push 0x68")," at ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7fffffffd430"),".\nJumping after it and skipping its execution is still problematic, but notice that we can now jump ",(0,i.yg)("strong",{parentName:"p"},"before")," it, missing it by several bytes with no issue.\nIf we jump to ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7fffffffd42c")," for example, we'll reach a ",(0,i.yg)("inlineCode",{parentName:"p"},"nop"),", then execution will pass on to the next ",(0,i.yg)("inlineCode",{parentName:"p"},"nop")," and so on;\nafter executing 4 ",(0,i.yg)("inlineCode",{parentName:"p"},"NOPs"),", our shellcode will be reached and everything will be as if we had jumped directly to ",(0,i.yg)("inlineCode",{parentName:"p"},"0x7fffffffd430")," in the first place.\nThere is now a continuous range of 8 addresses where it's OK to jump to."),(0,i.yg)("p",null,"But 8 is such a small number;\nthe longer the NOP sled, the better our chances.\nThe only limit is how much data we can feed into the program when we inject our shellcode."),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"Run ",(0,i.yg)("inlineCode",{parentName:"li"},"make"),", then inspect the ",(0,i.yg)("inlineCode",{parentName:"li"},"vuln")," binary in ",(0,i.yg)("inlineCode",{parentName:"li"},"gdb")," and determine the location of the vulnerable buffer."),(0,i.yg)("li",{parentName:"ul"},"Modify line 14 of the ",(0,i.yg)("inlineCode",{parentName:"li"},"exploit.py")," script with the address you've found, then run the script.\nMost likely, it will not work: the address outside of ",(0,i.yg)("inlineCode",{parentName:"li"},"gdb")," is different."),(0,i.yg)("li",{parentName:"ul"},"Uncomment line 17 of the script, then run it again."),(0,i.yg)("li",{parentName:"ul"},"You should now have a shell!")),(0,i.yg)("p",null,"If this doesn't work, play a bit with the address left on line 14;\nincrement it by 256, then decrement it by 256.\nYou're aiming to get ",(0,i.yg)("strong",{parentName:"p"},"below")," the actual address at some offset smaller than the NOP sled length which, in this example, is 1536."),(0,i.yg)("h3",{id:"03-tutorial-null-free-shellcodes"},"03. Tutorial: null-free shellcodes"),(0,i.yg)("p",null,"Up until now, all the vulnerable programs attacked used ",(0,i.yg)("inlineCode",{parentName:"p"},"read")," as a method of getting the input.\nThis allows us to feed them any string of arbitrary bytes.\nIn practice, however, there are many cases in which the input is treated as a 0-terminated string and processed by functions like ",(0,i.yg)("inlineCode",{parentName:"p"},"strcpy"),"."),(0,i.yg)("p",null,"This means that our shellcode cannot contain a 0 byte because, as far as functions like ",(0,i.yg)("inlineCode",{parentName:"p"},"strcpy")," are concerned, that signals the end of the input.\nHowever, shellcodes are likely to contain 0 bytes.\nFor example, remember that we need to set ",(0,i.yg)("inlineCode",{parentName:"p"},"rax")," to a value indicating the syscall we want;\nif we wish to ",(0,i.yg)("inlineCode",{parentName:"p"},"execve")," a new shell, we'll have to place the value ",(0,i.yg)("inlineCode",{parentName:"p"},"59")," in ",(0,i.yg)("inlineCode",{parentName:"p"},"rax"),":"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"  mov rax, 0x3b\n")),(0,i.yg)("p",null,"Due to the nature of x86 instructions and the size of the ",(0,i.yg)("inlineCode",{parentName:"p"},"rax")," register, that ",(0,i.yg)("inlineCode",{parentName:"p"},"0x3b")," might be considered an 8-byte wide constant, yielding the following machine code: ",(0,i.yg)("inlineCode",{parentName:"p"},"48 b8 59 00 00 00 00 00 00 00"),"."),(0,i.yg)("p",null,"As you can see, there are quite a lot of zeroes.\nWe could get rid of them if we considered ",(0,i.yg)("inlineCode",{parentName:"p"},"0x3b")," to be a 1-byte wide constant;\nunfortunately there's no instruction to place into ",(0,i.yg)("inlineCode",{parentName:"p"},"rax")," an immediate 1-byte value.\nHowever, there is an instruction to place an immediate 1-byte value in ",(0,i.yg)("inlineCode",{parentName:"p"},"al"),", the lowest octet of ",(0,i.yg)("inlineCode",{parentName:"p"},"rax"),".\nBut we need the other seven octets to be 0...\nFortunately, we can do a trick by xor-ing the register with itself!\nThis will make every bit 0, plus the ",(0,i.yg)("inlineCode",{parentName:"p"},"xor")," instruction itself doesn't contain 0 bytes.\nSo we can replace the code above with:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"  xor rax, rax\n  mov al, 0x3b\n")),(0,i.yg)("p",null,"Which assembles to ",(0,i.yg)("inlineCode",{parentName:"p"},"48 31 c0 b0 3b"),".\nNot only are there no 0 bytes, we've also reduced the size of the code!"),(0,i.yg)("p",null,"Takeaways:"),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"xor-ing a register with itself is a good way of obtaining some zeroes in memory without using zeroes in machine code"),(0,i.yg)("li",{parentName:"ul"},"working with the lower parts of registers avoids immediate values with leading-zeroes")),(0,i.yg)("p",null,"We can apply these insights in other situations to avoid zeroes in our code.\nFor example, instead of"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"    mov rax, `/bin/sh\\0`\n    push rax\n")),(0,i.yg)("p",null,"We can write:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-asm"},"    xor rax, rax\n    push rax\n    mov rax, `//bin/sh`\n    push rax\n")),(0,i.yg)("p",null,"Note that extra-slashes in a path don't make any difference."),(0,i.yg)("p",null,"The ",(0,i.yg)("inlineCode",{parentName:"p"},"vuln.c")," program reads data properly into a buffer, then uses ",(0,i.yg)("inlineCode",{parentName:"p"},"strcpy")," to move data into a smaller buffer, resulting in an overflow.\nRun ",(0,i.yg)("inlineCode",{parentName:"p"},"make"),", then the ",(0,i.yg)("inlineCode",{parentName:"p"},"exploit.py")," script;\njust like before, it will start a new terminal window with a ",(0,i.yg)("inlineCode",{parentName:"p"},"gdb")," instance in which you can explore what happens.\nThe attack will fail because the injected shellcode contains 0 bytes so ",(0,i.yg)("inlineCode",{parentName:"p"},"strcpy")," will only stop copying well before the end of the shellcode."),(0,i.yg)("p",null,"Comment line 55 and uncomment line 56, replacing the shellcode with a null-free version.\nRun ",(0,i.yg)("inlineCode",{parentName:"p"},"exploit.py")," again.\nIt should work!"),(0,i.yg)("h3",{id:"04-tutorial-shellcodes-in-pwntools"},"04. Tutorial: shellcodes in pwntools"),(0,i.yg)("p",null,"Once again, ",(0,i.yg)("inlineCode",{parentName:"p"},"pwntools")," can come to our aid and help us with shellcode attacks.\nThe most useful feature for this is the ",(0,i.yg)("a",{parentName:"p",href:"https://docs.pwntools.com/en/stable/shellcraft.html"},(0,i.yg)("inlineCode",{parentName:"a"},"shellcraft")," module")," which offers prebuilt shellcodes for various architectures."),(0,i.yg)("p",null,"For example, to obtain a shellcode which performs ",(0,i.yg)("inlineCode",{parentName:"p"},'execve("/bin/sh", {"/bin/sh", NULL}, NULL)')," on an ",(0,i.yg)("inlineCode",{parentName:"p"},"x86_64")," platform we can call:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-python"},"shellcraft.amd64.linux.sh()\n")),(0,i.yg)("p",null,"Note that this will give you back text representing assembly code and ",(0,i.yg)("strong",{parentName:"p"},"not")," machine code bytes.\nYou can then use the ",(0,i.yg)("inlineCode",{parentName:"p"},"asm")," function to assemble it:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-python"},'asm(shellcraft.amd64.linux.sh(), arch="amd64", os="linux"))\n')),(0,i.yg)("p",null,"Remember the friendly features of pwntools!\nInstead of always specifying the OS and the architecture, we can set them in the global context, like this:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-python"},'context.arch="amd64"\ncontext.os="linux"\n')),(0,i.yg)("p",null,"Or - even simpler - we can indicate a particular binary and let pwntools deduce the OS and architecture: ",(0,i.yg)("inlineCode",{parentName:"p"},'context.binary = "./vuln"'),".\nWe can then invoke a much cleaner ",(0,i.yg)("inlineCode",{parentName:"p"},"asm(shellcraft.sh())"),"."),(0,i.yg)("p",null,"Besides the magic snippet to invoke a shell, there are other built-in code fragments, such as to cause a crash, an infinite loop, ",(0,i.yg)("inlineCode",{parentName:"p"},"cat")," a file or call some other syscall.\nPlay around with ",(0,i.yg)("inlineCode",{parentName:"p"},"shellcraft"),", inspecting the output.\nYou'll notice that all these shellcodes are free of zero bytes and newlines!"),(0,i.yg)("h3",{id:"05-tutorial-alphanumeric-shellcode"},"05. Tutorial: alphanumeric shellcode"),(0,i.yg)("p",null,'It is commonly the case that user input is filtered to make sure it matches certain conditions.\nMost user input expected from a keyboard should not contain non-printable characters;\na "name" should contain only letters, a PIN should contain only digits, etc.'),(0,i.yg)("p",null,"The program might check its input against some conditions and, if rejected, bail in such a way so as to not trigger our injected code.\nThis places the burden on us to develop shellcode that doesn't contain certain bytes.\nWe've seen how we can avoid newlines and zero bytes to work around some input-reading functions.\nThis concept can be pushed even further, heavily restricting our character set: on 32-bit platforms, we can write ",(0,i.yg)("strong",{parentName:"p"},"alphanumeric shellcodes"),"!"),(0,i.yg)("p",null,"But can we really?\nIt's plausible that there are some clever tricks on the level of replacing ",(0,i.yg)("inlineCode",{parentName:"p"},"mov eax, 0x3b")," with ",(0,i.yg)("inlineCode",{parentName:"p"},"xor eax, eax; mov al, 0x3b")," that could make use of only alphanumeric characters, but all our shellcodes so far need to perform a syscall.\nLooking at the encoding of the ",(0,i.yg)("inlineCode",{parentName:"p"},"int 0x80")," instruction seems pretty grim: ",(0,i.yg)("inlineCode",{parentName:"p"},"\\xcd\\x80"),".\nThose are not even printable characters.\nSo how can we perform a syscall?"),(0,i.yg)("p",null,"Here it's important to step back and carefully consider our assumptions:"),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},"There is some memory region to which we have both write and execute access (otherwise we wouldn't attempt a code injection attack)"),(0,i.yg)("li",{parentName:"ul"},"After our input is read, there is some check on it to make sure it doesn't contain certain characters.")),(0,i.yg)("p",null,"Aha!\nWe cannot ",(0,i.yg)("strong",{parentName:"p"},"inject")," some bytes, but nothing's stopping us from injecting something that ",(0,i.yg)("strong",{parentName:"p"},"generates")," those bytes!\nGenerating is just an alternative way of writing, so instead of ",(0,i.yg)("strong",{parentName:"p"},"injecting")," our shellcode, we'll inject some code which ",(0,i.yg)("strong",{parentName:"p"},"generates")," the shellcode, then executes it!"),(0,i.yg)("p",null,"This is, in fact, as complicated as it sounds, so we won't do it ourselves.\nWe'll just observe how such a shellcode, produced by a specialized tool (",(0,i.yg)("inlineCode",{parentName:"p"},"msfvenom"),') works.\nSo invoke the following command, which should give you a python-syntax buffer containing an alphanumeric shellcode that executes "/bin/sh":'),(0,i.yg)("p",null,(0,i.yg)("inlineCode",{parentName:"p"},"msfvenom -a x86 --platform linux -p linux/x86/exec -e x86/alpha_mixed BufferRegister=ECX -f python")),(0,i.yg)("ul",null,(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"-a x86"),": specifies the architecture as 32-bit x86"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"--platform linux"),": specifies OS"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"-p linux/x86/exec"),": specifies a preset program (you can use ",(0,i.yg)("inlineCode",{parentName:"li"},"-")," or ",(0,i.yg)("inlineCode",{parentName:"li"},"stdin")," for a custom initial shellcode, to be transformed)"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"-e x86/alpha_mixed"),": specifies encoding to be alphanumeric"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"BufferRegister=ECX"),": specifies an initial register which holds the address of the buffer;\nthis is needed in order to have some way to refer to the region in which we're unpacking our code.\nWithout this, a short non-alphanumeric preamble is added instead to automatically extract the buffer address"),(0,i.yg)("li",{parentName:"ul"},(0,i.yg)("inlineCode",{parentName:"li"},"-f python"),": formats output using python syntax")),(0,i.yg)("p",null,(0,i.yg)("inlineCode",{parentName:"p"},"msfvenom")," is actually capable of taking an arbitrary assembly snippet and transforming it into an alphanumeric ",(0,i.yg)("inlineCode",{parentName:"p"},'"bootstrapper"')," which, once injected, unpacks the original shellcode and executes it."),(0,i.yg)("h2",{id:"challenges"},"Challenges"),(0,i.yg)("h3",{id:"06-challenge-nop-sled-redo"},"06. Challenge: ",(0,i.yg)("inlineCode",{parentName:"h3"},"NOP"),"-sled Redo"),(0,i.yg)("p",null,"Redo the last three challenges (9, 10, 11) from ",(0,i.yg)("a",{parentName:"p",href:"../../Shellcodes/Reading"},'the "Shellcodes" session')," using NOP-sleds."),(0,i.yg)("h3",{id:"07-challenge-no-nops-allowed"},"07. Challenge: No ",(0,i.yg)("inlineCode",{parentName:"h3"},"NOPs")," Allowed"),(0,i.yg)("p",null,"This is similar to the previous tasks: you are left to guess a stack address.\nHowever, the ",(0,i.yg)("inlineCode",{parentName:"p"},"\\x90"),' byte is filtered from input so you cannot use a NOP sled.\nBut you should be able to adapt the concept.\nRemember the relevant features of the "NOP" instruction!'),(0,i.yg)("h3",{id:"08-challenge-multi-line-output"},"08. Challenge: Multi-line Output"),(0,i.yg)("p",null,"While perfectly OK with the byte 0, some functions (e.g.\n",(0,i.yg)("inlineCode",{parentName:"p"},"fgets"),") will stop reading when they encounter a newline character (",(0,i.yg)("inlineCode",{parentName:"p"},"\\n"),").\nThus, if our input is read by such a function, we need to make sure our shellcode contains no ",(0,i.yg)("inlineCode",{parentName:"p"},"\\n")," bytes."),(0,i.yg)("p",null,"For this challenge, the input will be read using the ",(0,i.yg)("inlineCode",{parentName:"p"},"gets")," function, but you will need to craft a shellcode which prints to ",(0,i.yg)("inlineCode",{parentName:"p"},"stdout")," the exact string:"),(0,i.yg)("pre",null,(0,i.yg)("code",{parentName:"pre",className:"language-text"},"first\nsecond\nthird\n")),(0,i.yg)("h3",{id:"09-challenge-execve-blocking-attempt"},"09: Challenge: ",(0,i.yg)("inlineCode",{parentName:"h3"},"execve")," blocking attempt"),(0,i.yg)("p",null,"If shellcodes are such a powerful threat, what if we attempted to block some shellcode-specific characters?\nSuch as the bytes that encode a ",(0,i.yg)("inlineCode",{parentName:"p"},"syscall")," function.\nOr the slash needed in a path;\nmaybe it's not such a big loss to avoid these in legitimate inputs."),(0,i.yg)("p",null,"Can you still get a shell?\nFor this task, ",(0,i.yg)("strong",{parentName:"p"},"don't use")," an existing encoder, but rather apply the encoding principles yourself."),(0,i.yg)("h2",{id:"further-reading"},"Further Reading"),(0,i.yg)("p",null,(0,i.yg)("a",{parentName:"p",href:"http://phrack.org/issues/49/14.html"},'"Smashing The Stack For Fun And Profit", Aleph One')," - a legendary attack paper documenting stack buffer overflows and shellcodes.\nAs it is written in '96, the examples in it will probably ",(0,i.yg)("strong",{parentName:"p"},"not")," work (either out-of-the-box or with some tweaks).\nWe recommend perusing it for its historical/cultural significance, but don't waste much time on the technical details of the examples."),(0,i.yg)("h3",{id:"input-restrictions"},"Input restrictions"),(0,i.yg)("p",null,"The following articles deal with restrictions on the shellcode structure, such as forbidden characters or statistical properties of the input string.\nThe examples presented will most likely not work as-they-are in a modern environment, so don't focus on the technical details, but rather on the methodology presented."),(0,i.yg)("p",null,(0,i.yg)("a",{parentName:"p",href:"http://phrack.org/issues/57/15.html"},(0,i.yg)("em",{parentName:"a"},"Writing ia32 alphanumeric shellcodes"),", 2001 - ",(0,i.yg)("inlineCode",{parentName:"a"},"rix"))," - probably the first comprehensive presentation of how to automatically convert generic shellcodes to alphanumeric ones."),(0,i.yg)("p",null,(0,i.yg)("a",{parentName:"p",href:"http://phrack.org/issues/61/11.html"},(0,i.yg)("em",{parentName:"a"},"Building IA32 'Unicode-Proof' Shellcodes"),", 2003 - ",(0,i.yg)("inlineCode",{parentName:"a"},"obscou"))," - rather than being concerned with input restrictions, this addresses ulterior transformations on input, namely converting an ASCII string to a UTF-16 one (as mentioned in the article's introduction, you could also imagine other possible transformations, such as case normalization)."),(0,i.yg)("p",null,(0,i.yg)("a",{parentName:"p",href:"http://phrack.org/issues/62/9.html"},(0,i.yg)("em",{parentName:"a"},"Writing UTF-8 compatible shellcodes"),", 2004 - ",(0,i.yg)("inlineCode",{parentName:"a"},"Wana"))),(0,i.yg)("p",null,(0,i.yg)("a",{parentName:"p",href:"https://www.cs.jhu.edu/~sam/ccs243-mason.pdf"},(0,i.yg)("em",{parentName:"a"},"English shellcode"),", 2009 - Mason, Small, Monrose, MacManus")," delves into automatically generating shellcode which has the same statistical properties as English text."))}d.isMDXComponent=!0}}]);