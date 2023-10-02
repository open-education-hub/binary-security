set disassembly-flavor intel
file ssp
break *0x804844c
commands
p/x $eax
c
end
run
quit
