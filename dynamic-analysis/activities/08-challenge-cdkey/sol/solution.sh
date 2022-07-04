

echo "SSS_CTF{IS_THIS_THE_REAL_FLAG}" > payload
cat payload - | ./encoder # cat payload - | nc <ip>:42069	#cat /home/ctf/flag
rm payload
