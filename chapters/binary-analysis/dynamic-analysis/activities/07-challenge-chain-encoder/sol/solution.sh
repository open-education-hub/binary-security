

echo -e "password\nadmin123" > payload
cat payload - | ./encoder # cat payload - | nc <ip>:42069	#cat /home/ctf/flag
rm payload
