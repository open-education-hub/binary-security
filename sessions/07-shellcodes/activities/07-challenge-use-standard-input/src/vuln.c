#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68"
				"\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89"
				"\xe1\x31\xd2\xb0\x0b\xcd\x80";

static void do_nothing_successfully(const char *str)
{
	int state = 3;
	char buffer[70];
	strcpy(buffer, str);

	/* Dumb thing to use state. */
	if (buffer[0] % 8 == state)
		buffer[0] = 'a';
}

int main(void)
{
	char input_buffer[128];

	fgets(input_buffer, 128, stdin);
	do_nothing_successfully(input_buffer);

	return 0;
}
