#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void print_hex(const char *msg, size_t len)
{
	size_t i;

	printf("[ ");
	for (i = 0; i < len; i++)
		printf("0x%02x ", (unsigned char) msg[i]);
	printf("]");
}

int main(int argc, char **argv)
{
	void (*func_ptr)(void);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	printf("Program argument is: ");
	print_hex(argv[1], strlen(argv[1]));
	printf("\n");

	/* Call shellcode. */
	func_ptr = (void (*)(void)) argv[1];
	func_ptr();

	printf("Afterwards.\n");

	return 0;
}
