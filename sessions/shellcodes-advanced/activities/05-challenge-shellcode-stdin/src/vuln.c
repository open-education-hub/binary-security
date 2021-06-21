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

int main(void)
{
	void (*func_ptr)(void);
	char shellcode[128];

	printf("Gimme input: ");
	fgets(shellcode, 128, stdin);
	if (shellcode[strlen(shellcode)-1] == '\n')
		shellcode[strlen(shellcode)-1] = '\0';

	printf("Program input is: ");
	print_hex(shellcode, strlen(shellcode));
	printf("\n");

	/* Call shellcode. */
	func_ptr = (void (*)(void)) shellcode;
	func_ptr();

	printf("Afterwards.\n");

	return 0;
}
