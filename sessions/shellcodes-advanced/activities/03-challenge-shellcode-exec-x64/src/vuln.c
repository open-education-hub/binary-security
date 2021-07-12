#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Byte string shellcode for exiting with exit code 42 */
static const char shellcode[] = "\xbb\x2a\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80";

int main()
{
	void (*func_ptr)(void) = (void (*)(void)) shellcode;

	printf("Nice function at %p\n", func_ptr);

	/* Call shellcode. */
	func_ptr();

	printf("Afterwards.\n");

	return 0;
}
