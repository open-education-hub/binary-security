#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Byte string shellcode for printing "Hello, World!" */
static const char shellcode[] = "\x68\x21\x0a\x00\x00\x68\x6f\x72\x6c"
				 "\x64\x68\x6f\x2c\x20\x57\x68\x48\x65"
				 "\x6c\x6c\xba\x0e\x00\x00\x00\x89\xe1"
				 "\xbb\x01\x00\x00\x00\xb8\x04\x00\x00"
				 "\x00\xcd\x80";

int main()
{
	void (*func_ptr)(void) = (void (*)(void)) shellcode;

	/* Call shellcode. */
	func_ptr();

	return 0;
}
