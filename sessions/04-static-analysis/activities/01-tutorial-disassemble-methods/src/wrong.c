#include <stdio.h>

int main()
{
	asm volatile(
		"A: jmp B\n\t"
		".byte 0xde\n\t"
		".byte 0xad\n\t"
		".byte 0xc0\n\t"
		".byte 0xde\n\t"
		"jmp -1\n\t"
		"B:\n\t"
	);
	printf("What is wrong with me :-s?\n");
	return -1;
}
