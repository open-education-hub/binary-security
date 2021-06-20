#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	int x = atoi(argv[1]);
	size_t sx = x;

	printf("%%d (int): %d\n", x);
	printf("%%u (int): %u\n", x);
	printf("%%x (int): %x\n", x);
	printf("%%d (size_t): %d\n", sx);
	printf("%%u (size_t): %u\n", sx);
	printf("%%x (size_t): %x\n", sx);

	return 0;
}
