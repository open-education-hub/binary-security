#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int x = atoi(argv[1]);
	size_t sx = x;

	printf("%%d (int): %d %d\n", x, x * sizeof(int));
	printf("%%u (int): %u %u\n", x, x * sizeof(int));
	printf("%%x (int): %x %x\n", x, x * sizeof(int));
	printf("%%d (size_t): %d %d\n", sx, sx * sizeof(int));
	printf("%%u (size_t): %u %u\n", sx, sx * sizeof(int));
	printf("%%x (size_t): %x %x\n", sx, sx * sizeof(int));

	return 0;
}
