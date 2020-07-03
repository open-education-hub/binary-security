#include <stdio.h>

#define SHIFT 11

void caesar(unsigned char *s) {

	while (*s) {
		*s += SHIFT;
		if (*s > 'z')
			*s -= 'z' - 'A' + 1;
		s++;
	}
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return -1;

	printf("dummy: %c\n", *argv[2]);
	printf("plaintext: %s\n", argv[1]);
	caesar((unsigned char *)argv[1]);
	printf("caesar: %s\n", argv[1]);

	return 0;
}


