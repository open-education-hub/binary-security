#include <stdio.h>
#include <stdlib.h>

void clear_stdin(void)
{
	char x = 0;
	while (1) {
		x = getchar();
		if (x == '\n' || x == EOF)
			break;
	}
}

void print_banner(void)
{
	printf("################################################################################\n");
	printf("Welcome to the Simple Storage Service!\n");
	printf("You can store any value anywhere!\n");
	printf("################################################################################\n");
	fflush(stdout);
}

void get_shell()
{
	system("/bin/sh");
}

void f(unsigned int* storage)
{
	unsigned int index;
	unsigned int value;
	print_banner();

	/* Read index */
	printf("Index: ");
	fflush(stdout);
	scanf("%u", &index);
	clear_stdin();

	/* Read value */
	printf("Value: ");
	fflush(stdout);
	scanf("%u", &value);
	clear_stdin();

	storage[index] = value;
	puts("Ok, have fun!\n");
}

int main(int argc, char* argv[])
{
	unsigned int storage[32];
	f(storage);
	return 0;
}
