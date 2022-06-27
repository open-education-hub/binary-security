#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int fibonacci(unsigned int n)
{
	if (n <= 1)
		return 1;
	return fibonacci(n-1) + fibonacci(n-2);
}

static int validate_password(const char *pass)
{
	size_t i;

	for (i = 0; i < 24; i++)
		if (pass[i] != ('A' + (fibonacci(i) % ('z'-'A'))))
			return 0;

	return 1;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s <password>\n", argv0);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strlen(argv[1]) != 24) {
		fprintf(stderr, "Wrong password size.\n");
		exit(EXIT_FAILURE);
	}

	if (validate_password(argv[1]))
		printf("That's correct! The password is '%s'\n", argv[1]);
	else
		printf("Password '%s' is incorrect. Try again.\n", argv[1]);

	return 0;
}
