#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int verify(const char *str)
{
	char buf[] = "Where is the shell?";
	int n;

	return strncmp(buf, str, strlen(buf + n)) == 0;
}

static void foo(void)
{
	char buf[1024];
	char num[8];
	unsigned long int n;

	fgets(num, 8, stdin);
	n = atoi(num);

	if (fgets(buf + n, 16, stdin) == NULL) {
		perror("fgets");
		exit(EXIT_FAILURE);
	}

	if (verify(buf))
		system("/bin/sh");
}

int main(void)
{
	foo();

	return 0;
}
