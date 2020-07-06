#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void win(void)
{
	printf("Congrats!\n");
}

static void vuln(void)
{
	char *msg = "Hello! Gimme input: ";
	size_t i = 50;
	char input[64];

	printf("Have a number: %zu\n", i);
	printf("%s", msg);
	fgets(input, 256, stdin);

	printf("Glad to meet you!\n");
}

int main(void)
{
	vuln();
	return 0;
}
