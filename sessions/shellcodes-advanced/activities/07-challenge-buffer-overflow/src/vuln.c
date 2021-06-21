#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void win(void)
{
	printf("Congrats!\n");
}

static void vuln(void)
{
	char input[80];

	printf("Give me input: ");
	fgets(input, 256, stdin);

	printf("Glad to meet you!\n");
}

int main(void)
{
	vuln();
	return 0;
}
