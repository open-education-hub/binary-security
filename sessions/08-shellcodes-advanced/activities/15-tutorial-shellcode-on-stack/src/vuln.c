#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void vuln(void)
{
	char input[72];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("Give me input: ");
	fgets(input, 128, stdin);
}

int main(void)
{
	vuln();
	return 0;
}
