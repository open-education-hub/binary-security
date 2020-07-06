#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void vuln(void)
{
	size_t n = 100;
	char c = 'a';
	char v[13];
	char input[72];

	setvbuf(stdout, NULL, _IONBF, 0);

	printf("Have char %c and number %zu\n", c, n);

	printf("Give me input: ");
	fgets(v, 10, stdin);

	printf("Give me another input: ");
	fgets(input, 256, stdin);
}

int main(void)
{
	vuln();
	return 0;
}
