#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char shellcode[128];

static void vuln(void)
{
	char input[17];

	printf("Give me shellcode: ");
	fgets(shellcode, 128, stdin);

	printf("Give me input: ");
	fgets(input, 128, stdin);
}

int main(void)
{
	vuln();
	return 0;
}
