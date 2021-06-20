#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void do_nothing_successfully(const char *str)
{
	char buffer[32];

	strcpy(buffer, str);
}

int main(void)
{
	char input_buffer[128];

	printf("Provide input data: ");
	fgets(input_buffer, 128, stdin);
	do_nothing_successfully(input_buffer);

	return 0;
}
