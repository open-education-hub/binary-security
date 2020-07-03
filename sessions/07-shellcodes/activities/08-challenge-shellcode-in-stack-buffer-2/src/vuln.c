#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void do_nothing_successfully(const char *str)
{
	int states[3];
	char buffer[37];

	strcpy(buffer, str);

	/* Dumb thing to use state. */
	if (buffer[0] % 8 == states[0])
		buffer[0] = 'a';
}

int main(void)
{
	char input_buffer[128];

	printf("Provide input data: ");
	fgets(input_buffer, 128, stdin);
	do_nothing_successfully(input_buffer);

	return 0;
}
