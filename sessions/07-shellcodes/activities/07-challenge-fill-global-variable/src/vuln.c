#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char resident_data[128];

static void do_nothing_successfully(const char *str)
{
	int state = 3;
	char buffer[70];

	strcpy(buffer, str);

	/* Dumb thing to use state. */
	if (buffer[0] % 8 == state)
		buffer[0] = 'a';
}

int main(void)
{
	char input_buffer[128];

	printf("Provide resident data: ");
	fgets(resident_data, 128, stdin);

	printf("Provide input data: ");
	fgets(input_buffer, 128, stdin);
	do_nothing_successfully(input_buffer);

	return 0;
}
