#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void get_name(void)
{
	char buffer[48];

	printf("What's your name? ");
	fgets(buffer, 48, stdin);
	if (buffer[strlen(buffer)-1] == '\n')
		buffer[strlen(buffer)-1] = '\0';
	printf("Hi, %s!\n", buffer);
}

static void get_message(void)
{
	char buffer[48];

	printf("Tell me a joke: ");
	fgets(buffer, 256, stdin);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	puts("Hello");
	get_name();
	get_message();
	return 0;
}
