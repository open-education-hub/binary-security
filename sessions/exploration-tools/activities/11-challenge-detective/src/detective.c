#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void nononono(void)
{
	system("/bin/sh");
}

static void read_flag(void)
{
	printf("Well done, here's your flag: ");
	system("/bin/cat /home/ctf/flag");
	puts("There is another flag. Can you get it?");
}

static void read_and_compare(void)
{
	char buffer[64];
	fgets(buffer, 1024, stdin);

	if (strncmp(buffer, "gimme gimme", 11) == 0)
		read_flag();
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	read_and_compare();
	return 0;
}
