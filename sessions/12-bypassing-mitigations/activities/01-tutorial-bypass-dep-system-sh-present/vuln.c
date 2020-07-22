#include <stdio.h>
#include <stdlib.h>

static void hidden(void)
{
	system("/bin/sh");
}

static void reader(void)
{
	char buffer[32];

	fgets(buffer, 128, stdin);
}

int main(void)
{
	reader();
	return 0;
}
