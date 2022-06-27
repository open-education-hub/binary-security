#include <stdio.h>
#include <stdlib.h>

static const char sh[] = "/bin/sh";

static void hidden(void)
{
	system("ls");
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
