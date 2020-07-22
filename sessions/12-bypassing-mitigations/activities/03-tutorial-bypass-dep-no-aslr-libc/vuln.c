#include <stdio.h>
#include <stdlib.h>

static void reader(void)
{
	char buffer[32];

	fgets(buffer, 128, stdin);
}

int main(void)
{
	puts("Hello");
	reader();
	return 0;
}
