#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	char buf[2048];
	read(0, buf, 4096);
	if (strchr(buf, '\x90')) {
		puts("NOPe!");
		exit(1);
	}
	return 0;
}
