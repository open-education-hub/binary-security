#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(void)
{
	char buf[2048];
	printf("%p\n", buf);
	gets(buf);
	for (int i = 0; buf[i]; ++i) {
		if (!isalnum(buf[i])) {
			puts("Potentially malitious input detected!");
			exit(1);
		}
	}
	return 0;
}
