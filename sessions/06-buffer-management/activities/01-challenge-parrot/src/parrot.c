#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void get_shell()
{
	system("/bin/sh");
}

void f(char* buf)
{
	fgets(buf, 100, stdin);
}


int main(int argc, char* argv[])
{
	int par = 1337;
	char buf[16];

	f(buf);

	if (par != 1337) {
		printf("SQUAAACK, stack getting smashed, stack getting smashed, SQUAAACK!!!\n");
		exit(1);
	}

	return 0;
}
