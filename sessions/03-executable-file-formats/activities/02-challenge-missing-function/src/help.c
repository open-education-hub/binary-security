#include <stdio.h>
#include "stuff.h"


int g()
{
	printf("I lost my function have you seen it?\n");
}

extern int f(char a, char b, char c);

int main()
{
	char a='1', b='2', c='3';

	int result = f(a,b,c);

	if (result == 150)
		printf("welcome back function I have missed you\n");
	else
		g();

	return 0;
}
