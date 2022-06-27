#include <stdio.h>
#include "libguess.h"

extern int var1;
extern char var2;
extern int var3;

extern char f(void);

int g(void)
{
	printf("g(): not really external\n");
}


int main()
{
	int var4=0;

	puts("Congratulations");
	printf("extern var1 %d at %p\n", var1, &var1);
	printf("extern var2 %c at %p\n", var2, &var2);
	printf("extern var3 %d at %p\n", var3, &var3);
	printf("local var4 %d at %p\n", var4, &var4);

	f();
	g();
}
