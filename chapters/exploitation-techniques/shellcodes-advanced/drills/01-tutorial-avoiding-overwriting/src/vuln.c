#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[48];
	printf("%p\n", buf);
	read(0, buf, 64);
	return 0;
}
