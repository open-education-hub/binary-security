#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[4];
	printf("%p\n", buf);
	read(0, buf, 512);
	return 0;
}
