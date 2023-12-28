#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[256];
	printf("%p\n", buf);
	read(0, buf, 512);
	return 0;
}
