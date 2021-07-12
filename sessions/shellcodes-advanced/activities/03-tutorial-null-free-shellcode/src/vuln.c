#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[128];
	char rbuf[256];
	printf("%p\n", buf);
	read(0, rbuf, 256);
	strcpy(buf, rbuf);
	return 0;
}
