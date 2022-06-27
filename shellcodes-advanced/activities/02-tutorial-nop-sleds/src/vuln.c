#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[2048];
	read(0, buf, 4096);
	return 0;
}
