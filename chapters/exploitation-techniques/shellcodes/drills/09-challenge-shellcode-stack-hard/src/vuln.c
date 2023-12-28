#include <unistd.h>
#include <stdio.h>

int main(void)
{
	char buf[4];
	read(0, buf, 512);
	return 0;
}
