#include <unistd.h>

char machine_code[128];

int main(void)
{
	char buf[16];
	read(0, machine_code, 128);
	read(0, buf, 128);
	return 0;
}
