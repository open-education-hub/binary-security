#include <unistd.h>

int main(int argc, char *argv[])
{
	char buf[4];
	read(0, buf, 20);
	return 0;
}
