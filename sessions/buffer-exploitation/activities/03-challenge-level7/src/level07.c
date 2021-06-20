//written by bla
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{

	int count = atoi(argv[1]);
	int buf[10];

	if (count >= 10)
		return 1;


	memcpy(buf, argv[2], count * sizeof(int));

	if (count == 0x574f4c46) {
		printf("WIN!\n");
		execl("/bin/sh", "sh" ,NULL);
	} else
		printf("Not today son\n");

	return 0;
}

