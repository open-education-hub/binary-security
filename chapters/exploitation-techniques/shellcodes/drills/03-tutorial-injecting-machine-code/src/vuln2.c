#include <unistd.h>
#include <stdlib.h>


char machine_code[128];

int main(void)
{
	char option;

	read(0, &option, 1);
	switch (option) {
	case '1':
		read(0, machine_code, 128);
	break;
	case '2':
		exit(0);
	break;
	}

	// Treat this as a pointer to a function that takes and returns nothing
	// and call it (i.e. jump execution at this address).
	((void(*)(void))machine_code)();
	return 0;
}
