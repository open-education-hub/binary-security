#include <unistd.h>


char machine_code[128];

int main(void)
{
	read(0, machine_code, 128);

	// Treat this a pointer to a function that takes and returns nothing and
	// call it (i.e. jump execution at this address).
	((void(*)(void))machine_code)();
	return 0;
}
