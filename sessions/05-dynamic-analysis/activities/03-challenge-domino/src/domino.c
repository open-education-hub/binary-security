#include <stdio.h>
#include <stdlib.h>

unsigned int d(unsigned int D)
{
	return D * 4 == 4;
}

unsigned int c(unsigned int CD)
{
	unsigned int C = (CD >> 8) & 0xff;

	return (C / 3 == 3) + d(CD & 0x000000ff);
}

unsigned int b(unsigned int BCD)
{
	unsigned int B = (BCD >> 16) & 0xff;

	return (B + 2 == 2) + c(BCD & 0x0000ffff);
}

unsigned int a(unsigned int ABCD)
{
	unsigned int A = (ABCD >> 24) & 0xff;

	return (A - 1 == 1) + b(ABCD & 0x00ffffff);
}

int main()
{
	unsigned int input = 0;

	printf("Kindly provide value, sir/madam: ");
	// input should be 33556737 (0x0x02000901)
	scanf("%u", &input);

	if (a(input) == 4)
		system("/bin/bash");

	return 0;
}
