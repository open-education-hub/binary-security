#include <stdio.h>
#include <stdlib.h>

void secret_func() {
	system("/bin/sh");
}

int main() {
	int *addr;

	printf("Give me and address to modify!\n");
	scanf("%p", &addr);

	printf("Give me a value!\n");
	scanf("%d", addr);

	exit(0);
}