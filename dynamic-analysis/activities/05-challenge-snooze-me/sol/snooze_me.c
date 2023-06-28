#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

void timeout(int signum) {
	puts("Time's up!");
	exit(1);
}

int seed = 0xcafebabe;
char mangled[] = "2Cf3{1b743_046aS11Saec500b3b15T5391400ffc6517F8}S";

int my_prng() {
	return (seed = seed * 0xc0dec0de + 0x1337f00d);
}

void swap(int i, int j) {
	char aux = mangled[i];
	mangled[i] = mangled[j];
	mangled[j] = aux;
}

void demangle(int i) {
	sleep(mangled[i]);
	swap(i, my_prng() % strlen(mangled));
}

int main() {
	signal(SIGALRM, timeout);
	puts("You have 15 seconds. GO!");
	alarm(15);

	for (int i = 0; i < strlen(mangled); ++ i)
		demangle(i);

	printf("%s\n", mangled);	
}
