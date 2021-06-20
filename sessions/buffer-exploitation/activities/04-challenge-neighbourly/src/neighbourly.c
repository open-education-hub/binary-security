#include <stdio.h>
#include <stdlib.h>

void win() {
	system("/bin/sh");
}

struct neighbours {
	char chars[32];
	void (*ptext)();
};

void ptext(struct neighbours* self) {
	printf("%s\n", self->chars);
}

void neigh(struct neighbours* n) {
	n->ptext = ptext;
	fgets(n->chars, 40, stdin);
	n->ptext(n);
}

int main(int argc, char* argv[])
{
	struct neighbours* n = malloc(sizeof(struct neighbours));
	puts("Oh, hi neighbour!");
	puts("Give me some text and I'll print it for you, yessir.");
	neigh(n);
	free(n);
	return 0;
}
