#include <stdio.h>
#include <stdlib.h>

#define available_reads 3
#define available_writes 1

#define MAX_SLOTS 32

long read_int(int base)
{
	char buf[64];
	char *endptr;

	if (fgets(buf, sizeof(buf), stdin) == NULL) {
		puts("Failed to read input!");
		exit(1);
	}

	return strtol(buf, &endptr, base);
}

long slots[MAX_SLOTS];

void setup() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void menu(int reads, int writes) {
	puts("==== www / rww ====");
	if (reads)
		printf("1. Read (%d/%d)\n", reads, available_reads);
	else
		printf("1. Read (unavailable)\n");
	if (writes)
		printf("2. Write (%d/%d)\n", writes, available_writes);
	else
		printf("2. Write (unavailable)\n");
	puts("3. Exit");
}

void do_read() {
	long index;

	printf("Input slot index: ");
	index = read_int(10);

	if (index >= MAX_SLOTS) {
		printf("Index out of bounds!");
		exit(3);
	}

	printf("Slot[%ld]: %04lx\n", index, slots[index]);
}

void do_write() {
	long index, value;

	printf("Input slot index: ");
	index = read_int(10);

	printf("Input new slot value: ");
	value = read_int(16);

	printf("Slot[%ld]:= %04lx\n", index, value);
	slots[index] = value;
}

int main() {
	int reads = available_reads;
	int writes = available_writes;
	int choice;

	setup();

	while (1) {
		menu(reads, writes);
		printf("> ");
		choice = read_int(10);

		switch (choice) {
			case 1:
				if (reads) {
					do_read();
					-- reads;
				}
				break;
			case 2:
				if (writes) {
					do_write();
					-- writes;
				}
				break;
			case 3:
				exit(0);
			default:
				puts("Option not available!");
				break;
		}
	}
}

