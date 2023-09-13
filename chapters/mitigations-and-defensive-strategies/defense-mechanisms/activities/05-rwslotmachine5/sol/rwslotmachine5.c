#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>

#define available_reads 1
#define available_writes 32

#define MAX_SLOTS 32

const unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,10,3,0,0,64,32,0,0,0,0,0,0,0,53,0,8,0,0,0,0,64,21,0,6,0,4,0,0,0,21,0,5,0,5,0,0,0,21,0,4,0,252,0,0,0,21,0,0,4,3,0,0,0,32,0,0,0,16,0,0,0,21,0,1,0,0,0,0,0,21,0,0,1,4,0,0,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0}; 

void install_filters() {
	struct sock_fprog prog = {
		.len = (unsigned short)((sizeof(filter) + 7) / 8),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    	perror("ERROR on prctl #1");
		exit(4);
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    	perror("ERROR on prctl #2");
		exit(4);
	}
}

void setup() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	
	install_filters();
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

long read_int(int base) {
	char buf[64];
	int value;

	if (!fgets(buf, sizeof(buf) - 8, stdin))
		exit(1);

	errno = 0;
	value = strtoll(buf, NULL, base);
	if (errno)
		exit(2);

	return value;
}

void do_read(long *slots) {
	long index;

	printf("Input slot index: ");
	index = read_int(10);

	if (index >= MAX_SLOTS) {
		printf("Index out of bounds!");
		exit(3);
	}

	printf("Slot[%ld]: %04lx\n", index, slots[index]);
}

void do_write(long *slots) {
	long index, value;

	printf("Input slot index: ");
	index = read_int(10);

	if (index >= MAX_SLOTS) {
		printf("Index out of bounds!");
		exit(3);
	}

	printf("Input new slot value: ");
	value = read_int(16);

	printf("Slot[%ld]:= %04lx\n", index, value);
	slots[index] = value;
}

int main() {
	int reads = available_reads;
	int writes = available_writes;
	int choice;
	long slots[MAX_SLOTS];

	setup();

	while (1) {
		menu(reads, writes);
		printf("> ");
		choice = read_int(10);

		switch (choice) {
			case 1:
				if (reads) {
					do_read(slots);
					-- reads;
				}
				break;
			case 2:
				if (writes) {
					do_write(slots);
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

