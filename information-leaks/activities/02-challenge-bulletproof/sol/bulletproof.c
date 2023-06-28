#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void (*exit_handler)(int);

struct user {
	int id;
	char name[100];
};
struct user admin;

void bad_func() {
	printf("Game over! Your flag is SSS{I_am_out_of_ideas_stop_finding_flags}\n");
}

void update_name(unsigned int position, char c) {
	admin.name[position] = c;
	printf("Name updated: %s\n", admin.name);
}

void update_4() {
	unsigned int p;
	char c;
	int i;
	for (i = 0; i < 4; i++) {
		printf("Enter position and new char (e.g., 1 x):\n");
		scanf("%d %c", &p, &c);
		update_name(p, c);
	}
}

int main() {
	unsigned int p;
	char c;
	setvbuf(stdout, NULL, _IOLBF, 0);
	exit_handler = &exit;

	admin.id = 1337;
	memset(admin.name, 0, 100);
	while (1) {
		printf("\n Options: 1 = update 1 char, 2 = update 4 chars, 3 = exit\n? ");
		switch (getchar()) {
			case '1': {
				printf("Enter position and new char (e.g., 1 x):\n");
				scanf("%d %c", &p, &c);
				update_name(p, c);
				break;
			}
			case '2': {
				update_4();
				break;
			}
			case '3': {
				exit_handler(0);
				break;
			}
			default: {
				printf("Invalid option!\n");
			}
		}
		getchar();
	}
}
