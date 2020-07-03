#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

void anti_ptrace(void) __attribute__((constructor));

void anti_ptrace(void)
{
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
		printf("ptrace 102: it can be blocked :)\n");
		exit(EXIT_FAILURE);
	}
}

char chan_name[32];

char password[24] = "\xe7\xc2\xe6\xd9\xc8\xd6\xcc\xb4\xb2\xc8\xd0\xb8\xfa\xd3\xe1\xcc\xc1\xf6\xe9\xb5\xc7\xe1\xef\xb9";

char* deobfuscate(char *s)
{
	int i;
	char *res = strdup(s);
	for (i = 0; i < 24; i++)
		res[i] = res[i] ^ 128;
	return res;
}

void cleanup(void)
{
	int rc = unlink(chan_name);
	if (rc < 0) {
		perror("Failed to cleanup.");
		exit(EXIT_FAILURE);
	}
}

void* child_routine(void *arg)
{
	int fd = open(chan_name, O_RDONLY);
	if (fd < 0) {
		perror("Failed to open channel on reading side.");
		cleanup();
		exit(EXIT_FAILURE);
	}
	char buffer[1024];
	sleep(60);
	int rc = read(fd, buffer, 1023);
	if (rc < 0) {
		perror("Failed reading from user.");
		cleanup();
		exit(EXIT_FAILURE);
	}
	buffer[1023] = 0;

	if (strncmp(buffer, deobfuscate(password), 24) == 0)
		printf("Authorization test succeeded. "
		       "You can now attempt to authenticate yourself "
		       "or type 'quit' to exit.\n");
	else
		printf("This shouldn't happen. Type 'quit' NOW!\n");

	while (1) {
		rc = read(fd, buffer, 1023);
		if (rc < 0) {
			perror("Failed reading from user.");
			cleanup();
			exit(EXIT_FAILURE);
		}
		buffer[1023] = 0;
		if (strncmp(buffer, "quit", 4) == 0)
			break;
		if (strncmp(buffer, deobfuscate(password), 24) == 0)
			printf("Correct!\n");
		else
			printf("NO!\n");
	}

	return NULL;
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		printf("I don't do requests.");
		exit(EXIT_FAILURE);
	}

	int rc = 0;

	sprintf(chan_name, "/%s/%s.%c%c%c%c", "tmp", argv[0], 'f', 'i', 'f', 'o');

	rc = mkfifo(chan_name, 0666);
	if (rc < 0) {
		perror("Could not create communication channel.");
		exit(EXIT_FAILURE);
	}

	pthread_t child;
	if (pthread_create(&child, NULL, &child_routine, argv[0])) {
		perror("Could not create child.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	int fd = open(chan_name, O_WRONLY);
	if (fd < 0) {
		perror("Failed to open channel on writing side.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	printf("Type 'start' to begin authentication test (will take a minute)\n");
	char c[8];
	rc = read(STDIN_FILENO, c, 8);
	if (rc < 0) {
		perror("Failed reading from user.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	rc = write(fd, deobfuscate(password), 24);
	if (rc < 0) {
		perror("Failed writing to channel.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	while (1) {
		char buffer[1024];
		rc = read(STDIN_FILENO, buffer, 1023);
		if (rc < 0) {
			perror("Failed reading from user.");
			cleanup();
			exit(EXIT_FAILURE);
		}
		buffer[1023] = 0;
		rc = write(fd, buffer, 1023);
		if (rc < 0) {
			perror("Failed writing to channel.");
			cleanup();
			exit(EXIT_FAILURE);
		}
		if (strncmp(buffer, "quit", 4) == 0) {
			break;
		}
	}

	if (pthread_join(child, NULL)) {
		perror("Child has failed us.");
		cleanup();
		exit(EXIT_FAILURE);
	}

	cleanup();

	return 0;
}
