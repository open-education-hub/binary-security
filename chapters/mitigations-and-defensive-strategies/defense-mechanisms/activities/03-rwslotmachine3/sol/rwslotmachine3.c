#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define available_reads 1
#define available_writes 1

#define MAX_SLOTS 32

long slots[MAX_SLOTS];

void setup(int sockfd) {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	dup2(sockfd, 1);
	dup2(sockfd, 0);
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

	if (index >= MAX_SLOTS) {
		printf("Index out of bounds!");
		exit(3);
	}

	printf("Input new slot value: ");
	value = read_int(16);

	printf("Slot[%ld]:= %04lx\n", index, value);
	slots[index] = value;
}

void run(int sockfd) {
	int reads = available_reads;
	int writes = available_writes;
	int choice;

	setup(sockfd);

	while (1) {
		menu(reads, writes);
		printf("> ");
		choice = read_int(10);

		switch (choice) {
			case 1:
				if (reads) {
					do_read();
					-- reads;
					-- writes;
				}
				break;
			case 2:
				if (writes) {
					do_write();
					-- reads;
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

int main(int argc, const char *argv[]) {
    int optval = 1;
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    if (argc != 2) {
    	printf("Usage: %s <port>\n", argv[0]);
    	exit(0);
    }

    portno = atoi(argv[1]);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    serv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    serv_addr.sin_port = htons(portno);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
         perror("ERROR on binding");
         exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    while (1) {
    	int pid;
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("ERROR on accept");
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            perror("ERROR on fork");
        	exit(1);
        }
        if (pid == 0) {

            close(sockfd);
            run(newsockfd);
            exit(0);
        }
        else
            close(newsockfd);
    }
}
