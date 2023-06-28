#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SZ_UNKNOWN -1

void make_it_easy(void)
{
	void (*f)() = dup2;
	f = system;
	f = 0x0;
	//blow up;
	f();
}

void echo_service(int sockfd)
{
	int count;
	char buf[1024];
	dprintf(sockfd, "==============================================\n");
	dprintf(sockfd, "Welcome to the Echo service\n");
	dprintf(sockfd, "==============================================\n");

	dprintf(sockfd, "For your free trial, we will only echo 1024 bytes back to you\n");
	dprintf(sockfd, "If you need more, contact our sales representatives at legit_services@lol.cat\n");
	count = read(sockfd, buf, 4096);
	dprintf(sockfd, "Got it! Here it is:\n");
	write(sockfd, buf, count);
}


void doprocessing(int sockfd)
{
	echo_service(sockfd);
}

int main(int argc, char **argv)
{
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
	if (sockfd < 0)
	{
		perror("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;

	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(portno);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("ERROR on binding");
		exit(1);
	}

	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	while (1)
	{
		int pid;
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0)
		{
			perror("ERROR on accept");
			exit(1);
		}
		pid = fork();
		if (pid < 0)
		{
			perror("ERROR on fork");
			exit(1);
		}
		if (pid == 0)
		{

			close(sockfd);
			doprocessing(newsockfd);
			exit(0);
		}
		else
		{
			close(newsockfd);
		}
	}
}
