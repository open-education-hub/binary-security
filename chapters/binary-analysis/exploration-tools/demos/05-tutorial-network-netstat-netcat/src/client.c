#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

void error(char *msg) {
    perror(msg);
    exit(1);
}

int fdmax;

static void listclients(char *buffer, int srv_sock)
{
	memset(buffer, 0, 1024);
	strcpy(buffer, "listclients");
	int n = send(srv_sock, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending command to server");

	memset(buffer, 0, 1024);
	n = recv(srv_sock, buffer, 1023, 0);
	if (n < 0)
		error("ERROR: receiving server response");
	if (n == 0) {
		printf("Serverul has closed the connection.\n");
		int j;
		for (j = 3; j <= fdmax; j++)
			close(j); 
		exit(0);
	}
	printf("Connected clients are:\n");
	char *p = strtok(buffer, "|");
	while (p != NULL) {
		printf("%s\t", p);
		p = strtok(NULL, "|");
	}
	printf("\n");
}

static void infoclient(char *buffer, int srv_sock)
{
	buffer[strlen(buffer) - 1] = '\0';
	int n = send(srv_sock, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending command to server");
	memset(buffer, 0, 1024);
	n = recv(srv_sock, buffer, 1023, 0);
	if (n < 0)
		error("ERROR: receiving server response");
	if (n == 0) {
		printf("Server has closed the connection\n");
		//inchidem socketii
		int j;
		for (j = 3; j <= fdmax; j++)
			close(j);		    
		exit(0);
	}
	//extragem informatiile, acestea fiind separate prin "|"
	if (strchr(buffer, '|') == NULL) {
		printf("%s\n", buffer);
		return;
	}
	char *p = strtok(buffer, "|");
	printf("Name: %s\n", p);
	p = strtok(NULL, "|");
	printf("IP: %s\n", p);
	p = strtok(NULL, "|");
	printf("Port: %d\n", atoi(p));
	p = strtok(NULL, "|");
	printf("Admin: %s\n", atoi(p) == 1 ? "yes" : "no");
	p = strtok(NULL, "|");
	printf("Connected for %d seconds\n", atoi(p));
}

static void sendmessage(char *buffer, int srv_sock)
{
	int n = send(srv_sock, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending command to server");

}

static void recvmessage(char *buffer, int srv_sock)
{
	int n = recv(srv_sock, buffer, 1023, 0);
	if (n < 0)
		error("ERROR: receiving server response");
	if (n == 0) {
		printf("Server has closed the connection\n");
		//inchidem socketii
		int j;
		for (j = 3; j <= fdmax; j++)
			close(j);		    
		exit(0);
	}
	char *peer_name = strtok(buffer, "|");
	char *msg = strtok(NULL, "|");
	printf("Message from %s\n", peer_name);
	printf("%s\n", msg);
}

int main(int argc, char *argv[]) {
    int sockfd, n, err, i;
    struct addrinfo hint, *result, *rp;
    char buffer[1024];
    fd_set read_fds;
    fd_set tmp_fds;
    FD_ZERO(&tmp_fds);

    /*verifica numarul de argumente din linia de comanda*/
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <client name> <server IP> <server port>\n", argv[0]);
        exit(0);
    }

    /*definim o retrictie a informatiilor pe care le luam despre server*/
    memset(&hint, 0, sizeof (struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = 0;
    hint.ai_protocol = 0;
    err = getaddrinfo(argv[2], argv[3], &hint, &result);
    if (err != 0)
        error("ERROR: could not get server information");
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        /*incearca sa creezi un socket; daca nu se poate, incearca urmatorul rezultat*/
        if (sockfd < 0)
            continue;
        /*incearca sa te conectezi*/
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;
        /*daca a esuat conectarea inchide socketul*/
        close(sockfd);
    }
    if (rp == NULL)
        error("ERROR: could not connect to server");
    freeaddrinfo(result);

    /*luam bannerul de la server*/
    memset(buffer, 0, 1024);
    n = recv(sockfd, buffer, 1023, 0);
    if (n < 0)
        error("ERROR: could not retrieve server banner");
    if (n == 0) {
        printf("Server has closed the connection\n");
        close(sockfd);
        exit(0);
    }
    printf("%s\n", buffer);

    memset(buffer, 0, 1024);
    sprintf(buffer, "%s|false", argv[1]);
    n = send(sockfd, buffer, strlen(buffer), 0);
    if (n < 0)
        error("ERROR: sending information to server");

    /* preluam raspunsul de la server */
    memset(buffer, 0, 1024);
    n = recv(sockfd, buffer, 1023, 0);
    if (n < 0)
        error("ERROR: could not fetch server response");
    if (n == 0) {
        printf("Server has closed the connection.\n");
        close(sockfd);
        exit(0);
    }
    //daca este REJECT inchidem clientul astfel incat sa fie 
    //pornit din nou cu alt nume in linia de comanda
    if (strcmp(buffer, "REJECT") == 0) {
        fprintf(stderr, "ERROR: duplicate client name\n");
	close(sockfd);
        exit(1);
    }
    while (1) {
	//resetam setul de descriptori urmarit de select
        FD_ZERO(&read_fds);
	//tmp_fds va contine mereu socketii care trebuiesc
	//urmariti pentru primirea de fragmente de fisiere
	read_fds = tmp_fds;
	//monitorizam si intrarea standard
        FD_SET(0, &read_fds);
	FD_SET(sockfd, &read_fds);
	fdmax = sockfd;
        memset(buffer, 0, 1024);
        printf("Enter a command (or 'quit' to exit):\n");
        if (select(fdmax + 1, &read_fds, NULL, NULL, 0) == -1)
            error("ERROR: call to select() failed");
        for (i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == 0) {
		    //daca se primeste o comanda de la tastatura
                    n = read(i, buffer, 1023);
                    if (n < 0)
                        error("ERROR: reading command");
                    /* verific daca se doreste terminarea*/
                    if (strcmp(buffer, "quit\n") == 0) {
			int j;
			//inchidem socketii
			for (j = 3; j <= fdmax; j++)
                            close(j);
                        exit(0);
                    }
                    /* comanda de tip listclients*/
                    if (strcmp(buffer, "listclients\n") == 0) {
			listclients(buffer, sockfd);
                    }
                    /*comanda infoclient*/
                    if (strncmp(buffer, "infoclient", 10) == 0) {
			infoclient(buffer, sockfd);
                    }
		    /*comanda sendmsg*/
		    if (strncmp(buffer, "sendmsg", 7) == 0) {
			sendmessage(buffer, sockfd);
		    }
                }
		if (i == sockfd){
		    recvmessage(buffer, sockfd);
		}
            }//end ISSET
        }//end for
    }
    return 0;
}
