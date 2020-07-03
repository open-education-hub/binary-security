#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define SERVER_BANNER	"Welcome to the awesome server.\n"	\
			"Valid commands are:\n"			\
			"listclients\n"				\
			"infoclient <client name> [ADMIN access required]\n"\
			"\tname, IP, port, privileged, connected time\n"\
			"sendmsg <client name> <message>\n"
#define SERVER_HELP	"Welcome to the awesome server.\n"	\
			"Valid commands are:\n"			\
			"quit\n"				\
			"status\n"
#define MAX_CLIENTS	100

typedef struct client {
    char name[64]; /*nume client*/
    char ip[16]; /*adresa IP a clientului*/
    unsigned short int port; /*portul deschis pe client*/
    unsigned char is_admin;
    time_t conn_time; /* timpul la care s-a conectat
		         clientul la server*/
    int sfd; /*socket fd*/
} client;

void error(char *msg) {
    perror(msg);
    exit(1);
}

client peers[MAX_CLIENTS];
int nr_peers = 0;

static int find_peer(char *str, int sock) {/*functie care intoarce indicele unui client
				     din vectorul de clienti conectati in functie
				     de nume sau de socketul dat ca parametru;
				     daca nu exista, se returneaza -1*/
    int i;
    if (str != NULL) {
        for (i = 0; i < nr_peers; i++)
            if (strcmp(str, peers[i].name) == 0)
                return i;
    }
    if (sock != -1) {
        for (i = 0; i < nr_peers; i++)
            if (peers[i].sfd == sock)
                return i;
    }
    return -1;
}

static void listclients(char *buffer, int client_sock)
{
	memset(buffer, 0, 1024);
	strcpy(buffer, peers[0].name);
	int j;
	for (j = 1; j < nr_peers; j++) {
		strcat(buffer, "|");
		strcat(buffer, peers[j].name);
	}
	int n = send(client_sock, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending client list");
}

static void infoclient(char *buffer, int client_sock)
{
	char client[64];
	//extragem numele clientului despre care se cer informatii
	strcpy(client, buffer + 11);
	if (client[strlen(client) - 1] < 21)
		client[strlen(client) - 1] = 0;
	memset(buffer, 0, 1024);
	int i = find_peer(NULL, client_sock);
	int j = find_peer(client, -1);

	if (peers[i].is_admin)
		sprintf(buffer, "%s|%s|%d|%d|%d",
			peers[j].name,
			peers[j].ip,
			peers[j].port,
			peers[j].is_admin,
			(int) (time(NULL) - peers[j].conn_time));
	else
		sprintf(buffer, "Not enough minerals!\n");
	
	int n = send(client_sock, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending client information");
}

static void sendmessage(char *buffer, int client_sock)
{
	char *first_space = strchr(buffer, ' ');
	char *second_space = strchr(&first_space[1], ' ');

	unsigned int dest_name_len = second_space - &first_space[1];
	char *dest_name = malloc(dest_name_len);
	strncpy(dest_name, &first_space[1], dest_name_len);
	
	unsigned int msg_len = strlen(second_space) - 1;
	char *msg = malloc(msg_len);
	strncpy(msg, &second_space[1], msg_len);
	
	int src_id = find_peer(NULL, client_sock);
	int dst_id = find_peer(dest_name, -1);
	
	sprintf(buffer, "%s|%s", peers[src_id].name, msg);

	int n = send(peers[dst_id].sfd, buffer, strlen(buffer), 0);
	if (n < 0)
		error("ERROR: sending message");

	free(dest_name);
	free(msg);
}

int main(int argc, char *argv[]) {
    int sockfd, portno, clilen;
    char buffer[1024];
    struct sockaddr_in serv_addr, cli_addr;
    int n, i;

    fd_set read_fds; //fd_set folosit in select()
    fd_set tmp_fds; //fd_set folosit temporar
    int fdmax; //nr maxim de file descriptori

    if (argc < 2) 
	portno = 31337;
    else
	portno = atoi(argv[1]);

    //golim read_fds
    FD_ZERO(&read_fds);
    FD_ZERO(&tmp_fds);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR: could not open server socket");

    memset((char *) &serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_aton("127.0.0.1", &serv_addr.sin_addr);
    //serv_addr.sin_addr.s_addr = INADDR_ANY; // foloseste adresa IP a masinii
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof (struct sockaddr)) < 0)
        error("ERROR: could not bind server socket");

    printf(SERVER_HELP);

    listen(sockfd, MAX_CLIENTS);

    //adaugam noul file descriptor in multimea read_fds
    FD_SET(sockfd, &read_fds);
    fdmax = sockfd;

    // main loop
    for (;;) {
        tmp_fds = read_fds;
        FD_SET(0, &tmp_fds); //monitorizam si intrarea standard pentru activitate
        if (select(fdmax + 1, &tmp_fds, NULL, NULL, NULL) == -1)
            error("ERROR: select() call failed");

        for (i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &tmp_fds)) {
                if (i == 0) {
                    memset(buffer, 0, 1024);
                    n = read(i, buffer, 1023);
                    if (n < 0)
                        error("ERROR: reading from a client");
                    if (strcmp(buffer, "quit\n") == 0) {
                        int j;
                        //inchidem socketii deschisi catre clienti
                        for (j = 3; j <= fdmax; j++) {
                            close(j);
                        }
                        FD_ZERO(&read_fds);
                        FD_ZERO(&tmp_fds);
                        //inchidem socketul pe care asculta serverul
                        //pentru conexiuni noi
                        close(sockfd);
                        exit(0);
                    }
                    if (strcmp(buffer, "status\n") == 0) {
                        //afisam un antet de tabel daca exista clienti conectati
                        if (nr_peers > 0)
                            printf("%-32s\t%-16s\t%-6s\n", "Client", "IP", "Port");
                        int j;
                        for (j = 0; j < nr_peers; j++) {
                            printf("%-32s\t%-16s\t%-6d\n",
				   peers[j].name, peers[j].ip, peers[j].port);
                        }
                    }
                    continue;
                }
                if (i == sockfd) {
                    // o noua conexiune
                    clilen = sizeof (cli_addr);
		    int newsockfd = accept(sockfd,
					   (struct sockaddr*)&cli_addr,
					   (socklen_t*)&clilen);
                    if (newsockfd == -1) {
                        error("ERROR: failed to accept new client");
                    } else {
                        FD_SET(newsockfd, &read_fds);
                        if (newsockfd > fdmax) {
                            fdmax = newsockfd;
                        }
                        //trimitem banner
                        n = send(newsockfd, SERVER_BANNER, strlen(SERVER_BANNER), 0);
                        if (n < 0)
                            error("ERROR: sending banner to client");
                        memset(buffer, 0, 1024);
                        n = recv(newsockfd, buffer, 1023, 0);
                        if (n < 0)
                            error("ERROR: receiving client registration");
                        char cli_name[128];
                        //extragem numele clientului
                        strcpy(cli_name, strtok(buffer, "|"));
                        //verificam daca mai exista un client cu acelasi nume
                        if (find_peer(cli_name, -1) != -1) {
                            memset(buffer, 0, 1024);
                            strcpy(buffer, "REJECTED");
                            n = send(newsockfd, buffer, strlen(buffer), 0);
                            if (n < 0)
                                error("ERROR: sending reject");
                            //inchidem socket-ul
                            close(newsockfd);
                            //si nu il mai monitorizam
                            FD_CLR(newsockfd, &read_fds);
                            continue;
                        }
                        //daca numele nu exista deja atunci retinem noul client conectat
                        strcpy(peers[nr_peers].name, cli_name);
                        strcpy(peers[nr_peers].ip, inet_ntoa(cli_addr.sin_addr));
                        peers[nr_peers].port = ntohs(cli_addr.sin_port);
                        peers[nr_peers].conn_time = time(NULL);
                        peers[nr_peers].sfd = newsockfd;
			char *admin_str = strtok(NULL, "|");
                        peers[nr_peers].is_admin = strncmp(admin_str, "true", 4) ? 0 : 1;
                        nr_peers++;
                        //si trimitem un mesaj ca a fost acceptat
                        memset(buffer, 0, 1024);
                        strcpy(buffer, "ACCEPTED");
                        n = send(newsockfd, buffer, strlen(buffer), 0);
                        if (n < 0)
                            error("ERROR: sending accept");
                    }
                }
                else {
                    // am primit date
                    memset(buffer, 0, 1024);
                    if ((n = recv(i, buffer, 1023, 0)) <= 0) {
                        if (n == 0) {
                            int id = find_peer(NULL, i);
                            nr_peers--;
                            //si il eliminam din vectorul de clienti conectati
                            //prin inlocuirea lui cu ultimul client conectat
                            strcpy(peers[id].name, peers[nr_peers].name);
                            strcpy(peers[id].ip, peers[nr_peers].ip);
                            peers[id].port = peers[nr_peers].port;
                            peers[id].conn_time = peers[nr_peers].conn_time;
                            peers[id].sfd = peers[nr_peers].sfd;
                            peers[id].is_admin = peers[nr_peers].is_admin;
                        }
                        else {
                            error("ERROR: receiving information from client");
                        }
                        //inchidem socket-ul
                        close(i);
                        FD_CLR(i, &read_fds); // il scoatem din set
                    }
                    else {
                        /*comanda listclients*/
                        if (strncmp(buffer, "listclients", 11) == 0) {
			    listclients(buffer, i);
                        }
                        /*comanda infoclient*/
                        if (strncmp(buffer, "infoclient", 10) == 0) {
			    infoclient(buffer, i);
                        }
                        /*comanda sendmsg*/
                        if (strncmp(buffer, "sendmsg", 7) == 0) {
			    sendmessage(buffer, i);
                        }
                    }
                }
            }
        }
    }

    //inchidem socketul pe care se ascultau conexiuni
    close(sockfd);
    return 0;
}
