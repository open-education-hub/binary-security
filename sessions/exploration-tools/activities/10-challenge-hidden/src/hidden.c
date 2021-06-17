#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define FIRST_PRINTABLE 	'A'
#define LAST_PRINTABLE 		'z'


#define FLAG_LEN		20

void seed_rng()
{
	struct timeval time;
	gettimeofday(&time, NULL);
	srand(time.tv_usec);
}

char *gen_rand_str(size_t len)
{
	char *s = malloc(len + 2);
	size_t i,interv_size = LAST_PRINTABLE - FIRST_PRINTABLE + 1;
	for (i = 0; i < len; i++)
		s[i] = rand() % interv_size + FIRST_PRINTABLE;
	s[len] = '\n';
	s[len + 1] = '\0';
	return s;
}


int main()
{
	char *s = NULL;
	char *input = NULL;
	size_t input_size = 0;
	size_t allocd;

	char tmp_path[] = "/tmp/graybox1234";
	int fd1;

	seed_rng();
	printf("Generating the flag\n");
	s = gen_rand_str(FLAG_LEN);


	fd1 = open(tmp_path, O_RDWR | O_APPEND | O_CREAT, 0644);
	if (fd1 == -1) {
		goto bye;
	}
	write(fd1, s, FLAG_LEN + 1);
	close(fd1);
	unlink(tmp_path);

	printf("Generated! Can you guess it?\n");
	input_size = getline(&input, &allocd, stdin);

	if (input_size - 1 != FLAG_LEN) {
		printf("Not even close\n");
		goto bye;
	}

	if (memcmp(input, s, FLAG_LEN)) {
		printf("Needs more l33t skillz\n");
		goto bye;
	}

	printf("Congrats! Hostages released.\n");

bye:
	if (s)
		free(s);
	free(input);
	return 0;
}
