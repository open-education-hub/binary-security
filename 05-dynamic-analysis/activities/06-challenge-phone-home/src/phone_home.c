#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/wait.h>

int magicval;

const char error_wrong_msg[] = "Communication mismatch\n";
const char cheating_msg[] = "Cheating attempt detected\n";

char* gen_flag() {
	int strvec[32];
	strvec[0] = 0x52464646;
	strvec[1] = 0x6e394736;
	strvec[2] = 0x57545523;
	strvec[3] = 0x23242c26;
	strvec[4] = 0x57272459;
	strvec[5] = 0x29282324;
	strvec[6] = 0x552b552c;
	strvec[7] = 0x24245859;
	strvec[8] = 0x23245454;
	strvec[9] = 0x2c58242b;
	strvec[10] = 0x2a58232a;
	strvec[11] = 0xf3705825;

	for (int i = 0; i < 48; ++ i)
		((char*)strvec)[i] += 13;	

	return strdup((char*)strvec);
}

void readmem(int fd, void *addr, char *val) {
	lseek(fd, (int)addr, SEEK_SET);
	read(fd, val, 1);
}

void writemem(int fd, void *addr, char *val) {
	lseek(fd, (int)addr, SEEK_SET);
	write(fd, val, 1);
}

void decrypt(int fd) {
	char *endptr = (char*)gen_flag + 0xac;
	char *ptr = (char*)gen_flag;
	char b1, b2;

	for (; ptr < endptr; ++ ptr, -- endptr) {
		readmem(fd, endptr, &b1);
		b1 += 1;
		writemem(fd, endptr, &b1);
		//*endptr += 1;
		readmem(fd, ptr, &b2);
		b2 ^= b1;
		writemem(fd, ptr, &b2);
		//*ptr ^= *endptr;
	}
}

int main(int argc, char *argv[]) {
	char filename[32];
	char readbuf[32];
	char *ptr;
	int status;
	int memfd;
	int fd1[2];
    int fd2[2];

	pipe(fd1);
	pipe(fd2);

	pid_t p = fork();
	pid_t ownpid = getpid();

	if (!p) {
		magicval = getppid();

		close(fd1[0]);
		close(fd2[1]);

		while (magicval != 666) { }
		
		write(fd1[1], "OK", 3);

		ptr = readbuf;
		while ((ptr += read(fd2[0], ptr, readbuf + 4 - ptr)) != (readbuf + 4)) { }

		if (strncmp(readbuf, "GO!", 4)) {
			write(2, error_wrong_msg, sizeof(error_wrong_msg));
			exit(3);
		}

		gen_flag();

	} else {
		close(fd1[1]);
		close(fd2[0]);

		ptr = readbuf;
		while ((ptr += read(fd1[0], ptr, readbuf + 3 - ptr)) != (readbuf + 3)) { }

		if (strncmp(readbuf, "OK", 3)) {
			write(2, error_wrong_msg, sizeof(error_wrong_msg));
			exit(1);
		}

		snprintf(filename, sizeof(filename), "/proc/%d/mem", p);
		int memfd = open(filename, O_RDWR);
		if (memfd < 0)
			exit(2);

		readmem(memfd, &magicval, &magicval);
		readmem(memfd, (char*)&magicval + 1, (char*)&magicval + 1);
		readmem(memfd, (char*)&magicval + 2, (char*)&magicval + 2);
		readmem(memfd, (char*)&magicval + 3, (char*)&magicval + 3);

		if (magicval != ownpid) {
			write(2, cheating_msg, sizeof(cheating_msg));
			waitpid(p, &status, 1);
			exit(3);
		}

		decrypt(memfd);	

		write(fd2[1], "GO!", 4);

		while (1) {
			pid_t done = wait(&status);
			if (done == -1 && errno == ECHILD)
				break;
		}
	}
}
