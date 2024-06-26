#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

struct timeval start_time, stop_time;

int get_time(struct timeval *t)
{
	int result = gettimeofday(t, 0);
	if (result < 0) {
		perror("gettimeofday");
		exit(1);
	}

	return result;
}

int do_measure()
{
	get_time(&start_time);
	getpid();
	return get_time(&stop_time);
}

int main(void)
{
	do_measure();
	puts("ahCeshuiKuch7Ah7ehahhahha0du2Oof");
	return 0;
}
