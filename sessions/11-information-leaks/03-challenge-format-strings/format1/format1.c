#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target2;
int target;

void vuln(char *string)
{
	printf(string);
  
	if(target) {
		printf("more GTAB :)\n");
	}
}

int main(int argc, char **argv)
{
	vuln(argv[1]);
}
