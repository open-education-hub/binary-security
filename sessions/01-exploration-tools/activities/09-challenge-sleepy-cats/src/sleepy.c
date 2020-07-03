#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>

int num_array[] = {'C','T','F','_','S','S','S','{','C','a','t','s',
	'_','a','r','e','_','s','l','e','e','p','y','&','}'};

int main()
{
	int i;
	sleep(0x9999);

	for(i = 0; i < sizeof(num_array)/sizeof(num_array[0]); i++)
		printf("%c", num_array[i]);

	printf("\n");

	return 0;
}
