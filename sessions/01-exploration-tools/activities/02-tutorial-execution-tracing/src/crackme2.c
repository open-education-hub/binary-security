#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char correct_pass[] = "\xc4\xc3\xd6\xc6\xd1\xf2\xb6\xf4\xbb\xf3\xc7\xcc\xed\xbc\xcd\xce\xc3\xc4\xa0\xf2\xf3\xad\x96";


char *deobf(char *s)
{
	int i;
	for (i = 0 ; i < strlen(s); i++) {
		s[i] = s[i] ^ 0x80 ^ (i%256);
	}

	return s;
}


int main()
{
	char buf[1000];

	printf("Password:\n");
	if (fgets(buf, 1000, stdin) == NULL)
		exit(-1);

	buf[strlen(buf) - 1] = '\0';

	if (!strcmp(buf, deobf(correct_pass))) {
		printf("Correct!\n");
	} else
		printf("Nope!\n");

	return 0;
}
