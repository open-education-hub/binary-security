#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char correct_pass[] = "\xd7\xd9\xda\xcb\xdd\xcc\xd1\xc2\xbd\xf0\xdd\xe2\xef\xb4\xf8\xe1\xfd\xdc\xd5\xff\xd5\x95";

int my_strcmp(char *s1, char *s2)
{
	size_t i, len = strlen(s1);
	if (len == 0)
		return -1;
	for (i = 0; i < len; i++)
		if (s1[i] != s2[i])
			return -1;
	return 0;
}

char *deobf(char *s)
{
	size_t len = strlen(s), i;
	for (i = 0 ; i < len; i++) {
		s[i] = s[i] ^ 0x80 ^ (i%256);
	}

	return s;
}


int main()
{
	char buf[1000];
	deobf(correct_pass);
	printf("Password:\n");
	if (fgets(buf, 1000, stdin) == NULL)
		exit(-1);

	buf[strlen(buf) - 1] = '\0';

	if (!my_strcmp(buf, correct_pass)) {
		printf("Correct!\n");
	} else
		printf("Nope!\n");

	return 0;
}
