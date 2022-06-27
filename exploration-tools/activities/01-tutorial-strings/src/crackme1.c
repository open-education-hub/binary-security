#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main()
{
	char buf[1000];

	printf("Password:\n");
	if (fgets(buf, 1000, stdin) == NULL)
		exit(-1);

	buf[strlen(buf) - 1] = '\0';

	if (!my_strcmp(buf, "crackme_hello_world")) {
		printf("Correct!\n");
	} else
		printf("Nope!\n");

	return 0;
}
