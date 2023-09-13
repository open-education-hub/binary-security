#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int strcmp(const char *a, const char *b)
{
	int result;
	printf("Entering strcmp() wrapper function.\n");
	int (*original_strcmp)(const char *, const char *);
	original_strcmp = dlsym(RTLD_NEXT, "strcmp");
	printf("Calling original strcmp().\n");
	result = original_strcmp(a, b);
	printf("Returned from original strcmp().\n");
	printf("Returning from strcmp() wrapper.\n");
	return result;
}
