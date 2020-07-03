#include <stdio.h>
#include <unistd.h>

void password_accepted()
{
	execve("/bin/sh", 0, 0);
}

int main()
{
	int readValue = 0;

	printf("Please provide password: ");
	scanf("%d", &readValue);

	printf("Your password is: %d. Evaluating it...\n", readValue);
	sleep(2);

	if (readValue < 100)
		return 0;

	if (readValue % 13 != 0)
		return 0;

	if (readValue - 312 < 11)
		password_accepted();

	return 0;
}
