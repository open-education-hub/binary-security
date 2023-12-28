/* 
 * This is a simple authenticator. Exits with code 137 when successful, and 1
 * when it failed. The password is kept in the binary as a SHA-1 hash.
 * 
 * This seems super-safe, but we are going to make the stack non-executable 
 * just in case.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

const unsigned char password[] = "\xa6\x1b\x25\x97\x01\x09\x90\xc4\xf8\x71"
"\xb3\x53\xa3\x87\xca\x0e\xd9\xdd\xf2\xc2";

unsigned char *hash;

void read_password(char *dst) {
	puts("Enter password: ");
	gets(dst);
}

int check_password() {
	char buffer[1337];

	hash = malloc(SHA_DIGEST_LENGTH);
	if (hash == NULL) {
		puts("malloc failed");
		exit(EXIT_FAILURE);
	}

	read_password(buffer);

	memset(hash, 0, SHA_DIGEST_LENGTH);
	SHA1((unsigned char *)buffer, 137, hash);

	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
		if (password[i] != hash[i])
			return 1;

	return 137;
}

int main() {
	return check_password();
}
