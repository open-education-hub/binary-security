#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void xor_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const unsigned char *key, size_t key_len)
{
	size_t i;
	static size_t key_idx = 0;

	for (i = 0; i < len; i++, key_idx++)
		out[i] = in[i] ^ key[key_idx % key_len];
}

static void print_hex(const unsigned char *buffer, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("0x%02x, ", buffer[i]);
}

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s xor_key\n", argv0);
}

int main(int argc, char **argv)
{
	const unsigned char *key;
	size_t key_len;
	unsigned char msg[64];
	unsigned char enc_msg[64];
	size_t len;

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	key = (const unsigned char *) argv[1];
	key_len = strlen(argv[1]);

	printf("{ ");
	while (!feof(stdin)) {
		len = fread(msg, 1, 64, stdin);
		xor_encrypt(msg, enc_msg, len, key, key_len);
		print_hex(enc_msg, len);
	}
	printf("}\n");

	return 0;
}
