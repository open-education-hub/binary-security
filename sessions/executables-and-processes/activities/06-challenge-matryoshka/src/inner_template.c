#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char key[] = "I laugh in the face of danger";
static const unsigned char enc_msg[] = __TEMPLATE__;

static void xor_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const unsigned char *key, size_t key_len)
{
	size_t i;

	for (i = 0; i < len; i++)
		out[i] = in[i] ^ key[i % key_len];
}

int main(void)
{
	unsigned char *dec_msg;

	dec_msg = calloc(sizeof(enc_msg) + 1, sizeof(enc_msg[0]));

	xor_encrypt(enc_msg, dec_msg, sizeof(enc_msg) / sizeof(enc_msg[0]),
			key, strlen((const char *) key));

	printf("Flag is: %s\n", dec_msg);

	return 0;
}
