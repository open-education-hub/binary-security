#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char key[] = "I laugh in the face of danger";
static const unsigned char enc_msg[] = { 0x1a, 0x73, 0x3f, 0x3e, 0x36, 0x33, 0x2e, 0x5b, 0x00, 0x00, 0x7f, 0x07, 0x18, 0x04, 0x43, 0x03, 0x3e, 0x0d, 0x0a, 0x7f, 0x00, 0x08, 0x45, 0x3b, 0x02, 0x0f, 0x09, 0x3a, 0x1a, 0x2c, 0x41, 0x1e, 0x3e, 0x0c, 0x08, 0x1d, 0x7f, 0x0b, 0x0b, 0x4c, 0x17, 0x00, 0x18, 0x2a, };

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
