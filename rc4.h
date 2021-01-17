#ifndef RC4_H
#define RC4_H

struct rc4_state
{
	unsigned char i, j;
	unsigned char S[256];
};

void rc4_init(struct rc4_state *state, const unsigned char *key, int key_len);
void rc4_crypt(struct rc4_state *state, const unsigned char *in, unsigned char *out, int len);

#endif
