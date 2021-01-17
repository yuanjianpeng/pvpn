/* 
 * RC4 library
 *
 * Copyright (c) 2018 Yuan Jianpeng <yuanjp89@163.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "rc4.h"

void rc4_init(struct rc4_state *state, const unsigned char *key, int key_len)
{
	int i, j = 0;
	unsigned char t;
	for (i = 0; i < 256; i++)
		state->S[i] = i;
	for (i = 0; i < 256; i++) {
		j = (j + state->S[i] + key[i%key_len]) % 256;
		t = state->S[i];
		state->S[i] = state->S[j];
		state->S[j] = t;
	}	 
	state->i = 0;
	state->j = 0;
}

void rc4_crypt(struct rc4_state *state, const unsigned char *in, unsigned char *out, int len)
{
	int k;
	unsigned char t, pr;
	for (k = 0; k < len; k++) {
		state->i = (state->i + 1) % 256;
		state->j = (state->j + state->S[state->i]) % 256;
		t = state->S[state->i];
		state->S[state->i] = state->S[state->j];
		state->S[state->j] = t;
		pr = state->S[(state->S[state->i] + state->S[state->j]) % 256];
		out[k] = in[k] ^ pr;
	}
}

