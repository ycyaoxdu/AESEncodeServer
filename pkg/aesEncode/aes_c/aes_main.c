#include <stdio.h>
#include "aes.h"

int *run(uint8_t in[16]){
	/* 128 bit key */
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f};

	//output
	static uint8_t out[16]; // 128
 
	uint8_t i;

	// expanded key
	uint8_t *w;
	w = aes_init(sizeof(key)); //16bytes , Nb = 4; Nk = 4; Nr = 10;
	aes_key_expansion(key, w);

	//
	// printf("Plaintext message:\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02d %02d %02d %02d ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	// }
	// printf("\n");
	// 
	aes_cipher(in, out, w);

	// printf("Ciphered message:\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02x %02x %02x %02x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
	// }

	// printf("\n");
	//
	free(w);

	uint8_t *p = out;
	return (int*)p;
}
 