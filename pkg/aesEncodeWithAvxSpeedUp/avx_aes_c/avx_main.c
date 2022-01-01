#include <stdio.h>
#include "avx_aes.h"

// aes encode
int *run(uint8_t in[16])
{
	/* 128 bit key */
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f};

	// output
	static uint8_t out[16]; // 128

	uint8_t i;

	// expanded key
	uint8_t *w;
	w = aes_init(sizeof(key)); // 16bytes , Nb = 4; Nk = 4; Nr = 10;
	aes_key_expansion(key, w);
	//

	// remove comments between +++ and ---
	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	// printf("Plaintext message:\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02x %02x %02x %02x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	// }
	// printf("\n");
	//---------------------------------------------------------------------------------------------------------

	//
	// call encode function
	avx_aes_encode(in, out, w);
	//
	//

	// remove comments between +++ and ---
	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	// printf("Ciphered message:\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02x %02x %02x %02x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
	// }
	// printf("\n");
	//---------------------------------------------------------------------------------------------------------

	//
	free(w);
	//
	uint8_t *p = out;
	return (int *)p;
}

// aes decode
int *inv_run(uint8_t in[16])
{
	/* 128 bit key */
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f};

	// output
	static uint8_t out[16]; // 128

	uint8_t i;

	// expanded key
	uint8_t *w;
	w = aes_init(sizeof(key)); // 16bytes , Nb = 4; Nk = 4; Nr = 10;
	aes_key_expansion(key, w);
	//

	// remove comments between +++ and ---
	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	// printf("Plaintext message:\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02x %02x %02x %02x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
	// }
	// printf("\n");
	//---------------------------------------------------------------------------------------------------------

	//
	// call decode function
	avx_aes_decode(in, out, w);
	//
	//

	// remove comments between +++ and ---
	//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	// printf("Ciphered message:(raw input)\n");
	// for (i = 0; i < 4; i++)
	// {
	// 	printf("%02x %02x %02x %02x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
	// }
	// printf("\n");
	//---------------------------------------------------------------------------------------------------------

	//
	free(w);
	//
	uint8_t *p = out;
	return (int *)p;
}