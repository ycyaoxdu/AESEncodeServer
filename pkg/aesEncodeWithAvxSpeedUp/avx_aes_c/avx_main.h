#ifndef _AVX_MAIN_H_
#define _AVX_MAIN_H_

#include <stdint.h>

// aes encode function
int *run(uint8_t in[16]);
// aes decode function
int *inv_run(uint8_t in[16]);

#endif