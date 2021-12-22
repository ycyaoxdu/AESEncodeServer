#include "avx_aes.h"
#include "gmult.h"

/*
 * The cipher Key.
 */
int K;

/*
 * Number of columns (32-bit words) comprising the State. For this
 * standard, Nb = 4.
 */
int Nb = 4;

/*
 * Number of 32-bit words comprising the Cipher Key. For this
 * standard, Nk = 4, 6, or 8.
 */
int Nk;

/*
 * Number of rounds, which is a function of  Nk  and  Nb (which is
 * fixed). For this standard, Nr = 10, 12, or 14.
 */
int Nr;

/*
 * Addition of 4 byte words
 * m(x) = x4+1
 */
void coef_add(uint8_t a[], uint8_t b[], uint8_t d[])
{

    d[0] = a[0] ^ b[0];
    d[1] = a[1] ^ b[1];
    d[2] = a[2] ^ b[2];
    d[3] = a[3] ^ b[3];
}

/*
 * Multiplication of 4 byte words
 * m(x) = x4+1
 */
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d)
{

    d[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^ gmult(a[1], b[3]);
    d[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^ gmult(a[2], b[3]);
    d[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^ gmult(a[3], b[3]);
    d[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^ gmult(a[0], b[3]);
}

/*
 * Generates the round constant Rcon[i]
 */
uint8_t R[] = {0x02, 0x00, 0x00, 0x00};

uint8_t *Rcon(uint8_t i)
{

    if (i == 1)
    {
        R[0] = 0x01; // x^(1-1) = x^0 = 1
    }
    else if (i > 1)
    {
        R[0] = 0x02;
        i--;
        while (i > 1)
        {
            R[0] = gmult(R[0], 0x02);
            i--;
        }
    }

    return R;
}

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * input word and applies an S-box to each of the four bytes to
 * produce an output word.
 */
void sub_word(uint8_t *w)
{

    uint8_t i;

    for (i = 0; i < 4; i++)
    {
        w[i] = s_box[w[i]];
    }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * word and performs a cyclic permutation.
 */
void rot_word(uint8_t *w)
{

    uint8_t tmp;
    uint8_t i;

    tmp = w[0];

    for (i = 0; i < 3; i++)
    {
        w[i] = w[i + 1];
    }

    w[3] = tmp;
}

/*
 * Initialize AES variables and allocate memory for expanded key
 */
uint8_t *aes_init(size_t key_size)
{

    switch (key_size)
    {
    default:
    case 16:
        Nk = 4;
        Nr = 10;
        break; // 128
    case 24:
        Nk = 6;
        Nr = 12;
        break; // 192
    case 32:
        Nk = 8;
        Nr = 14;
        break; // 256
    }

    return malloc(Nb * (Nr + 1) * 4); // nb=4 nr=10
}

void aes_key_expansion(uint8_t *key, uint8_t *w)
{

    uint8_t tmp[4];
    uint8_t i;
    uint8_t len = Nb * (Nr + 1);

    for (i = 0; i < Nk; i++)
    {
        w[4 * i + 0] = key[4 * i + 0];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
    }

    for (i = Nk; i < len; i++)
    {
        tmp[0] = w[4 * (i - 1) + 0];
        tmp[1] = w[4 * (i - 1) + 1];
        tmp[2] = w[4 * (i - 1) + 2];
        tmp[3] = w[4 * (i - 1) + 3];

        if (i % Nk == 0)
        {
            rot_word(tmp);
            sub_word(tmp);
            coef_add(tmp, Rcon(i / Nk), tmp);
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            sub_word(tmp);
        }

        w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ tmp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ tmp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ tmp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ tmp[3];
    }
}
/*
    avx constants
*/
const uint16_t T[16] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02};
const uint16_t mask_bit[16] = {
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01};
const uint16_t multiplier[16] = {
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b};

const uint64_t left1[4] = {0x00, 0x10, 0x20, 0x30};
const uint64_t right1[4] = {0x00, 0x30, 0x20, 0x10};

/*
 *  AVX FUNCTIONS
 */
// fill the 4*4 matrix into __m256i.
__m256i avx_set_data_u8(uint8_t *in)
{
    alignas(32) uint8_t input[32] = {
        0x00, in[0], 0x00, in[1],
        0x00, in[2], 0x00, in[3],
        0x00, in[4], 0x00, in[5],
        0x00, in[6], 0x00, in[7],
        0x00, in[8], 0x00, in[9],
        0x00, in[10], 0x00, in[11],
        0x00, in[12], 0x00, in[13],
        0x00, in[14], 0x00, in[15]};

    return _mm256_load_si256((const __m256i *)input);
}

__m256i avx_set_data_u16(uint16_t *in)
{
    return _mm256_load_si256((const __m256i *)in);
}

// return round key for specified round i.
uint8_t *get_round_key(int i, uint8_t *expanded_key)
{
    // 4*11=44 elements per line.
    uint8_t res[] = {
        expanded_key[44 * 0 + 4 * i], expanded_key[44 * 0 + 4 * i + 1], expanded_key[44 * 0 + 4 * i + 2], expanded_key[44 * 0 + 4 * i + 3],
        expanded_key[44 * 1 + 4 * i], expanded_key[44 * 1 + 4 * i + 1], expanded_key[44 * 1 + 4 * i + 2], expanded_key[44 * 1 + 4 * i + 3],
        expanded_key[44 * 2 + 4 * i], expanded_key[44 * 2 + 4 * i + 1], expanded_key[44 * 2 + 4 * i + 2], expanded_key[44 * 2 + 4 * i + 3],
        expanded_key[44 * 3 + 4 * i], expanded_key[44 * 3 + 4 * i + 1], expanded_key[44 * 3 + 4 * i + 2], expanded_key[44 * 3 + 4 * i + 3]};
    return res;
}

// avx_set_round_key return the round key specified by round i, and stores it in __m256i format.
__m256i avx_set_round_key(int i, uint8_t *expanded_key)
{
    return avx_set_data_u8(get_round_key(i, expanded_key));
}

// avx_flush clear invalid data in every 16-bit words.
__m256i avx_flush(__m256i input)
{
    __m256i template = _mm256_set1_epi16(0x00ff);
    return _mm256_and_si256(template, input);
}

// avx_add_round_key do the add round key step with param state and round_key.
__m256i avx_add_round_key(__m256i state, __m256i round_key)
{
    return avx_flush(_mm256_xor_si256(state, round_key));
}

// avx_sub_bytes return the result of sub_bytes.
__m256i avx_sub_bytes(__m256i in_state)
{
    alignas(32) uint16_t temp_state[4][4];
    _mm256_store_si256(temp_state, in_state); // temp_state = sin_state
    alignas(32) uint16_t state[4][4];

    for (uint8_t i = 0; i < 4; ++i)
        for (uint8_t j = 0; j < 4; ++j)
            // 拿出低八位有效数据去查表
            state[i][j] = (uint16_t)getSBoxValue(temp_state[j][i] % 0xff);
    return avx_set_data_u16(state[0]);
}

//
__m256i avx_shift_rows(__m256i input)
{
    __m256i state = input;
    // load
    __m256i left = _mm256_load_si256(left1);
    __m256i right = _mm256_load_si256(right1);
    // do shift
    __m256i shift_left = _mm256_sllv_epi64(input, left);
    __m256i shift_right = _mm256_srlv_epi64(input, right);
    //
    return _mm256_or_si256(shift_left, shift_right);
}

//
__m256i avx_update_state(__m256i in_state)
{
    alignas(32) uint16_t temp_state[4][4];
    _mm256_store_si256(temp_state, in_state); // temp_state = in_state
    alignas(32) uint16_t state[4][4];

    for (int x = 0; x < 4; x++)
        for (int y = 0; y < 4; y++)
            state[y][x] = temp_state[x][y];
    return avx_set_data_u16(state[0]);
}

//
__m256i avx_mix_column(__m256i state)
{
    __m256i avx_T = avx_set_data_u16(T);
    __m256i avx_mask_bit = avx_set_data_u16(mask_bit);
    __m256i avx_multiplier = avx_set_data_u16(multiplier);
    //
    return _mm256_xor_si256(state,
                            _mm256_xor_si256(_mm256_and_si256(avx_T, avx_mask_bit),
                                             _mm256_xor_si256(_mm256_slli_epi16(state, 1),
                                                              _mm256_xor_si256(avx_multiplier,
                                                                               _mm256_and_si256(_mm256_srli_epi16(state, 7),
                                                                                                _mm256_srli_epi16(avx_T, 1))))));
}

//
__m256i avx_aes_loop(__m256i state, __m256i round_key)
{
    return avx_add_round_key(
        avx_mix_column(
            avx_shift_rows(
                avx_sub_bytes(state))),
        round_key);
}

//
__m256i avx_aes_final(__m256i state, __m256i round_key)
{
    return avx_add_round_key(
        avx_shift_rows(
            avx_sub_bytes(state)),
        round_key);
}

//
void *get_avx_output(__m256i message, uint8_t *out)
{
    out[0] = message[0] % 0xff;
    out[1] = (message[0] >> 16) % 0xff;
    out[2] = message[1] % 0xff;
    out[3] = message[1 >> 16] % 0xff;
    out[4] = message[2] % 0xff;
    out[5] = message[2 >> 16] % 0xff;
    out[6] = message[3] % 0xff;
    out[7] = message[3 >> 16] % 0xff;
    out[8] = message[4] % 0xff;
    out[9] = message[4 >> 16] % 0xff;
    out[10] = message[5] % 0xff;
    out[11] = message[5 >> 16] % 0xff;
    out[12] = message[6] % 0xff;
    out[13] = message[6 >> 16] % 0xff;
    out[14] = message[7] % 0xff;
    out[15] = message[7 >> 16] % 0xff;
}

// avx_aes_encode do 128-bit aes encode.
void avx_aes_encode(uint8_t *in, uint8_t *out, uint8_t *w)
{
    uint8_t r = 0;

    // init
    __m256i avx_state = avx_set_data_u8(in);
    __m256i avx_round_key = avx_set_round_key(r, w);

    // 1. add_round_key
    __m256i avx_state1 = avx_add_round_key(avx_state, avx_round_key);

    // 2. aes_loop
    for (r = 1; r < 10; ++r)
    {
        avx_round_key = avx_set_round_key(r, w);
        avx_state1 = avx_aes_loop(avx_state, avx_round_key);
    }

    // 3. aes_final
    avx_round_key = avx_set_round_key(r, w);
    __m256i avx_state_final = avx_aes_final(avx_state1, avx_round_key);

    // output
    get_avx_output(avx_state_final, out);
}

// 95 e6 5a 95 f3 95 4f 95 00 95 00 95 00 95 00 95