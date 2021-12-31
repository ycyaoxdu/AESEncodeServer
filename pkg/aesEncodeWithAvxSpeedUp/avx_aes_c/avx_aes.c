#include "avx_aes.h"
#include "gmult.h"
#include <stdio.h>

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
    // printf("print expanded key: ");
    // for (int i = 0; i < 4 * 11 * 4; i++)
    // {
    //     if (i % 4 == 0)
    //         printf("\n");

    //     if (i % 16 == 0)
    //         printf("\n\n");
    //     printf("%02x\t", w[i]);
    // }
    // printf("\n");
}

// 00      01      02      03
// 04      05      06      07
// 08      09      0a      0b
// 0c      0d      0e      0f

// d6      aa      74      fd
// d2      af      72      fa
// da      a6      78      f1
// d6      ab      76      fe

// b6      92      cf      0b
// 64      3d      bd      f1
// be      9b      c5      00
// 68      30      b3      fe

// b6      ff      74      4e
// d2      c2      c9      bf
// 6c      59      0c      bf
// 04      69      bf      41

// 47      f7      f7      bc
// 95      35      3e      03
// f9      6c      32      bc
// fd      05      8d      fd

// 3c      aa      a3      e8
// a9      9f      9d      eb
// 50      f3      af      57
// ad      f6      22      aa

// 5e      39      0f      7d
// f7      a6      92      96
// a7      55      3d      c1
// 0a      a3      1f      6b

// 14      f9      70      1a
// e3      5f      e2      8c
// 44      0a      df      4d
// 4e      a9      c0      26

// 47      43      87      35
// a4      1c      65      b9
// e0      16      ba      f4
// ae      bf      7a      d2

// 54      99      32      d1
// f0      85      57      68
// 10      93      ed      9c
// be      2c      97      4e

// 13      11      1d      7f
// e3      94      4a      17
// f3      07      a7      8b
// 4d      2b      30      c5

/*
    avx constants
*/
uint16_t T[] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02};
uint16_t mask_bit[] = {
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01};
uint16_t mask_int16[] = {
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff};
uint16_t multiplier[] = {
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b,
    0x1b, 0x1b, 0x1b, 0x1b};

uint16_t selector1[] = {
    0xff, 0x00, 0x00, 0x00,
    0x00, 0xff, 0x00, 0x00,
    0x00, 0x00, 0xff, 0x00,
    0x00, 0x00, 0x00, 0xff};

uint16_t(*p_T) = T;
uint16_t(*p_mask_bit) = mask_bit;
uint16_t(*p_multiplier) = multiplier;
uint16_t(*p_mask_int16) = mask_int16;
uint16_t(*p_selector1) = selector1;

const long long left1[4] = {0x00, 0x30, 0x20, 0x10};
const long long right1[4] = {0x00, 0x10, 0x20, 0x30};

/*
 *  AVX FUNCTIONS
 */

void avx_print_u16(__m256i *input)
{
    short *sho = (short *)input;
    printf(" %02x, %02x, %02x, %02x,\n %02x, %02x, %02x, %02x,\n %02x, %02x, %02x, %02x,\n %02x, %02x, %02x, %02x,\n\n", sho[0], sho[1], sho[2], sho[3], sho[4], sho[5], sho[6], sho[7], sho[8], sho[9], sho[10], sho[11], sho[12], sho[13], sho[14], sho[15]);
}

// fill the 4*4 matrix into __m256i.
__m256i avx_set_data_u8(uint8_t *in)
{
    alignas(32) uint8_t input[32] = {
        in[0], 0x00, in[1], 0x00,
        in[2], 0x00, in[3], 0x00,
        in[4], 0x00, in[5], 0x00,
        in[6], 0x00, in[7], 0x00,
        in[8], 0x00, in[9], 0x00,
        in[10], 0x00, in[11], 0x00,
        in[12], 0x00, in[13], 0x00,
        in[14], 0x00, in[15], 0x00};
    return _mm256_load_si256((const __m256i *)input);
}

__m256i avx_set_data_u16(uint16_t *in)
{
    return _mm256_load_si256((const __m256i *)in);
}

//
__m256i avx_left_shift_step(__m256i state)
{
    __m256i res = _mm256_or_si256(
        _mm256_slli_epi64(state, 0x30),
        _mm256_srli_epi64(state, 0x10));
    return res;
}
//
__m256i avx_right_shift_step(__m256i state)
{

    __m256i res = _mm256_or_si256(
        _mm256_slli_epi64(state, 0x10),
        _mm256_srli_epi64(state, 0x30));
    return res;
}
//
__m256i avx_up_shift_step(__m256i state)
{
    __m256i res = _mm256_permute4x64_epi64(state, 0b00111001);
    return res;
}

__m256i avx_select_diag(__m256i state)
{
    __m256i avx_selector = avx_set_data_u16(p_selector1);
    __m256i res = _mm256_and_si256(state, avx_selector);
    return res;
}

uint8_t res[16];
// return round key for specified round i.
uint8_t *get_round_key(int i, uint8_t *expanded_key)
{
    res[0] = expanded_key[16 * i + 0];
    res[1] = expanded_key[16 * i + 1];
    res[2] = expanded_key[16 * i + 2];
    res[3] = expanded_key[16 * i + 3];
    res[4] = expanded_key[16 * i + 4];
    res[5] = expanded_key[16 * i + 5];
    res[6] = expanded_key[16 * i + 6];
    res[7] = expanded_key[16 * i + 7];
    res[8] = expanded_key[16 * i + 8];
    res[9] = expanded_key[16 * i + 9];
    res[10] = expanded_key[16 * i + 10];
    res[11] = expanded_key[16 * i + 11];
    res[12] = expanded_key[16 * i + 12];
    res[13] = expanded_key[16 * i + 13];
    res[14] = expanded_key[16 * i + 14];
    res[15] = expanded_key[16 * i + 15];

    uint8_t *p = res;
    return p;
}

// avx_set_round_key return the round key specified by round i, and stores it in __m256i format.
__m256i avx_set_round_key(int i, uint8_t *expanded_key)
{
    __m256i res = avx_set_data_u8(get_round_key(i, expanded_key));
    // printf("avx_set_round_key:\n");
    // avx_print_u16(&res);
    return res;
}

// avx_add_round_key do the add round key step with param state and round_key.
__m256i avx_add_round_key(__m256i state, __m256i round_key)
{
    // printf("in avx_add_round_key...\n");

    __m256i res = _mm256_xor_si256(state, round_key);

    // printf("avx_add_round_key:\n");
    // avx_print_u16(&res);
    // printf("out avx_add_round_key...\n");

    return res;
}

//
__m256i avx_sub_bytes(__m256i in_state)
{
    // printf("in avx_sub_bytes...\n");

    alignas(32) uint16_t temp_state[16];
    _mm256_store_si256((__m256i *)&temp_state, in_state);
    alignas(32) uint16_t state[16];

    for (uint8_t i = 0; i < 4; ++i)
        for (uint8_t j = 0; j < 4; ++j)
            // 拿出低八位有效数据去查表
            state[4 * i + j] = (uint16_t)getSBoxValue(temp_state[i + 4 * j]);

    __m256i res = avx_set_data_u16(state);

    // printf("avx_sub_bytes:\n");
    // avx_print_u16(&res);
    // printf("out avx_sub_bytes...\n");
    return res;
}

//
__m256i avx_shift_rows(__m256i input)
{
    // printf("in avx_shift_rows...\n");

    __m256i state = input;
    // load
    __m256i left = _mm256_set_epi64x(left1[3], left1[2], left1[1], left1[0]);
    __m256i right = _mm256_set_epi64x(right1[3], right1[2], right1[1], right1[0]);
    //
    __m256i shift_left = _mm256_sllv_epi64(input, left);
    __m256i shift_right = _mm256_srlv_epi64(input, right);
    __m256i res = _mm256_or_si256(shift_left, shift_right);

    // printf("avx_shift_rows:\n");
    // avx_print_u16(&res);
    // printf("out avx_shift_rows...\n");

    return res;
}

//
__m256i avx_update_state(__m256i in_state)
{
    // printf("in avx_update_state...\n");

    alignas(32) uint16_t temp_state[16];
    _mm256_store_si256((__m256i *)&temp_state, in_state); 
    alignas(32) uint16_t state[16];

    for (int x = 0; x < 4; x++)
        for (int y = 0; y < 4; y++)
            state[x + 4 * y] = temp_state[4 * x + y];

    // printf("update state:\n");
    // for (int i = 0; i < 16; ++i)
    // {
    //     if (i % 4 == 0)
    //         printf("\n");
    //     printf("%02x\t", state[i]);
    // }
    // printf("\n");

    // printf("out avx_update_state...\n");

    return avx_set_data_u16(state);
}

__m256i avx_mix_colomn_helper(__m256i state, __m256i TT)
{
    __m256i avx_mask_bit = avx_set_data_u16(p_mask_bit);
    __m256i avx_mask_int16 = avx_set_data_u16(p_mask_int16);
    __m256i avx_multiplier = avx_set_data_u16(p_multiplier);
    //
    __m256i state_mul_t_and_mask = _mm256_mullo_epi16(state, _mm256_and_si256(TT, avx_mask_bit));
    //
    __m256i s_right_7 = _mm256_srli_epi16(state, 7);
    __m256i t_right_1 = _mm256_srli_epi16(TT, 1);
    __m256i sr7_and_tr1 = _mm256_and_si256(s_right_7, t_right_1);
    __m256i sr7_and_tr1_mul_0x1b = _mm256_mullo_epi16(sr7_and_tr1, avx_multiplier);
    //
    __m256i s_left_1 = _mm256_and_si256(avx_mask_int16, _mm256_slli_epi16(state, 1));
    __m256i s_left_1_mul_t_right_1 = _mm256_mullo_epi16(s_left_1, t_right_1);
    //
    __m256i res = _mm256_xor_si256(state_mul_t_and_mask,
                                   _mm256_xor_si256(s_left_1_mul_t_right_1,
                                                    sr7_and_tr1_mul_0x1b));

    return res;
}

__m256i avx_mix_colomn_add_helper(__m256i state)
{
    __m256i avx_T = avx_set_data_u16(p_T);
    //
    __m256i tl0 = avx_T;
    __m256i tl1 = avx_left_shift_step(tl0);
    __m256i tl2 = avx_left_shift_step(tl1);
    __m256i tl3 = avx_left_shift_step(tl2);
    //
    __m256i su0 = state;
    __m256i su1 = avx_up_shift_step(su0);
    __m256i su2 = avx_up_shift_step(su1);
    __m256i su3 = avx_up_shift_step(su2);
    // 只有对角线元素有意义，取出对角线
    __m256i mul0 = avx_mix_colomn_helper(avx_select_diag(su0), avx_select_diag(tl0));
    __m256i mul1 = avx_mix_colomn_helper(avx_select_diag(su1), avx_select_diag(tl1));
    __m256i mul2 = avx_mix_colomn_helper(avx_select_diag(su2), avx_select_diag(tl2));
    __m256i mul3 = avx_mix_colomn_helper(avx_select_diag(su3), avx_select_diag(tl3));

    //
    __m256i res1 = _mm256_xor_si256(mul2, mul3);
    __m256i res2 = _mm256_xor_si256(mul0, mul1);
    __m256i res = _mm256_xor_si256(res1, res2);

    return res;
}

//
__m256i avx_mix_column(__m256i state)
{
    // printf("in avx_mix_column...\n");

    //
    __m256i state_l0 = state;
    __m256i state_l1 = avx_left_shift_step(state_l0);
    __m256i state_l2 = avx_left_shift_step(state_l1);
    __m256i state_l3 = avx_left_shift_step(state_l2);
    //
    __m256i raw_res_part1 = avx_mix_colomn_add_helper(state_l0);
    __m256i raw_res_part2 = avx_mix_colomn_add_helper(state_l1);
    __m256i raw_res_part3 = avx_mix_colomn_add_helper(state_l2);
    __m256i raw_res_part4 = avx_mix_colomn_add_helper(state_l3);

    __m256i res = _mm256_or_si256(raw_res_part1,
                                  _mm256_or_si256(avx_right_shift_step(raw_res_part2),
                                                  _mm256_or_si256(avx_right_shift_step(avx_right_shift_step(raw_res_part3)),
                                                                  avx_right_shift_step(avx_right_shift_step(avx_right_shift_step(raw_res_part4))))));

    // printf("avx_mix_column:\n");
    // avx_print_u16(&res);
    // //
    // printf("out avx_mix_column...\n");
    //
    return res;
}

//
__m256i avx_aes_loop(__m256i state, __m256i round_key)
{
    // printf("------------------------------------------------------------------------\n");

    // // test
    // printf("state:\n");
    // avx_print_u16(&state);
    // printf("round_key:\n");
    // avx_print_u16(&round_key);
    //

    return avx_add_round_key(
        avx_mix_column(
            avx_shift_rows(
                avx_sub_bytes(state))),
        round_key);
}

//
__m256i avx_aes_final(__m256i state, __m256i round_key)
{
    // printf("------------------------------------------------------------------------\n");

    // // test
    // printf("state:\n");
    // avx_print_u16(&state);
    // printf("round_key:\n");
    // avx_print_u16(&round_key);
    //
    return avx_add_round_key(
        avx_shift_rows(
            avx_sub_bytes(state)),
        round_key);
}

//
void get_avx_output(__m256i *message, uint8_t *out)
{
    uint16_t *sh = (uint16_t *)message;

    out[0] = sh[0];
    out[1] = sh[1];
    out[2] = sh[2];
    out[3] = sh[3];
    out[4] = sh[4];
    out[5] = sh[5];
    out[6] = sh[6];
    out[7] = sh[7];
    out[8] = sh[8];
    out[9] = sh[9];
    out[10] = sh[10];
    out[11] = sh[11];
    out[12] = sh[12];
    out[13] = sh[13];
    out[14] = sh[14];
    out[15] = sh[15];
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
        avx_state1 = avx_aes_loop(avx_state1, avx_round_key);
    }

    // 3. aes_final
    avx_round_key = avx_set_round_key(r, w);
    __m256i avx_state_final = avx_aes_final(avx_state1, avx_round_key);

    // output
    get_avx_output(&avx_state_final, out);
}

