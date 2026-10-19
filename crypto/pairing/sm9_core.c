/*
 *  Adapted for Tongsuo in 2026. See README.md for provenance and changes.
 *
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/err.h>
#include "sm9_local.h"
static uint64_t load_u64_be(const unsigned char *p)
{
    uint64_t r = 0;
    int i;
    for (i = 0; i < 8; i++)
        r = (r << 8) | p[i];
    return r;
}
static void store_u64_be(unsigned char *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}
#define error_print() ERR_raise(ERR_LIB_EC, ERR_R_PASSED_INVALID_ARGUMENT)
#define GETU64(p) load_u64_be(p)
#define PUTU64(p, v) store_u64_be(p, v)


const ossl_sm9_z256_t OSSL_SM9_Z256_ONE = {1,0,0,0};


// p =  b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
const ossl_sm9_z256_t OSSL_SM9_Z256_P = {
	0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1
};

const uint64_t *ossl_sm9_z256_prime(void) {
	return &OSSL_SM9_Z256_P[0];
}

// p - 2 = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b, used in a^(p-2) = a^-1
const ossl_sm9_z256_t OSSL_SM9_Z256_P_MINUS_TWO = {
	0xe56f9b27e351457b, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1
};

// n =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25
const ossl_sm9_z256_t OSSL_SM9_Z256_N = {
	0xe56ee19cd69ecf25, 0x49f2934b18ea8bee, 0xd603ab4ff58ec744, 0xb640000002a3a6f1
};

const uint64_t *ossl_sm9_z256_order(void) {
	return &OSSL_SM9_Z256_N[0];
}

// n - 1
const ossl_sm9_z256_t OSSL_SM9_Z256_N_MINUS_ONE = {
	0xe56ee19cd69ecf24, 0x49f2934b18ea8bee, 0xd603ab4ff58ec744, 0xb640000002a3a6f1
};

const ossl_sm9_z256_t OSSL_SM9_Z256_NEG_N = {
	0x1a911e63296130db, 0xb60d6cb4e7157411, 0x29fc54b00a7138bb, 0x49bffffffd5c590e
};

// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
// mu_n = 2^512 // n





// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
const OSSL_SM9_Z256_POINT _OSSL_SM9_Z256_P1 = {
	{0xe8c4e4817c66dddd, 0xe1e4086909dc3280, 0xf5ed0704487d01d6, 0x93de051d62bf718f},
	{0x0c464cd70a3ea616, 0x1c1c00cbfa602435, 0x631065125c395bbc, 0x21fe8dda4f21e607},
	{1,0,0,0}
};

const OSSL_SM9_Z256_POINT *OSSL_SM9_Z256_P1 = &_OSSL_SM9_Z256_P1;

/*
	X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
	     0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n],
	Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
	     0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n],
	Z : [1n, 0n],
*/
const OSSL_SM9_Z256_TWIST_POINT _OSSL_SM9_Z256_P2 = {
	{{0xF9B7213BAF82D65B, 0xEE265948D19C17AB, 0xD2AAB97FD34EC120, 0x3722755292130B08},
	 {0x54806C11D8806141, 0xF1DD2C190F5E93C4, 0x597B6027B441A01F, 0x85AEF3D078640C98}},
	{{0x6215BBA5C999A7C7, 0x47EFBA98A71A0811, 0x5F3170153D278FF2, 0xA7CF28D519BE3DA6},
	 {0x856DC76B84EBEB96, 0x0736A96FA347C8BD, 0x66BA0D262CBEE6ED, 0x17509B092E845C12}},
	{{1,0,0,0}, {0,0,0,0}},
};
const OSSL_SM9_Z256_TWIST_POINT *OSSL_SM9_Z256_P2 = &_OSSL_SM9_Z256_P2;


const OSSL_SM9_Z256_TWIST_POINT _OSSL_SM9_Z256_Ppubs = {
	{{0x8F14D65696EA5E32, 0x414D2177386A92DD, 0x6CE843ED24A3B573, 0x29DBA116152D1F78},
	 {0x0AB1B6791B94C408, 0x1CE0711C5E392CFB, 0xE48AFF4B41B56501, 0x9F64080B3084F733}},
	{{0x0E75C05FB4E3216D, 0x1006E85F5CDFF073, 0x1A7CE027B7A46F74, 0x41E00A53DDA532DA},
	 {0xE89E1408D0EF1C25, 0xAD3E2FDB1A77F335, 0xB57329F447E3A0CB, 0x69850938ABEA0112}},
	{{1,0,0,0}, {0,0,0,0}},
};
const OSSL_SM9_Z256_TWIST_POINT *OSSL_SM9_Z256_Ppubs = &_OSSL_SM9_Z256_Ppubs;


// mont params (mod p)
// mu = p^-1 mod 2^64 = 0x76d43bd3d0d11bd5
// 2^512 mod p = 0x2ea795a656f62fbde479b522d6706e7b88f8105fae1a5d3f27dea312b417e2d2
// mont(1) mod p = 2^256 mod p = 0x49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83
//const uint64_t OSSL_SM9_Z256_MODP_MU = 0x76d43bd3d0d11bd5;
const ossl_sm9_z256_t OSSL_SM9_Z256_MODP_2e512 = {0x27dea312b417e2d2, 0x88f8105fae1a5d3f, 0xe479b522d6706e7b, 0x2ea795a656f62fbd};
#define OSSL_SM9_Z256_NEG_P OSSL_SM9_Z256_MODP_MONT_ONE
const ossl_sm9_z256_t OSSL_SM9_Z256_MODP_MONT_ONE = {0x1a9064d81caeba83, 0xde0d6cb4e5851124, 0x29fc54b00a7138ba, 0x49bffffffd5c590e};
const ossl_sm9_z256_t OSSL_SM9_Z256_MODP_MONT_FIVE = {0xb9f2c1e8c8c71995, 0x125df8f246a377fc, 0x25e650d049188d1c, 0x43fffffed866f63};


const OSSL_SM9_Z256_POINT OSSL_SM9_Z256_MONT_P1 = {
	{0x22e935e29860501b, 0xa946fd5e0073282c, 0xefd0cec817a649be, 0x5129787c869140b5},
	{0xee779649eb87f7c7, 0x15563cbdec30a576, 0x326353912824efbf, 0x7215717763c39828},
	{0x1a9064d81caeba83, 0xde0d6cb4e5851124, 0x29fc54b00a7138ba, 0x49bffffffd5c590e}
};
const OSSL_SM9_Z256_POINT *ossl_sm9_z256_generator(void) {
	return &OSSL_SM9_Z256_MONT_P1;
}


const OSSL_SM9_Z256_TWIST_POINT OSSL_SM9_Z256_MONT_P2 = {
	{{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1},
	 {0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}},
	{{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece},
	 {0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}},
	{{0x1a9064d81caeba83, 0xde0d6cb4e5851124, 0x29fc54b00a7138ba, 0x49bffffffd5c590e}, {0,0,0,0}},
};
const OSSL_SM9_Z256_TWIST_POINT *ossl_sm9_z256_twist_generator(void) {
	return &OSSL_SM9_Z256_MONT_P2;
}

void ossl_sm9_z256_to_bits(const ossl_sm9_z256_t a, char bits[256])
{
	int i, j;
	for (i = 3; i >= 0; i--) {
		uint64_t w = a[i];
		for (j = 0; j < 64; j++) {
			*bits++ = (w & 0x8000000000000000) ? '1' : '0';
			w <<= 1;
		}
	}
}



void ossl_sm9_z256_from_bytes(ossl_sm9_z256_t r, const uint8_t in[32])
{
	r[3] = GETU64(in);
	r[2] = GETU64(in + 8);
	r[1] = GETU64(in + 16);
	r[0] = GETU64(in + 24);
}

void ossl_sm9_z256_to_bytes(const ossl_sm9_z256_t a, uint8_t out[32])
{
	PUTU64(out, a[3]);
	PUTU64(out + 8, a[2]);
	PUTU64(out + 16, a[1]);
	PUTU64(out + 24, a[0]);
}

void ossl_sm9_z256_copy(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	r[0] = a[0];
	r[1] = a[1];
	r[2] = a[2];
	r[3] = a[3];
}

void ossl_sm9_z256_copy_conditional(ossl_sm9_z256_t dst, const ossl_sm9_z256_t src, uint64_t move)
{
	uint64_t mask1 = 0-move;
	uint64_t mask2 = ~mask1;

	dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
	dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
	dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
	dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
}


void ossl_sm9_z256_set_one(ossl_sm9_z256_t r)
{
	r[0] = 1;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

void ossl_sm9_z256_set_zero(ossl_sm9_z256_t r)
{
	r[0] = 0;
	r[1] = 0;
	r[2] = 0;
	r[3] = 0;
}

static uint64_t is_zero(uint64_t in)
{
	in |= (0 - in);
	in = ~in;
	in >>= 63;
	return in;
}

uint64_t ossl_sm9_z256_equ(const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t res;

	res = a[0] ^ b[0];
	res |= a[1] ^ b[1];
	res |= a[2] ^ b[2];
	res |= a[3] ^ b[3];

	return is_zero(res);
}

int ossl_sm9_z256_cmp(const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	if (a[3] > b[3]) return 1;
	else if (a[3] < b[3]) return -1;
	if (a[2] > b[2]) return 1;
	else if (a[2] < b[2]) return -1;
	if (a[1] > b[1]) return 1;
	else if (a[1] < b[1]) return -1;
	if (a[0] > b[0]) return 1;
	else if (a[0] < b[0]) return -1;
	return 0;
}

uint64_t ossl_sm9_z256_is_zero(const ossl_sm9_z256_t a)
{
	return
		is_zero(a[0]) &
		is_zero(a[1]) &
		is_zero(a[2]) &
		is_zero(a[3]);
}

uint64_t ossl_sm9_z256_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t t, c = 0;

	t = a[0] + b[0];
	c = t < a[0];
	r[0] = t;

	t = a[1] + c;
	c = t < a[1];
	r[1] = t + b[1];
	c += r[1] < t;

	t = a[2] + c;
	c = t < a[2];
	r[2] = t + b[2];
	c += r[2] < t;

	t = a[3] + c;
	c = t < a[3];
	r[3] = t + b[3];
	c += r[3] < t;

	return c;
}

uint64_t ossl_sm9_z256_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t t, c = 0;

	t = a[0] - b[0];
	c = t > a[0];
	r[0] = t;

	t = a[1] - c;
	c = t > a[1];
	r[1] = t - b[1];
	c += r[1] > t;

	t = a[2] - c;
	c = t > a[2];
	r[2] = t - b[2];
	c += r[2] > t;

	t = a[3] - c;
	c = t > a[3];
	r[3] = t - b[3];
	c += r[3] > t;

	return c;
}

void ossl_sm9_z256_mul(uint64_t r[8], const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t a_[8];
	uint64_t b_[8];
	uint64_t s[16] = {0};
	uint64_t u;
	int i, j;

	for (i = 0; i < 4; i++) {
		a_[2 * i] = a[i] & 0xffffffff;
		b_[2 * i] = b[i] & 0xffffffff;
		a_[2 * i + 1] = a[i] >> 32;
		b_[2 * i + 1] = b[i] >> 32;
	}

	for (i = 0; i < 8; i++) {
		u = 0;
		for (j = 0; j < 8; j++) {
			u = s[i + j] + a_[i] * b_[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 8] = u;
	}

	for (i = 0; i < 8; i++) {
		r[i] = (s[2 * i + 1] << 32) | s[2 * i];
	}
}

int ossl_sm9_z256_get_booth(const uint64_t a[4], uint64_t window_size, int i)
{
	uint64_t mask = (1 << window_size) - 1;
	uint64_t wbits;
	int n, j;

	if (i == 0) {
		return (int)((a[0] << 1) & mask) - (int)(a[0] & mask);
	}

	j = i * (int)window_size - 1;
	n = j / 64;
	j = j % 64;

	wbits = a[n] >> j;
	if ((64 - j) < (window_size + 1) && n < 3) {
		wbits |= a[n + 1] << (64 - j);
	}
	return (int)(wbits & mask) - (int)((wbits >> 1) & mask);
}




#ifndef ENABLE_SM9_ARM64
void ossl_sm9_z256_modp_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t c;
	c = ossl_sm9_z256_add(r, a, b);

	if (c) {
		// a + b - p = (a + b - 2^256) + (2^256 - p)
		(void)ossl_sm9_z256_add(r, r, OSSL_SM9_Z256_NEG_P);
		return;
	}
	if (ossl_sm9_z256_cmp(r, OSSL_SM9_Z256_P) >= 0) {
		(void)ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_P);
	}
}

void ossl_sm9_z256_modp_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t c;
	c = ossl_sm9_z256_sub(r, a, b);

	if (c) {
		// a - b + p = (a - b + 2^256) - (2^256 - p)
		(void)ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_NEG_P);
	}
}

void ossl_sm9_z256_modp_dbl(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modp_add(r, a, a);
}

void ossl_sm9_z256_modp_tri(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_t t;
	ossl_sm9_z256_modp_add(t, a, a);
	ossl_sm9_z256_modp_add(r, t, a);
}

void ossl_sm9_z256_modp_haf(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	uint64_t c = 0;

	if (a[0] & 1) {
		c = ossl_sm9_z256_add(r, a, OSSL_SM9_Z256_P);
	} else {
		r[0] = a[0];
		r[1] = a[1];
		r[2] = a[2];
		r[3] = a[3];
	}

	r[0] = (r[0] >> 1) | ((r[1] & 1) << 63);
	r[1] = (r[1] >> 1) | ((r[2] & 1) << 63);
	r[2] = (r[2] >> 1) | ((r[3] & 1) << 63);
	r[3] = (r[3] >> 1) | ((c & 1) << 63);
}

void ossl_sm9_z256_modp_neg(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	(void)ossl_sm9_z256_sub(r, OSSL_SM9_Z256_P, a);
}
#endif


// p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
// p' = -p^(-1) mod 2^256 = afd2bac5558a13b3966a4b291522b137181ae39613c8dbaf892bc42c2f2ee42b
// sage: -(IntegerModRing(2^256)(p))^-1
const uint64_t OSSL_SM9_Z256_P_PRIME[4] = {
	0x892bc42c2f2ee42b, 0x181ae39613c8dbaf, 0x966a4b291522b137, 0xafd2bac5558a13b3,
};


#if defined(ENABLE_SM9_ARM64)
	// src/ossl_sm9_z256_armv8.S
#elif defined(ENABLE_OSSL_SM9_Z256_NEON)
#include <arm_neon.h>

// precompute <<= 32
const uint64_t OSSL_SM9_Z256_P_LEFT_32[8] = {
	0xe351457d00000000, 0xe56f9b2700000000, 0x1a7aeedb00000000, 0x21f2934b00000000,
	0xf58ec74500000000, 0xd603ab4f00000000, 0x02a3a6f100000000, 0xb640000000000000
};

const uint32_t OSSL_SM9_Z256_MU_32 = 0xd0d11bd5;

void ossl_sm9_z256_modp_mont_mul(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	int i;
	uint32_t a_[8], b_[8];

	for (i = 0; i < 4; ++i) {
		a_[2 * i]     = a[i] & 0xffffffff;
		a_[2 * i + 1] = a[i] >> 32;
		b_[2 * i]     = b[i] & 0xffffffff;
		b_[2 * i + 1] = b[i] >> 32;
	}

	uint64x2_t d0, d1, d2, d3, d4, d5, d6, d7;
	uint64x2_t t, low32 = vmovq_n_u64(0xffffffff);
	uint32x2_t w0, w1;
	uint64_t q, d[16] = {};
	uint32_t pre = OSSL_SM9_Z256_MU_32 * b[0];

	d0 = vmovq_n_u64(0);
	d1 = vmovq_n_u64(0);
	d2 = vmovq_n_u64(0);
	d3 = vmovq_n_u64(0);
	d4 = vmovq_n_u64(0);
	d5 = vmovq_n_u64(0);
	d6 = vmovq_n_u64(0);
	d7 = vmovq_n_u64(0);

	for (i = 0; i < 8; i++) {
		q = pre * a_[i] + OSSL_SM9_Z256_MU_32 * (d[0]-d[1]);
		q <<= 32;

		w0 = vcreate_u32(a_[i] | q);
		w1 = vcreate_u32(b_[0] | OSSL_SM9_Z256_P_LEFT_32[0]);
		t = vmlal_u32(d0, w0, w1);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[1] | OSSL_SM9_Z256_P_LEFT_32[1]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d1);
		d0 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[2] | OSSL_SM9_Z256_P_LEFT_32[2]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d2);
		d1 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[3] | OSSL_SM9_Z256_P_LEFT_32[3]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d3);
		d2 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[4] | OSSL_SM9_Z256_P_LEFT_32[4]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d4);
		d3 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[5] | OSSL_SM9_Z256_P_LEFT_32[5]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d5);
		d4 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[6] | OSSL_SM9_Z256_P_LEFT_32[6]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d6);
		d5 = vandq_u64(t, low32);
		t = vshrq_n_u64(t, 32);

		w1 = vcreate_u32(b_[7] | OSSL_SM9_Z256_P_LEFT_32[7]);
		t = vmlal_u32(t, w0, w1);
		t = vaddq_u64(t, d7);
		d6 = vandq_u64(t, low32);

		d7 = vshrq_n_u64(t, 32);

		vst1q_u64(d, d0);
	}

	vst1q_u64(d, d0);
	vst1q_u64(d + 2, d1);
	vst1q_u64(d + 4, d2);
	vst1q_u64(d + 6, d3);
	vst1q_u64(d + 8, d4);
	vst1q_u64(d + 10, d5);
	vst1q_u64(d + 12, d6);
	vst1q_u64(d + 14, d7);

	ossl_sm9_z256_t e, f;
	for (i = 0; i < 4; ++i) {
		e[i] = d[4 * i]     | d[4 * i + 2] << 32;
		f[i] = d[4 * i + 1] | d[4 * i + 3] << 32;
	}

	if (ossl_sm9_z256_sub(r, e, f)) {
		ossl_sm9_z256_add(r, r, OSSL_SM9_Z256_P);
	}
}

#else // ENABLE_OSSL_SM9_Z256_NEON


static uint64_t sm9_z512_add(uint64_t r[8], const uint64_t a[8], const uint64_t b[8])
{
	uint64_t t, c = 0;

	t = a[0] + b[0];
	c = t < a[0];
	r[0] = t;

	t = a[1] + c;
	c = t < a[1];
	r[1] = t + b[1];
	c += r[1] < t;

	t = a[2] + c;
	c = t < a[2];
	r[2] = t + b[2];
	c += r[2] < t;

	t = a[3] + c;
	c = t < a[3];
	r[3] = t + b[3];
	c += r[3] < t;

	t = a[4] + c;
	c = t < a[4];
	r[4] = t + b[4];
	c += r[4] < t;

	t = a[5] + c;
	c = t < a[5];
	r[5] = t + b[5];
	c += r[5] < t;

	t = a[6] + c;
	c = t < a[6];
	r[6] = t + b[6];
	c += r[6] < t;

	t = a[7] + c;
	c = t < a[7];
	r[7] = t + b[7];
	c += r[7] < t;

	return c;
}

// z = a*b
// c = (z + (z * p' mod 2^256) * p)/2^256
void ossl_sm9_z256_modp_mont_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4])
{
	uint64_t z[8];
	uint64_t t[8];
	uint64_t c;

	// z = a * b
	ossl_sm9_z256_mul(z, a, b);

	// t = low(z) * p'
	ossl_sm9_z256_mul(t, z, OSSL_SM9_Z256_P_PRIME);

	// t = low(t) * p
	ossl_sm9_z256_mul(t, t, OSSL_SM9_Z256_P);

	// z = z + t
	c = sm9_z512_add(z, z, t);

	// r = high(r)
	ossl_sm9_z256_copy(r, z + 4);

	if (c) {
		ossl_sm9_z256_add(r, r, OSSL_SM9_Z256_MODP_MONT_ONE);

	} else if (ossl_sm9_z256_cmp(r, OSSL_SM9_Z256_P) >= 0) {
		(void)ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_P);
	}
}
#endif // ENABLE_SM9_ARM64


#ifndef ENABLE_SM9_ARM64
void ossl_sm9_z256_modp_to_mont(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modp_mont_mul(r, a, OSSL_SM9_Z256_MODP_2e512);
}

void ossl_sm9_z256_modp_from_mont(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modp_mont_mul(r, a, OSSL_SM9_Z256_ONE);
}

void ossl_sm9_z256_modp_mont_sqr(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modp_mont_mul(r, a, a);
}
#endif

void ossl_sm9_z256_modp_mont_pow(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t e)
{
	ossl_sm9_z256_t t;
	uint64_t w;
	int i, j;

	// t = mont(1) (mod p)
	ossl_sm9_z256_copy(t, OSSL_SM9_Z256_MODP_MONT_ONE);

	for (i = 3; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 64; j++) {
			ossl_sm9_z256_modp_mont_sqr(t, t);
			if (w & 0x8000000000000000) {
				ossl_sm9_z256_modp_mont_mul(t, t, a);
			}
			w <<= 1;
		}
	}

	ossl_sm9_z256_copy(r, t);
}

void ossl_sm9_z256_modp_mont_inv(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modp_mont_pow(r, a, OSSL_SM9_Z256_P_MINUS_TWO);
}

static const ossl_sm9_z256_fp2_t OSSL_SM9_Z256_FP2_MONT_5U = {{0,0,0,0},{0xb9f2c1e8c8c71995, 0x125df8f246a377fc, 0x25e650d049188d1c, 0x43fffffed866f63}};


void ossl_sm9_z256_fp2_set_zero(ossl_sm9_z256_fp2_t r)
{
	ossl_sm9_z256_set_zero(r[0]);
	ossl_sm9_z256_set_zero(r[1]);
}

void ossl_sm9_z256_fp2_set_one(ossl_sm9_z256_fp2_t r)
{
	ossl_sm9_z256_copy(r[0], OSSL_SM9_Z256_MODP_MONT_ONE);
	ossl_sm9_z256_set_zero(r[1]);
}

int ossl_sm9_z256_fp2_is_one(const ossl_sm9_z256_fp2_t a)
{
	return ossl_sm9_z256_equ(a[0], OSSL_SM9_Z256_MODP_MONT_ONE) && ossl_sm9_z256_is_zero(a[1]);
}

int ossl_sm9_z256_fp2_is_zero(const ossl_sm9_z256_fp2_t a)
{
	return ossl_sm9_z256_is_zero(a[0]) && ossl_sm9_z256_is_zero(a[1]);
}

int ossl_sm9_z256_fp2_equ(const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	return ossl_sm9_z256_equ(a[0], b[0]) && ossl_sm9_z256_equ(a[1], b[1]);
}

void ossl_sm9_z256_fp2_copy(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_copy(r[0], a[0]);
	ossl_sm9_z256_copy(r[1], a[1]);
}



void ossl_sm9_z256_fp2_to_bytes(const ossl_sm9_z256_fp2_t a, uint8_t buf[64])
{
	ossl_sm9_z256_t z;

	ossl_sm9_z256_modp_from_mont(z, a[1]);
	ossl_sm9_z256_to_bytes(z, buf);

	ossl_sm9_z256_modp_from_mont(z, a[0]);
	ossl_sm9_z256_to_bytes(z, buf + 32);
}

int ossl_sm9_z256_fp2_from_bytes(ossl_sm9_z256_fp2_t r, const uint8_t buf[64])
{
	ossl_sm9_z256_from_bytes(r[1], buf);
	if (ossl_sm9_z256_cmp(r[1], OSSL_SM9_Z256_P) >= 0) {
		error_print();
		return -1;
	}
	ossl_sm9_z256_modp_to_mont(r[1], r[1]);

	ossl_sm9_z256_from_bytes(r[0], buf + 32);
	if (ossl_sm9_z256_cmp(r[0], OSSL_SM9_Z256_P) >= 0) {
		error_print();
		return -1;
	}
	ossl_sm9_z256_modp_to_mont(r[0], r[0]);

	return 1;
}

void ossl_sm9_z256_fp2_add(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	ossl_sm9_z256_modp_add(r[0], a[0], b[0]);
	ossl_sm9_z256_modp_add(r[1], a[1], b[1]);
}

void ossl_sm9_z256_fp2_dbl(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_modp_dbl(r[0], a[0]);
	ossl_sm9_z256_modp_dbl(r[1], a[1]);
}

void ossl_sm9_z256_fp2_tri(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_modp_tri(r[0], a[0]);
	ossl_sm9_z256_modp_tri(r[1], a[1]);
}

void ossl_sm9_z256_fp2_sub(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	ossl_sm9_z256_modp_sub(r[0], a[0], b[0]);
	ossl_sm9_z256_modp_sub(r[1], a[1], b[1]);
}

void ossl_sm9_z256_fp2_neg(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_modp_neg(r[0], a[0]);
	ossl_sm9_z256_modp_neg(r[1], a[1]);
}

void ossl_sm9_z256_fp2_a_mul_u(ossl_sm9_z256_fp2_t r, ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_t r0;

	ossl_sm9_z256_modp_dbl(r0, a[1]);
	ossl_sm9_z256_modp_neg(r0, r0);

	ossl_sm9_z256_copy(r[1], a[0]);
	ossl_sm9_z256_copy(r[0], r0);
}


void ossl_sm9_z256_fp2_mul(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	ossl_sm9_z256_t t0;
	ossl_sm9_z256_t t1;
	ossl_sm9_z256_t t2;

	// t2 = (a0 + a1) * (b0 + b1)
	ossl_sm9_z256_modp_add(t0, a[0], a[1]);
	ossl_sm9_z256_modp_add(t1, b[0], b[1]);
	ossl_sm9_z256_modp_mont_mul(t2, t0, t1);

	// t0 = a0 * b0
	ossl_sm9_z256_modp_mont_mul(t0, a[0], b[0]);

	// t1 = a1 * b1
	ossl_sm9_z256_modp_mont_mul(t1, a[1], b[1]);

	// r1 = t2 - t0 - t1 = a0 * b1 + a1 * b0
	ossl_sm9_z256_modp_sub(t2, t2, t0);
	ossl_sm9_z256_modp_sub(t2, t2, t1);

	// r0 = t0 - 2*t1 = a0 * b0 - 2(a1 * b1)
	ossl_sm9_z256_modp_dbl(t1, t1);
	ossl_sm9_z256_modp_sub(t0, t0, t1);

	ossl_sm9_z256_copy(r[0], t0);
	ossl_sm9_z256_copy(r[1], t2);
}

void ossl_sm9_z256_fp2_mul_u(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	ossl_sm9_z256_t t0;
	ossl_sm9_z256_t t1;
	ossl_sm9_z256_t t2;

	// t2 = (a0 + a1) * (b0 + b1)
	ossl_sm9_z256_modp_add(t0, a[0], a[1]);
	ossl_sm9_z256_modp_add(t1, b[0], b[1]);
	ossl_sm9_z256_modp_mont_mul(t2, t0, t1);

	// t0 = a0 * b0
	ossl_sm9_z256_modp_mont_mul(t0, a[0], b[0]);

	// t1 = a1 * b1
	ossl_sm9_z256_modp_mont_mul(t1, a[1], b[1]);

	// r0 = -2 *(t2 - t0 - t1) = -2 * (a0 * b1 + a1 * b0)
	ossl_sm9_z256_modp_sub(t2, t2, t0);
	ossl_sm9_z256_modp_sub(t2, t2, t1);
	ossl_sm9_z256_modp_dbl(t2, t2);
	ossl_sm9_z256_modp_neg(t2, t2);

	// r1 = t0 - 2*t1 = a0 * b0 - 2(a1 * b1)
	ossl_sm9_z256_modp_dbl(t1, t1);
	ossl_sm9_z256_modp_sub(t0, t0, t1);

	ossl_sm9_z256_copy(r[0], t2);
	ossl_sm9_z256_copy(r[1], t0);
}

void ossl_sm9_z256_fp2_mul_fp(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_t k)
{
	ossl_sm9_z256_modp_mont_mul(r[0], a[0], k);
	ossl_sm9_z256_modp_mont_mul(r[1], a[1], k);
}

void ossl_sm9_z256_fp2_sqr(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_t r0, r1, c0, c1;

	// r0 = (a0 + a1) * (a0 - 2a1) + a0 * a1
	ossl_sm9_z256_modp_mont_mul(r1, a[0], a[1]);
	ossl_sm9_z256_modp_add(c0, a[0], a[1]);
	ossl_sm9_z256_modp_dbl(c1, a[1]);
	ossl_sm9_z256_modp_sub(c1, a[0], c1);
	ossl_sm9_z256_modp_mont_mul(r0, c0, c1);
	ossl_sm9_z256_modp_add(r0, r0, r1);

	// r1 = 2 * a0 * a1
	ossl_sm9_z256_modp_dbl(r1, r1);

	ossl_sm9_z256_copy(r[0], r0);
	ossl_sm9_z256_copy(r[1], r1);
}

void ossl_sm9_z256_fp2_sqr_u(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_t t0;
	ossl_sm9_z256_t t1;
	ossl_sm9_z256_t t2;

	// t0 = a0 * a1
	ossl_sm9_z256_modp_mont_mul(t0, a[0], a[1]);

	// t1 = a0 + a1
	ossl_sm9_z256_modp_add(t1, a[0], a[1]);

	// t2 = a0 - 2*a
	ossl_sm9_z256_modp_sub(t2, a[0], a[1]);
	ossl_sm9_z256_modp_sub(t2, t2, a[1]);

	// r1 = t1 * t2 + t0
	ossl_sm9_z256_modp_mont_mul(t2, t2, t1);
	ossl_sm9_z256_modp_add(t2, t2, t0);

	// r0 = -4 * t0
	ossl_sm9_z256_modp_dbl(t0, t0);
	ossl_sm9_z256_modp_dbl(t0, t0);
	ossl_sm9_z256_modp_neg(t0, t0);

	ossl_sm9_z256_copy(r[0], t0);
	ossl_sm9_z256_copy(r[1], t2);
}

void ossl_sm9_z256_fp2_inv(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	if (ossl_sm9_z256_is_zero(a[0])) {
		// r0 = 0
		ossl_sm9_z256_set_zero(r[0]);
		// r1 = -(2 * a1)^-1
		ossl_sm9_z256_modp_dbl(r[1], a[1]);
		ossl_sm9_z256_modp_mont_inv(r[1], r[1]);
		ossl_sm9_z256_modp_neg(r[1], r[1]);

	} else if (ossl_sm9_z256_is_zero(a[1])) {
		/* r1 = 0 */
		ossl_sm9_z256_set_zero(r[1]);
		/* r0 = a0^-1 */
		ossl_sm9_z256_modp_mont_inv(r[0], a[0]);

	} else {
		ossl_sm9_z256_t k, t;

		// k = (a[0]^2 + 2 * a[1]^2)^-1
		ossl_sm9_z256_modp_mont_sqr(k, a[0]);
		ossl_sm9_z256_modp_mont_sqr(t, a[1]);
		ossl_sm9_z256_modp_dbl(t, t);
		ossl_sm9_z256_modp_add(k, k, t);
		ossl_sm9_z256_modp_mont_inv(k, k);

		// r[0] = a[0] * k
		ossl_sm9_z256_modp_mont_mul(r[0], a[0], k);

		// r[1] = -a[1] * k
		ossl_sm9_z256_modp_mont_mul(r[1], a[1], k);
		ossl_sm9_z256_modp_neg(r[1], r[1]);
	}
}

void ossl_sm9_z256_fp2_div(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b)
{
	ossl_sm9_z256_fp2_t t;
	ossl_sm9_z256_fp2_inv(t, b);
	ossl_sm9_z256_fp2_mul(r, a, t);
}

void ossl_sm9_z256_fp2_haf(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_modp_haf(r[0], a[0]);
	ossl_sm9_z256_modp_haf(r[1], a[1]);
}


const ossl_sm9_z256_fp4_t OSSL_SM9_Z256_FP4_ZERO = {
	{{0,0,0,0},{0,0,0,0}},
	{{0,0,0,0},{0,0,0,0}}
};

const ossl_sm9_z256_fp4_t OSSL_SM9_Z256_FP4_MONT_ONE = {
	{{0x1a9064d81caeba83, 0xde0d6cb4e5851124, 0x29fc54b00a7138ba, 0x49bffffffd5c590e},{0,0,0,0}},
	{{0,0,0,0},{0,0,0,0}}
};


int ossl_sm9_z256_fp4_is_zero(const ossl_sm9_z256_fp4_t a)
{
	return ossl_sm9_z256_fp2_is_zero(a[0]) && ossl_sm9_z256_fp2_is_zero(a[1]);
}

int ossl_sm9_z256_fp4_equ(const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b)
{
	return ossl_sm9_z256_fp2_equ(a[0], b[0]) && ossl_sm9_z256_fp2_equ(a[1], b[1]);
}



void ossl_sm9_z256_fp4_copy(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_copy(r[0], a[0]);
	ossl_sm9_z256_fp2_copy(r[1], a[1]);
}

void ossl_sm9_z256_fp4_to_bytes(const ossl_sm9_z256_fp4_t a, uint8_t buf[128])
{
	ossl_sm9_z256_fp2_to_bytes(a[1], buf);
	ossl_sm9_z256_fp2_to_bytes(a[0], buf + 64);
}

int ossl_sm9_z256_fp4_from_bytes(ossl_sm9_z256_fp4_t r, const uint8_t buf[128])
{
	if (ossl_sm9_z256_fp2_from_bytes(r[1], buf) != 1) {
		error_print();
		return -1;
	}
	if (ossl_sm9_z256_fp2_from_bytes(r[0], buf + 64) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void ossl_sm9_z256_fp4_add(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b)
{
	ossl_sm9_z256_fp2_add(r[0], a[0], b[0]);
	ossl_sm9_z256_fp2_add(r[1], a[1], b[1]);
}

void ossl_sm9_z256_fp4_dbl(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_dbl(r[0], a[0]);
	ossl_sm9_z256_fp2_dbl(r[1], a[1]);
}

void ossl_sm9_z256_fp4_sub(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b)
{
	ossl_sm9_z256_fp2_sub(r[0], a[0], b[0]);
	ossl_sm9_z256_fp2_sub(r[1], a[1], b[1]);
}

void ossl_sm9_z256_fp4_neg(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_neg(r[0], a[0]);
	ossl_sm9_z256_fp2_neg(r[1], a[1]);
}

void ossl_sm9_z256_fp4_haf(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_haf(r[0], a[0]);
	ossl_sm9_z256_fp2_haf(r[1], a[1]);
}

// (a0 + a1*v) * v = a0 * v + a1 * v^2 = a1 * u + a0 * v
void ossl_sm9_z256_fp4_a_mul_v(ossl_sm9_z256_fp4_t r, ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_t r0; // incase r is a

	ossl_sm9_z256_fp2_a_mul_u(r0, a[1]);

	ossl_sm9_z256_fp2_copy(r[1], a[0]);
	ossl_sm9_z256_fp2_copy(r[0], r0);
}

void ossl_sm9_z256_fp4_mul(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b)
{
	ossl_sm9_z256_fp2_t r0, r1, t;

	// r0 = a0 + a1
	ossl_sm9_z256_fp2_add(r0, a[0], a[1]);

	// t = b0 + b1
	ossl_sm9_z256_fp2_add(t, b[0], b[1]);

	// r1 = (a0 + a1) * (b0 + b1)
	ossl_sm9_z256_fp2_mul(r1, t, r0);

	// r0 = a0 * b0
	ossl_sm9_z256_fp2_mul(r0, a[0], b[0]);

	// t = a1 * b1
	ossl_sm9_z256_fp2_mul(t, a[1], b[1]);

	// r1 = a0 * b1 + a1 * b0
	ossl_sm9_z256_fp2_sub(r1, r1, r0);
	ossl_sm9_z256_fp2_sub(r1, r1, t);

	// t = a1 * b1 * u
	ossl_sm9_z256_fp2_a_mul_u(t, t);

	// r0 = a0 * b0 + a1 * b1 * u
	ossl_sm9_z256_fp2_add(r0, r0, t);

	ossl_sm9_z256_fp2_copy(r[0], r0);
	ossl_sm9_z256_fp2_copy(r[1], r1);
}

void ossl_sm9_z256_fp4_mul_fp(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_t k)
{
	ossl_sm9_z256_fp2_mul_fp(r[0], a[0], k);
	ossl_sm9_z256_fp2_mul_fp(r[1], a[1], k);
}

void ossl_sm9_z256_fp4_mul_fp2(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp2_t b0)
{
	ossl_sm9_z256_fp2_mul(r[0], a[0], b0);
	ossl_sm9_z256_fp2_mul(r[1], a[1], b0);
}

void ossl_sm9_z256_fp4_mul_v(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b)
{
	ossl_sm9_z256_fp2_t r0, r1, t;

	ossl_sm9_z256_fp2_mul_u(r0, a[0], b[1]);
	ossl_sm9_z256_fp2_mul_u(t, a[1], b[0]);
	ossl_sm9_z256_fp2_add(r0, r0, t);

	ossl_sm9_z256_fp2_mul(r1, a[0], b[0]);
	ossl_sm9_z256_fp2_mul_u(t, a[1], b[1]);
	ossl_sm9_z256_fp2_add(r1, r1, t);

	ossl_sm9_z256_fp2_copy(r[0], r0);
	ossl_sm9_z256_fp2_copy(r[1], r1);
}

void ossl_sm9_z256_fp4_sqr(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_t r0, r1, t;

	ossl_sm9_z256_fp2_add(r1, a[0], a[1]);
	ossl_sm9_z256_fp2_sqr(r1, r1);

	ossl_sm9_z256_fp2_sqr(r0, a[0]);
	ossl_sm9_z256_fp2_sqr(t, a[1]);

	ossl_sm9_z256_fp2_sub(r1, r1, r0);
	ossl_sm9_z256_fp2_sub(r1, r1, t);

	ossl_sm9_z256_fp2_a_mul_u(t, t);
	ossl_sm9_z256_fp2_add(r0, r0, t);

	ossl_sm9_z256_fp2_copy(r[0], r0);
	ossl_sm9_z256_fp2_copy(r[1], r1);
}

void ossl_sm9_z256_fp4_sqr_v(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_t r0, r1, t;

	ossl_sm9_z256_fp2_mul_u(t, a[0], a[1]);
	ossl_sm9_z256_fp2_dbl(r0, t);

	ossl_sm9_z256_fp2_sqr(r1, a[0]);
	ossl_sm9_z256_fp2_sqr_u(t, a[1]);
	ossl_sm9_z256_fp2_add(r1, r1, t);

	ossl_sm9_z256_fp2_copy(r[0], r0);
	ossl_sm9_z256_fp2_copy(r[1], r1);
}

void ossl_sm9_z256_fp4_inv(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_t r0, r1, k;

	ossl_sm9_z256_fp2_sqr_u(k, a[1]);
	ossl_sm9_z256_fp2_sqr(r0, a[0]);
	ossl_sm9_z256_fp2_sub(k, k, r0);
	ossl_sm9_z256_fp2_inv(k, k);

	ossl_sm9_z256_fp2_mul(r0, a[0], k);
	ossl_sm9_z256_fp2_neg(r0, r0);

	ossl_sm9_z256_fp2_mul(r1, a[1], k);

	ossl_sm9_z256_fp2_copy(r[0], r0);
	ossl_sm9_z256_fp2_copy(r[1], r1);
}


void ossl_sm9_z256_fp12_copy(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp4_copy(r[0], a[0]);
	ossl_sm9_z256_fp4_copy(r[1], a[1]);
	ossl_sm9_z256_fp4_copy(r[2], a[2]);
}



void ossl_sm9_z256_fp12_set_zero(ossl_sm9_z256_fp12_t r)
{
	ossl_sm9_z256_fp4_copy(r[0], OSSL_SM9_Z256_FP4_ZERO);
	ossl_sm9_z256_fp4_copy(r[1], OSSL_SM9_Z256_FP4_ZERO);
	ossl_sm9_z256_fp4_copy(r[2], OSSL_SM9_Z256_FP4_ZERO);
}

void ossl_sm9_z256_fp12_set_one(ossl_sm9_z256_fp12_t r)
{
	ossl_sm9_z256_fp4_copy(r[0], OSSL_SM9_Z256_FP4_MONT_ONE);
	ossl_sm9_z256_fp4_copy(r[1], OSSL_SM9_Z256_FP4_ZERO);
	ossl_sm9_z256_fp4_copy(r[2], OSSL_SM9_Z256_FP4_ZERO);
}

void ossl_sm9_z256_fp12_to_bytes(const ossl_sm9_z256_fp12_t a, uint8_t buf[32 * 12])
{
	ossl_sm9_z256_fp4_to_bytes(a[2], buf);
	ossl_sm9_z256_fp4_to_bytes(a[1], buf + 32 * 4);
	ossl_sm9_z256_fp4_to_bytes(a[0], buf + 32 * 8);
}

int ossl_sm9_z256_fp12_from_bytes(ossl_sm9_z256_fp12_t r, const uint8_t buf[32 * 12])
{
	if (ossl_sm9_z256_fp4_from_bytes(r[2], buf) != 1) {
		error_print();
		return -1;
	}
	if (ossl_sm9_z256_fp4_from_bytes(r[1], buf + 128) != 1) {
		error_print();
		return -1;
	}
	if (ossl_sm9_z256_fp4_from_bytes(r[0], buf + 256) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

void ossl_sm9_z256_fp12_set(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp4_t a0, const ossl_sm9_z256_fp4_t a1, const ossl_sm9_z256_fp4_t a2)
{
	ossl_sm9_z256_fp4_copy(r[0], a0);
	ossl_sm9_z256_fp4_copy(r[1], a1);
	ossl_sm9_z256_fp4_copy(r[2], a2);
}

int ossl_sm9_z256_fp12_equ(const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b)
{
	return ossl_sm9_z256_fp4_equ(a[0], b[0])
		&& ossl_sm9_z256_fp4_equ(a[1], b[1])
		&& ossl_sm9_z256_fp4_equ(a[2], b[2]);
}

void ossl_sm9_z256_fp12_add(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b)
{
	ossl_sm9_z256_fp4_add(r[0], a[0], b[0]);
	ossl_sm9_z256_fp4_add(r[1], a[1], b[1]);
	ossl_sm9_z256_fp4_add(r[2], a[2], b[2]);
}

void ossl_sm9_z256_fp12_dbl(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp4_dbl(r[0], a[0]);
	ossl_sm9_z256_fp4_dbl(r[1], a[1]);
	ossl_sm9_z256_fp4_dbl(r[2], a[2]);
}

void ossl_sm9_z256_fp12_tri(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp12_t t;
	ossl_sm9_z256_fp12_dbl(t, a);
	ossl_sm9_z256_fp12_add(r, t, a);
}

void ossl_sm9_z256_fp12_sub(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b)
{
	ossl_sm9_z256_fp4_sub(r[0], a[0], b[0]);
	ossl_sm9_z256_fp4_sub(r[1], a[1], b[1]);
	ossl_sm9_z256_fp4_sub(r[2], a[2], b[2]);
}

void ossl_sm9_z256_fp12_neg(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp4_neg(r[0], a[0]);
	ossl_sm9_z256_fp4_neg(r[1], a[1]);
	ossl_sm9_z256_fp4_neg(r[2], a[2]);
}

void ossl_sm9_z256_fp12_mul(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b)
{
	ossl_sm9_z256_fp4_t r0, r1, r2;
	ossl_sm9_z256_fp4_t t,  k0, k1;
	ossl_sm9_z256_fp4_t m0, m1, m2;

	ossl_sm9_z256_fp4_mul(m0, a[0], b[0]);
	ossl_sm9_z256_fp4_mul(m1, a[1], b[1]);
	ossl_sm9_z256_fp4_mul(m2, a[2], b[2]);

	ossl_sm9_z256_fp4_add(k0, a[1], a[2]);
	ossl_sm9_z256_fp4_add(k1, b[1], b[2]);
	ossl_sm9_z256_fp4_mul(t, k0, k1);
	ossl_sm9_z256_fp4_sub(t, t, m1);
	ossl_sm9_z256_fp4_sub(t, t, m2);
	ossl_sm9_z256_fp4_a_mul_v(t, t);
	ossl_sm9_z256_fp4_add(r0, t, m0);

	ossl_sm9_z256_fp4_add(k0, a[0], a[2]);
	ossl_sm9_z256_fp4_add(k1, b[0], b[2]);
	ossl_sm9_z256_fp4_mul(t, k0, k1);
	ossl_sm9_z256_fp4_sub(t, t, m0);
	ossl_sm9_z256_fp4_sub(t, t, m2);
	ossl_sm9_z256_fp4_add(r2, t, m1);

	ossl_sm9_z256_fp4_add(k0, a[0], a[1]);
	ossl_sm9_z256_fp4_add(k1, b[0], b[1]);
	ossl_sm9_z256_fp4_mul(t, k0, k1);
	ossl_sm9_z256_fp4_sub(t, t, m0);
	ossl_sm9_z256_fp4_sub(t, t, m1);
	ossl_sm9_z256_fp4_a_mul_v(m2, m2);
	ossl_sm9_z256_fp4_add(r1, t, m2);

	ossl_sm9_z256_fp4_copy(r[0], r0);
	ossl_sm9_z256_fp4_copy(r[1], r1);
	ossl_sm9_z256_fp4_copy(r[2], r2);
}

#if 0
//this is slower than the version below
void ossl_sm9_z256_fp12_sqr(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp4_t r0, r1, r2, t;

	ossl_sm9_z256_fp4_sqr(r0, a[0]);
	ossl_sm9_z256_fp4_mul_v(t, a[1], a[2]);
	ossl_sm9_z256_fp4_dbl(t, t);
	ossl_sm9_z256_fp4_add(r0, r0, t);

	ossl_sm9_z256_fp4_mul(r1, a[0], a[1]);
	ossl_sm9_z256_fp4_dbl(r1, r1);
	ossl_sm9_z256_fp4_sqr_v(t, a[2]);
	ossl_sm9_z256_fp4_add(r1, r1, t);

	ossl_sm9_z256_fp4_mul(r2, a[0], a[2]);
	ossl_sm9_z256_fp4_dbl(r2, r2);
	ossl_sm9_z256_fp4_sqr(t, a[1]);
	ossl_sm9_z256_fp4_add(r2, r2, t);

	ossl_sm9_z256_fp4_copy(r[0], r0);
	ossl_sm9_z256_fp4_copy(r[1], r1);
	ossl_sm9_z256_fp4_copy(r[2], r2);
}
#else
void ossl_sm9_z256_fp12_sqr(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	ossl_sm9_z256_fp4_t h0, h1, h2, t;
	ossl_sm9_z256_fp4_t s0, s1, s2, s3;

	ossl_sm9_z256_fp4_sqr(h0, a[0]);
	ossl_sm9_z256_fp4_sqr(h1, a[2]);
	ossl_sm9_z256_fp4_add(s0, a[2], a[0]);

	ossl_sm9_z256_fp4_sub(t, s0, a[1]);
	ossl_sm9_z256_fp4_sqr(s1, t);

	ossl_sm9_z256_fp4_add(t, s0, a[1]);
	ossl_sm9_z256_fp4_sqr(s0, t);

	ossl_sm9_z256_fp4_mul(s2, a[1], a[2]);
	ossl_sm9_z256_fp4_dbl(s2, s2);

	ossl_sm9_z256_fp4_add(s3, s0, s1);
	ossl_sm9_z256_fp4_haf(s3, s3);

	ossl_sm9_z256_fp4_sub(t, s3, h1);
	ossl_sm9_z256_fp4_sub(h2, t, h0);

	ossl_sm9_z256_fp4_a_mul_v(h1, h1);
	ossl_sm9_z256_fp4_add(h1, h1, s0);
	ossl_sm9_z256_fp4_sub(h1, h1, s2);
	ossl_sm9_z256_fp4_sub(h1, h1, s3);

	ossl_sm9_z256_fp4_a_mul_v(s2, s2);
	ossl_sm9_z256_fp4_add(h0, h0, s2);

	ossl_sm9_z256_fp4_copy(r[0], h0);
	ossl_sm9_z256_fp4_copy(r[1], h1);
	ossl_sm9_z256_fp4_copy(r[2], h2);
}
#endif

void ossl_sm9_z256_fp12_inv(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a)
{
	if (ossl_sm9_z256_fp4_is_zero(a[2])) {
		ossl_sm9_z256_fp4_t k, t;

		ossl_sm9_z256_fp4_sqr(k, a[0]);
		ossl_sm9_z256_fp4_mul(k, k, a[0]);
		ossl_sm9_z256_fp4_sqr_v(t, a[1]);
		ossl_sm9_z256_fp4_mul(t, t, a[1]);
		ossl_sm9_z256_fp4_add(k, k, t);
		ossl_sm9_z256_fp4_inv(k, k);

		ossl_sm9_z256_fp4_sqr(r[2], a[1]);
		ossl_sm9_z256_fp4_mul(r[2], r[2], k);

		ossl_sm9_z256_fp4_mul(r[1], a[0], a[1]);
		ossl_sm9_z256_fp4_mul(r[1], r[1], k);
		ossl_sm9_z256_fp4_neg(r[1], r[1]);

		ossl_sm9_z256_fp4_sqr(r[0], a[0]);
		ossl_sm9_z256_fp4_mul(r[0], r[0], k);

	} else {
		ossl_sm9_z256_fp4_t t0, t1, t2, t3;

		ossl_sm9_z256_fp4_sqr(t0, a[1]);
		ossl_sm9_z256_fp4_mul(t1, a[0], a[2]);
		ossl_sm9_z256_fp4_sub(t0, t0, t1);

		ossl_sm9_z256_fp4_mul(t1, a[0], a[1]);
		ossl_sm9_z256_fp4_sqr_v(t2, a[2]);
		ossl_sm9_z256_fp4_sub(t1, t1, t2);

		ossl_sm9_z256_fp4_sqr(t2, a[0]);
		ossl_sm9_z256_fp4_mul_v(t3, a[1], a[2]);
		ossl_sm9_z256_fp4_sub(t2, t2, t3);

		ossl_sm9_z256_fp4_sqr(t3, t1);
		ossl_sm9_z256_fp4_mul(r[0], t0, t2);
		ossl_sm9_z256_fp4_sub(t3, t3, r[0]);
		ossl_sm9_z256_fp4_inv(t3, t3);
		ossl_sm9_z256_fp4_mul(t3, a[2], t3);

		ossl_sm9_z256_fp4_mul(r[0], t2, t3);

		ossl_sm9_z256_fp4_mul(r[1], t1, t3);
		ossl_sm9_z256_fp4_neg(r[1], r[1]);

		ossl_sm9_z256_fp4_mul(r[2], t0, t3);
	}
}

void ossl_sm9_z256_fp12_pow(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_t k)
{
	ossl_sm9_z256_fp12_t t;
	uint64_t w;
	int i, j;

	/* All 256-bit exponents, including the group order, are valid. */
	ossl_sm9_z256_fp12_set_one(t);

	for (i = 3; i >=0; i--) {
		w = k[i];
		for (j = 0; j < 64; j++) {
			ossl_sm9_z256_fp12_sqr(t, t);
			if (w & 0x8000000000000000) {
				ossl_sm9_z256_fp12_mul(t, t, a);
			}
			w <<= 1;
		}
	}
	ossl_sm9_z256_fp12_copy(r, t);
}

void ossl_sm9_z256_fp2_conjugate(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_copy(r[0], a[0]);
	ossl_sm9_z256_modp_neg (r[1], a[1]);
}

void ossl_sm9_z256_fp2_frobenius(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a)
{
	ossl_sm9_z256_fp2_conjugate(r, a);
}

// beta   = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha1 = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
// alpha2 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
// alpha3 = 0x6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
// alpha4 = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65333
// alpha5 = 0x2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686

// mont version (mod p)
static const ossl_sm9_z256_fp2_t OSSL_SM9_MONT_BETA  = {{0x39b4ef0f3ee72529, 0xdb043bf508582782, 0xb8554ab054ac91e3, 0x9848eec25498cab5}, {0}};
static const ossl_sm9_z256_t OSSL_SM9_MONT_ALPHA1   = {0x1a98dfbd4575299f, 0x9ec8547b245c54fd, 0xf51f5eac13df846c, 0x9ef74015d5a16393};
static const ossl_sm9_z256_t OSSL_SM9_MONT_ALPHA2   = {0xb626197dce4736ca, 0x08296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992};
static const ossl_sm9_z256_t OSSL_SM9_MONT_ALPHA3   = {0x39b4ef0f3ee72529, 0xdb043bf508582782, 0xb8554ab054ac91e3, 0x9848eec25498cab5};
static const ossl_sm9_z256_t OSSL_SM9_MONT_ALPHA4   = {0x81054fcd94e9c1c4, 0x4c0e91cb8ce2df3e, 0x4877b452e8aedfb4, 0x88f53e748b491776};
static const ossl_sm9_z256_t OSSL_SM9_MONT_ALPHA5   = {0x048baa79dcc34107, 0x5e2e7ac4fe76c161, 0x99399754365bd4bc, 0xaf91aeac819b0e13};


void ossl_sm9_z256_fp4_frobenius(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_conjugate(r[0], a[0]);
	ossl_sm9_z256_fp2_conjugate(r[1], a[1]);
	ossl_sm9_z256_fp2_mul(r[1], r[1], OSSL_SM9_MONT_BETA);
}

void ossl_sm9_z256_fp4_conjugate(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_copy(r[0], a[0]);
	ossl_sm9_z256_fp2_neg(r[1], a[1]);
}

void ossl_sm9_z256_fp4_frobenius2(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp4_conjugate(r, a);
}

void ossl_sm9_z256_fp4_frobenius3(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a)
{
	ossl_sm9_z256_fp2_conjugate(r[0], a[0]);
	ossl_sm9_z256_fp2_conjugate(r[1], a[1]);
	ossl_sm9_z256_fp2_mul(r[1], r[1], OSSL_SM9_MONT_BETA);
	ossl_sm9_z256_fp2_neg(r[1], r[1]);
}

void ossl_sm9_z256_fp12_frobenius(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x)
{
	const ossl_sm9_z256_fp2_t *xa = x[0];
	const ossl_sm9_z256_fp2_t *xb = x[1];
	const ossl_sm9_z256_fp2_t *xc = x[2];

	ossl_sm9_z256_fp4_t ra;
	ossl_sm9_z256_fp4_t rb;
	ossl_sm9_z256_fp4_t rc;

	ossl_sm9_z256_fp2_conjugate(ra[0], xa[0]);
	ossl_sm9_z256_fp2_conjugate(ra[1], xa[1]);
	ossl_sm9_z256_fp2_mul_fp(ra[1], ra[1], OSSL_SM9_MONT_ALPHA3);

	ossl_sm9_z256_fp2_conjugate(rb[0], xb[0]);
	ossl_sm9_z256_fp2_mul_fp(rb[0], rb[0], OSSL_SM9_MONT_ALPHA1);
	ossl_sm9_z256_fp2_conjugate(rb[1], xb[1]);
	ossl_sm9_z256_fp2_mul_fp(rb[1], rb[1], OSSL_SM9_MONT_ALPHA4);

	ossl_sm9_z256_fp2_conjugate(rc[0], xc[0]);
	ossl_sm9_z256_fp2_mul_fp(rc[0], rc[0], OSSL_SM9_MONT_ALPHA2);
	ossl_sm9_z256_fp2_conjugate(rc[1], xc[1]);
	ossl_sm9_z256_fp2_mul_fp(rc[1], rc[1], OSSL_SM9_MONT_ALPHA5);

	ossl_sm9_z256_fp12_set(r, ra, rb, rc);
}

void ossl_sm9_z256_fp12_frobenius2(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x)
{
	ossl_sm9_z256_fp4_t a;
	ossl_sm9_z256_fp4_t b;
	ossl_sm9_z256_fp4_t c;

	ossl_sm9_z256_fp4_conjugate(a, x[0]);
	ossl_sm9_z256_fp4_conjugate(b, x[1]);
	ossl_sm9_z256_fp4_mul_fp(b, b, OSSL_SM9_MONT_ALPHA2);
	ossl_sm9_z256_fp4_conjugate(c, x[2]);
	ossl_sm9_z256_fp4_mul_fp(c, c, OSSL_SM9_MONT_ALPHA4);

	ossl_sm9_z256_fp4_copy(r[0], a);
	ossl_sm9_z256_fp4_copy(r[1], b);
	ossl_sm9_z256_fp4_copy(r[2], c);
}

void ossl_sm9_z256_fp12_frobenius3(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x)
{
	const ossl_sm9_z256_fp2_t *xa = x[0];
	const ossl_sm9_z256_fp2_t *xb = x[1];
	const ossl_sm9_z256_fp2_t *xc = x[2];

	ossl_sm9_z256_fp4_t ra;
	ossl_sm9_z256_fp4_t rb;
	ossl_sm9_z256_fp4_t rc;

	ossl_sm9_z256_fp2_conjugate(ra[0], xa[0]);
	ossl_sm9_z256_fp2_conjugate(ra[1], xa[1]);
	ossl_sm9_z256_fp2_mul(ra[1], ra[1], OSSL_SM9_MONT_BETA);
	ossl_sm9_z256_fp2_neg(ra[1], ra[1]);

	ossl_sm9_z256_fp2_conjugate(rb[0], xb[0]);
	ossl_sm9_z256_fp2_mul(rb[0], rb[0], OSSL_SM9_MONT_BETA);
	ossl_sm9_z256_fp2_conjugate(rb[1], xb[1]);

	ossl_sm9_z256_fp2_conjugate(rc[0], xc[0]);
	ossl_sm9_z256_fp2_neg(rc[0], rc[0]);
	ossl_sm9_z256_fp2_conjugate(rc[1], xc[1]);
	ossl_sm9_z256_fp2_mul(rc[1], rc[1], OSSL_SM9_MONT_BETA);

	ossl_sm9_z256_fp4_copy(r[0], ra);
	ossl_sm9_z256_fp4_copy(r[1], rb);
	ossl_sm9_z256_fp4_copy(r[2], rc);
}

void ossl_sm9_z256_fp12_frobenius6(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x)
{
	ossl_sm9_z256_fp4_t a;
	ossl_sm9_z256_fp4_t b;
	ossl_sm9_z256_fp4_t c;

	ossl_sm9_z256_fp4_copy(a, x[0]);
	ossl_sm9_z256_fp4_copy(b, x[1]);
	ossl_sm9_z256_fp4_copy(c, x[2]);

	ossl_sm9_z256_fp4_conjugate(a, a);
	ossl_sm9_z256_fp4_conjugate(b, b);
	ossl_sm9_z256_fp4_neg(b, b);
	ossl_sm9_z256_fp4_conjugate(c, c);

	ossl_sm9_z256_fp4_copy(r[0], a);
	ossl_sm9_z256_fp4_copy(r[1], b);
	ossl_sm9_z256_fp4_copy(r[2], c);
}

int ossl_sm9_z256_point_is_at_infinity(const OSSL_SM9_Z256_POINT *P)
{
	if (ossl_sm9_z256_is_zero(P->Z)) {
		return 1;
	} else {
		return 0;
	}
}

void ossl_sm9_z256_point_set_infinity(OSSL_SM9_Z256_POINT *R)
{
	ossl_sm9_z256_copy(R->X, OSSL_SM9_Z256_MODP_MONT_ONE);
	ossl_sm9_z256_copy(R->Y, OSSL_SM9_Z256_MODP_MONT_ONE);
	ossl_sm9_z256_set_zero(R->Z);
}

void ossl_sm9_z256_point_get_xy(const OSSL_SM9_Z256_POINT *P, ossl_sm9_z256_t x, ossl_sm9_z256_t y)
{
	ossl_sm9_z256_t z_inv;

	assert(!ossl_sm9_z256_is_zero(P->Z));

	if (ossl_sm9_z256_equ(P->Z, OSSL_SM9_Z256_MODP_MONT_ONE)) {
		ossl_sm9_z256_modp_from_mont(x, P->X);
		ossl_sm9_z256_modp_from_mont(y, P->Y);
		return;
	}

	ossl_sm9_z256_modp_mont_inv(z_inv, P->Z);
	if (y) {
		ossl_sm9_z256_modp_mont_mul(y, P->Y, z_inv);
	}
	ossl_sm9_z256_modp_mont_sqr(z_inv, z_inv);
	ossl_sm9_z256_modp_mont_mul(x, P->X, z_inv);
	ossl_sm9_z256_modp_from_mont(x, x);
	if (y) {
		ossl_sm9_z256_modp_mont_mul(y, y, z_inv);
		ossl_sm9_z256_modp_from_mont(y, y);
	}
}

int ossl_sm9_z256_point_equ(const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q)
{
	ossl_sm9_z256_t t1, t2, t3, t4;
	ossl_sm9_z256_modp_mont_sqr(t1, P->Z);
	ossl_sm9_z256_modp_mont_sqr(t2, Q->Z);
	ossl_sm9_z256_modp_mont_mul(t3, P->X, t2);
	ossl_sm9_z256_modp_mont_mul(t4, Q->X, t1);
	if (!ossl_sm9_z256_equ(t3, t4)) {
		return 0;
	}
	ossl_sm9_z256_modp_mont_mul(t1, t1, P->Z);
	ossl_sm9_z256_modp_mont_mul(t2, t2, Q->Z);
	ossl_sm9_z256_modp_mont_mul(t3, P->Y, t2);
	ossl_sm9_z256_modp_mont_mul(t4, Q->Y, t1);
	return (int)ossl_sm9_z256_equ(t3, t4);
}

int ossl_sm9_z256_point_is_on_curve(const OSSL_SM9_Z256_POINT *P)
{
	ossl_sm9_z256_t t0, t1, t2;
	if (ossl_sm9_z256_equ(P->Z, OSSL_SM9_Z256_MODP_MONT_ONE)) {
		ossl_sm9_z256_modp_mont_sqr(t0, P->Y);
		ossl_sm9_z256_modp_mont_sqr(t1, P->X);
		ossl_sm9_z256_modp_mont_mul(t1, t1, P->X);
		ossl_sm9_z256_modp_add(t1, t1, OSSL_SM9_Z256_MODP_MONT_FIVE);
	} else {
		ossl_sm9_z256_modp_mont_sqr(t0, P->X);
		ossl_sm9_z256_modp_mont_mul(t0, t0, P->X);
		ossl_sm9_z256_modp_mont_sqr(t1, P->Z);
		ossl_sm9_z256_modp_mont_sqr(t2, t1);
		ossl_sm9_z256_modp_mont_mul(t1, t1, t2);
		ossl_sm9_z256_modp_mont_mul(t1, t1, OSSL_SM9_Z256_MODP_MONT_FIVE);
		ossl_sm9_z256_modp_add(t1, t0, t1);
		ossl_sm9_z256_modp_mont_sqr(t0, P->Y);
	}
	if (ossl_sm9_z256_equ(t0, t1) != 1) {
		//error_print();
		return 0;
	}
	return 1;
}

void ossl_sm9_z256_point_dbl(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;

	ossl_sm9_z256_t X3, Y3, Z3, T1, T2, T3;

	if (ossl_sm9_z256_point_is_at_infinity(P)) {
		*R = *P;
		return;
	}

	ossl_sm9_z256_modp_mont_sqr(T2, X1);
	ossl_sm9_z256_modp_tri(T2, T2);
	ossl_sm9_z256_modp_dbl(Y3, Y1);
	ossl_sm9_z256_modp_mont_mul(Z3, Y3, Z1);
	ossl_sm9_z256_modp_mont_sqr(Y3, Y3);
	ossl_sm9_z256_modp_mont_mul(T3, Y3, X1);
	ossl_sm9_z256_modp_mont_sqr(Y3, Y3);
	ossl_sm9_z256_modp_haf(Y3, Y3);
	ossl_sm9_z256_modp_mont_sqr(X3, T2);
	ossl_sm9_z256_modp_dbl(T1, T3);
	ossl_sm9_z256_modp_sub(X3, X3, T1);
	ossl_sm9_z256_modp_sub(T1, T3, X3);
	ossl_sm9_z256_modp_mont_mul(T1, T1, T2);
	ossl_sm9_z256_modp_sub(Y3, T1, Y3);

	ossl_sm9_z256_copy(R->X, X3);
	ossl_sm9_z256_copy(R->Y, Y3);
	ossl_sm9_z256_copy(R->Z, Z3);
}

void ossl_sm9_z256_point_add(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q)
{
	if (ossl_sm9_z256_point_is_at_infinity(Q)) {
		*R = *P;
		return;
	}
	if (ossl_sm9_z256_point_is_at_infinity(P)) {
		*R = *Q;
		return;
	}

	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *X2 = Q->X;
	const uint64_t *Y2 = Q->Y;
	const uint64_t *Z2 = Q->Z;

	ossl_sm9_z256_t X3, Y3, Z3, T1, T2, U1, U2, S1, S2, H, I;

	ossl_sm9_z256_modp_mont_sqr(T1, Z1);
	ossl_sm9_z256_modp_mont_sqr(T2, Z2);
	ossl_sm9_z256_modp_mont_mul(U1, X1, T2);
	ossl_sm9_z256_modp_mont_mul(U2, X2, T1);
	ossl_sm9_z256_modp_add(Z3, Z1, Z2);
	ossl_sm9_z256_modp_mont_sqr(Z3, Z3);
	ossl_sm9_z256_modp_sub(Z3, Z3, T1);
	ossl_sm9_z256_modp_sub(Z3, Z3, T2);
	ossl_sm9_z256_modp_mont_mul(T1, T1, Z1);
	ossl_sm9_z256_modp_mont_mul(T2, T2, Z2);
	ossl_sm9_z256_modp_mont_mul(S1, Y1, T2);
	ossl_sm9_z256_modp_mont_mul(S2, Y2, T1);
	ossl_sm9_z256_modp_sub(H, U2, U1);
	ossl_sm9_z256_modp_sub(U2, S2, S1);
	if (ossl_sm9_z256_is_zero(H)) {
		if (ossl_sm9_z256_is_zero(U2)) {
			ossl_sm9_z256_point_dbl(R, Q);
			return;
		} else {
			ossl_sm9_z256_point_set_infinity(R);
			return;
		}
	}
	ossl_sm9_z256_modp_mont_mul(Z3, Z3, H);
	ossl_sm9_z256_modp_dbl(I, H);
	ossl_sm9_z256_modp_mont_sqr(I, I);
	ossl_sm9_z256_modp_mont_mul(H, H, I);
	ossl_sm9_z256_modp_mont_mul(I, U1, I);
	ossl_sm9_z256_modp_dbl(U2, U2);
	ossl_sm9_z256_modp_mont_sqr(X3, U2);
	ossl_sm9_z256_modp_sub(X3, H, X3);
	ossl_sm9_z256_modp_tri(Y3, I);
	ossl_sm9_z256_modp_add(X3, Y3, X3);
	ossl_sm9_z256_modp_mont_mul(Y3, U2, X3);
	ossl_sm9_z256_modp_mont_mul(S1, S1, H);
	ossl_sm9_z256_modp_dbl(S1, S1);
	ossl_sm9_z256_modp_sub(Y3, Y3, S1);
	ossl_sm9_z256_modp_sub(X3, I, X3);

	ossl_sm9_z256_copy(R->X, X3);
	ossl_sm9_z256_copy(R->Y, Y3);
	ossl_sm9_z256_copy(R->Z, Z3);
}

void ossl_sm9_z256_point_neg(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P)
{
	ossl_sm9_z256_copy(R->X, P->X);
	ossl_sm9_z256_modp_neg(R->Y, P->Y);
	ossl_sm9_z256_copy(R->Z, P->Z);
}

void ossl_sm9_z256_point_sub(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q)
{
	OSSL_SM9_Z256_POINT T;
	ossl_sm9_z256_point_neg(&T, Q);
	ossl_sm9_z256_point_add(R, P, &T);
}

void ossl_sm9_z256_point_dbl_x5(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *A)

{
	ossl_sm9_z256_point_dbl(R, A);
	ossl_sm9_z256_point_dbl(R, R);
	ossl_sm9_z256_point_dbl(R, R);
	ossl_sm9_z256_point_dbl(R, R);
	ossl_sm9_z256_point_dbl(R, R);
}

void ossl_sm9_z256_point_mul(OSSL_SM9_Z256_POINT *R, const ossl_sm9_z256_t k, const OSSL_SM9_Z256_POINT *P)
{
	uint64_t window_size = 5;
	OSSL_SM9_Z256_POINT T[16];
	int R_infinity = 1;
	int n = (int)((256 + window_size - 1)/window_size);
	int i;

	// T[i] = (i + 1) * P
	T[0] = *P;

	ossl_sm9_z256_point_dbl(&T[2-1], &T[1-1]);
	ossl_sm9_z256_point_dbl(&T[4-1], &T[2-1]);
	ossl_sm9_z256_point_dbl(&T[8-1], &T[4-1]);
	ossl_sm9_z256_point_dbl(&T[16-1], &T[8-1]);
	ossl_sm9_z256_point_add(&T[3-1], &T[2-1], P);
	ossl_sm9_z256_point_dbl(&T[6-1], &T[3-1]);
	ossl_sm9_z256_point_dbl(&T[12-1], &T[6-1]);
	ossl_sm9_z256_point_add(&T[5-1], &T[3-1], &T[2-1]);
	ossl_sm9_z256_point_dbl(&T[10-1], &T[5-1]);
	ossl_sm9_z256_point_add(&T[7-1], &T[4-1], &T[3-1]);
	ossl_sm9_z256_point_dbl(&T[14-1], &T[7-1]);
	ossl_sm9_z256_point_add(&T[9-1], &T[4-1], &T[5-1]);
	ossl_sm9_z256_point_add(&T[11-1], &T[6-1], &T[5-1]);
	ossl_sm9_z256_point_add(&T[13-1], &T[7-1], &T[6-1]);
	ossl_sm9_z256_point_add(&T[15-1], &T[8-1], &T[7-1]);


	for (i = n - 1; i >= 0; i--) {
		int booth = ossl_sm9_z256_get_booth(k, window_size, i);

		if (R_infinity) {
			if (booth != 0) {
				*R = T[booth - 1];
				R_infinity = 0;
			}
		} else {
			ossl_sm9_z256_point_dbl_x5(R, R);

			if (booth > 0) {
				ossl_sm9_z256_point_add(R, R, &T[booth - 1]);
			} else if (booth < 0) {
				ossl_sm9_z256_point_sub(R, R, &T[-booth - 1]);
			}
		}
	}

	if (R_infinity) {
		memset(R, 0, sizeof(*R));
	}
}

void ossl_sm9_z256_point_copy_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_AFFINE_POINT *P)
{
	ossl_sm9_z256_copy(R->X, P->X);
	ossl_sm9_z256_copy(R->Y, P->Y);
	ossl_sm9_z256_copy(R->Z, OSSL_SM9_Z256_MODP_MONT_ONE);
}

void ossl_sm9_z256_point_add_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q)
{
	const uint64_t *X1 = P->X;
	const uint64_t *Y1 = P->Y;
	const uint64_t *Z1 = P->Z;
	const uint64_t *X2 = Q->X;
	const uint64_t *Y2 = Q->Y;

	ossl_sm9_z256_t X3, Y3, Z3, T1, S2, H, I;

	ossl_sm9_z256_modp_mont_sqr(T1, Z1);
	ossl_sm9_z256_modp_mont_mul(H, X2, T1);
	ossl_sm9_z256_modp_sub(H, H, X1);
	ossl_sm9_z256_modp_add(Z3, Z1, H);
	ossl_sm9_z256_modp_mont_sqr(Z3, Z3);
	ossl_sm9_z256_modp_sub(Z3, Z3, T1);
	ossl_sm9_z256_modp_mont_mul(T1, T1, Z1);
	ossl_sm9_z256_modp_mont_mul(S2, Y2, T1);
	ossl_sm9_z256_modp_mont_sqr(T1, H);
	ossl_sm9_z256_modp_sub(Z3, Z3, T1);
	ossl_sm9_z256_modp_dbl(I, T1);
	ossl_sm9_z256_modp_dbl(I, I);
	ossl_sm9_z256_modp_mont_mul(H, H, I);
	ossl_sm9_z256_modp_mont_mul(I, X1, I);
	ossl_sm9_z256_modp_sub(S2, S2, Y1);
	ossl_sm9_z256_modp_dbl(S2, S2);
	ossl_sm9_z256_modp_mont_sqr(X3, S2);
	ossl_sm9_z256_modp_sub(X3, H, X3);
	ossl_sm9_z256_modp_tri(Y3, I);
	ossl_sm9_z256_modp_add(X3, Y3, X3);
	ossl_sm9_z256_modp_mont_mul(Y3, S2, X3);
	ossl_sm9_z256_modp_mont_mul(H, H, Y1);
	ossl_sm9_z256_modp_dbl(H, H);
	ossl_sm9_z256_modp_sub(Y3, Y3, H);
	ossl_sm9_z256_modp_sub(X3, I, X3);

	ossl_sm9_z256_copy(R->X, X3);
	ossl_sm9_z256_copy(R->Y, Y3);
	ossl_sm9_z256_copy(R->Z, Z3);
}

void ossl_sm9_z256_point_sub_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q)
{
	OSSL_SM9_Z256_AFFINE_POINT _T, *T = &_T;
	ossl_sm9_z256_copy(T->X, Q->X);
	ossl_sm9_z256_modp_neg(T->Y, Q->Y);
	ossl_sm9_z256_point_add_affine(R, P, T);
}








int ossl_sm9_z256_twist_point_is_at_infinity(const OSSL_SM9_Z256_TWIST_POINT *P)
{
	return ossl_sm9_z256_fp2_is_zero(P->Z);
}

void ossl_sm9_z256_twist_point_set_infinity(OSSL_SM9_Z256_TWIST_POINT *R)
{
	ossl_sm9_z256_fp2_set_one(R->X);
	ossl_sm9_z256_fp2_set_one(R->Y);
	ossl_sm9_z256_fp2_set_zero(R->Z);
}

void ossl_sm9_z256_twist_point_get_xy(const OSSL_SM9_Z256_TWIST_POINT *P, ossl_sm9_z256_fp2_t x, ossl_sm9_z256_fp2_t y)
{
	ossl_sm9_z256_fp2_t z_inv;

	assert(!ossl_sm9_z256_fp2_is_zero(P->Z));

	if (ossl_sm9_z256_fp2_is_one(P->Z)) {
		ossl_sm9_z256_fp2_copy(x, P->X);
		ossl_sm9_z256_fp2_copy(y, P->Y);
	}

	ossl_sm9_z256_fp2_inv(z_inv, P->Z);
	if (y)
		ossl_sm9_z256_fp2_mul(y, P->Y, z_inv);
	ossl_sm9_z256_fp2_sqr(z_inv, z_inv);
	ossl_sm9_z256_fp2_mul(x, P->X, z_inv);
	if (y)
		ossl_sm9_z256_fp2_mul(y, y, z_inv);
}

int ossl_sm9_z256_twist_point_equ(const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q)
{
	ossl_sm9_z256_fp2_t t1, t2, t3, t4;

	ossl_sm9_z256_fp2_sqr(t1, P->Z);
	ossl_sm9_z256_fp2_sqr(t2, Q->Z);
	ossl_sm9_z256_fp2_mul(t3, P->X, t2);
	ossl_sm9_z256_fp2_mul(t4, Q->X, t1);
	if (!ossl_sm9_z256_fp2_equ(t3, t4)) {
		return 0;
	}
	ossl_sm9_z256_fp2_mul(t1, t1, P->Z);
	ossl_sm9_z256_fp2_mul(t2, t2, Q->Z);
	ossl_sm9_z256_fp2_mul(t3, P->Y, t2);
	ossl_sm9_z256_fp2_mul(t4, Q->Y, t1);
	return ossl_sm9_z256_fp2_equ(t3, t4);
}

int ossl_sm9_z256_twist_point_is_on_curve(const OSSL_SM9_Z256_TWIST_POINT *P)
{
	ossl_sm9_z256_fp2_t t0, t1, t2;

	if (ossl_sm9_z256_fp2_is_one(P->Z)) {
		ossl_sm9_z256_fp2_sqr(t0, P->Y);
		ossl_sm9_z256_fp2_sqr(t1, P->X);
		ossl_sm9_z256_fp2_mul(t1, t1, P->X);
		ossl_sm9_z256_fp2_add(t1, t1, OSSL_SM9_Z256_FP2_MONT_5U);

	} else {
		ossl_sm9_z256_fp2_sqr(t0, P->X);
		ossl_sm9_z256_fp2_mul(t0, t0, P->X);
		ossl_sm9_z256_fp2_sqr(t1, P->Z);
		ossl_sm9_z256_fp2_sqr(t2, t1);
		ossl_sm9_z256_fp2_mul(t1, t1, t2);
		ossl_sm9_z256_fp2_mul(t1, t1, OSSL_SM9_Z256_FP2_MONT_5U);
		ossl_sm9_z256_fp2_add(t1, t0, t1);
		ossl_sm9_z256_fp2_sqr(t0, P->Y);
	}

	return ossl_sm9_z256_fp2_equ(t0, t1);
}

void ossl_sm9_z256_twist_point_neg(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	ossl_sm9_z256_fp2_copy(R->X, P->X);
	ossl_sm9_z256_fp2_neg(R->Y, P->Y);
	ossl_sm9_z256_fp2_copy(R->Z, P->Z);
}

void ossl_sm9_z256_twist_point_dbl(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;
	ossl_sm9_z256_fp2_t X3, Y3, Z3, T1, T2, T3;

	if (ossl_sm9_z256_twist_point_is_at_infinity(P)) {
		*R = *P;
		return;
	}
	ossl_sm9_z256_fp2_sqr(T2, X1);
	ossl_sm9_z256_fp2_tri(T2, T2);
	ossl_sm9_z256_fp2_dbl(Y3, Y1);
	ossl_sm9_z256_fp2_mul(Z3, Y3, Z1);
	ossl_sm9_z256_fp2_sqr(Y3, Y3);
	ossl_sm9_z256_fp2_mul(T3, Y3, X1);
	ossl_sm9_z256_fp2_sqr(Y3, Y3);
	ossl_sm9_z256_fp2_haf(Y3, Y3);
	ossl_sm9_z256_fp2_sqr(X3, T2);
	ossl_sm9_z256_fp2_dbl(T1, T3);
	ossl_sm9_z256_fp2_sub(X3, X3, T1);
	ossl_sm9_z256_fp2_sub(T1, T3, X3);
	ossl_sm9_z256_fp2_mul(T1, T1, T2);
	ossl_sm9_z256_fp2_sub(Y3, T1, Y3);

	ossl_sm9_z256_fp2_copy(R->X, X3);
	ossl_sm9_z256_fp2_copy(R->Y, Y3);
	ossl_sm9_z256_fp2_copy(R->Z, Z3);
}

void ossl_sm9_z256_twist_point_add(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;
	const ossl_sm9_z256_t *x2 = Q->X;
	const ossl_sm9_z256_t *y2 = Q->Y;
	ossl_sm9_z256_fp2_t X3, Y3, Z3, T1, T2, T3, T4;

	if (ossl_sm9_z256_twist_point_is_at_infinity(Q)) {
		*R = *P;
		return;
	}
	if (ossl_sm9_z256_twist_point_is_at_infinity(P)) {
		*R = *Q;
		return;
	}

	ossl_sm9_z256_fp2_sqr(T1, Z1);
	ossl_sm9_z256_fp2_mul(T2, T1, Z1);
	ossl_sm9_z256_fp2_mul(T1, T1, x2);
	ossl_sm9_z256_fp2_mul(T2, T2, y2);
	ossl_sm9_z256_fp2_sub(T1, T1, X1);
	ossl_sm9_z256_fp2_sub(T2, T2, Y1);
	if (ossl_sm9_z256_fp2_is_zero(T1)) {
		if (ossl_sm9_z256_fp2_is_zero(T2)) {
			ossl_sm9_z256_twist_point_dbl(R, Q);
			return;
		} else {
			ossl_sm9_z256_twist_point_set_infinity(R);
			return;
		}
	}
	ossl_sm9_z256_fp2_mul(Z3, Z1, T1);
	ossl_sm9_z256_fp2_sqr(T3, T1);
	ossl_sm9_z256_fp2_mul(T4, T3, T1);
	ossl_sm9_z256_fp2_mul(T3, T3, X1);
	ossl_sm9_z256_fp2_dbl(T1, T3);
	ossl_sm9_z256_fp2_sqr(X3, T2);
	ossl_sm9_z256_fp2_sub(X3, X3, T1);
	ossl_sm9_z256_fp2_sub(X3, X3, T4);
	ossl_sm9_z256_fp2_sub(T3, T3, X3);
	ossl_sm9_z256_fp2_mul(T3, T3, T2);
	ossl_sm9_z256_fp2_mul(T4, T4, Y1);
	ossl_sm9_z256_fp2_sub(Y3, T3, T4);

	ossl_sm9_z256_fp2_copy(R->X, X3);
	ossl_sm9_z256_fp2_copy(R->Y, Y3);
	ossl_sm9_z256_fp2_copy(R->Z, Z3);
}

void ossl_sm9_z256_twist_point_sub(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q)
{
	OSSL_SM9_Z256_TWIST_POINT _T, *T = &_T;
	ossl_sm9_z256_twist_point_neg(T, Q);
	ossl_sm9_z256_twist_point_add_full(R, P, T);
}

void ossl_sm9_z256_twist_point_add_full(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;
	const ossl_sm9_z256_t *X2 = Q->X;
	const ossl_sm9_z256_t *Y2 = Q->Y;
	const ossl_sm9_z256_t *Z2 = Q->Z;
	ossl_sm9_z256_fp2_t T1, T2, T3, T4, T5, T6, T7, T8;

	if (ossl_sm9_z256_twist_point_is_at_infinity(Q)) {
		*R = *P;
		return;
	}
	if (ossl_sm9_z256_twist_point_is_at_infinity(P)) {
		*R = *Q;
		return;
	}

	ossl_sm9_z256_fp2_sqr(T1, Z1);
	ossl_sm9_z256_fp2_sqr(T2, Z2);
	ossl_sm9_z256_fp2_mul(T3, X2, T1);
	ossl_sm9_z256_fp2_mul(T4, X1, T2);
	ossl_sm9_z256_fp2_add(T5, T3, T4);
	ossl_sm9_z256_fp2_sub(T3, T3, T4);
	ossl_sm9_z256_fp2_mul(T1, T1, Z1);
	ossl_sm9_z256_fp2_mul(T1, T1, Y2);
	ossl_sm9_z256_fp2_mul(T2, T2, Z2);
	ossl_sm9_z256_fp2_mul(T2, T2, Y1);
	ossl_sm9_z256_fp2_add(T6, T1, T2);
	ossl_sm9_z256_fp2_sub(T1, T1, T2);

	if (ossl_sm9_z256_fp2_is_zero(T1) && ossl_sm9_z256_fp2_is_zero(T3)) {
		ossl_sm9_z256_twist_point_dbl(R, P);
		return;
	}
	if (ossl_sm9_z256_fp2_is_zero(T1) && ossl_sm9_z256_fp2_is_zero(T6)) {
		ossl_sm9_z256_twist_point_set_infinity(R);
		return;
	}

	ossl_sm9_z256_fp2_sqr(T6, T1);
	ossl_sm9_z256_fp2_mul(T7, T3, Z1);
	ossl_sm9_z256_fp2_mul(T7, T7, Z2);
	ossl_sm9_z256_fp2_sqr(T8, T3);
	ossl_sm9_z256_fp2_mul(T5, T5, T8);
	ossl_sm9_z256_fp2_mul(T3, T3, T8);
	ossl_sm9_z256_fp2_mul(T4, T4, T8);
	ossl_sm9_z256_fp2_sub(T6, T6, T5);
	ossl_sm9_z256_fp2_sub(T4, T4, T6);
	ossl_sm9_z256_fp2_mul(T1, T1, T4);
	ossl_sm9_z256_fp2_mul(T2, T2, T3);
	ossl_sm9_z256_fp2_sub(T1, T1, T2);

	ossl_sm9_z256_fp2_copy(R->X, T6);
	ossl_sm9_z256_fp2_copy(R->Y, T1);
	ossl_sm9_z256_fp2_copy(R->Z, T7);
}

void ossl_sm9_z256_twist_point_mul(OSSL_SM9_Z256_TWIST_POINT *R, const ossl_sm9_z256_t k, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	OSSL_SM9_Z256_TWIST_POINT _Q, *Q = &_Q;
	char kbits[256];
	int i;

	ossl_sm9_z256_to_bits(k, kbits);
	ossl_sm9_z256_twist_point_set_infinity(Q);
	for (i = 0; i < 256; i++) {
		ossl_sm9_z256_twist_point_dbl(Q, Q);
		if (kbits[i] == '1') {
			ossl_sm9_z256_twist_point_add_full(Q, Q, P);
		}
	}
	*R = *Q;
}

void ossl_sm9_z256_twist_point_mul_generator(OSSL_SM9_Z256_TWIST_POINT *R, const ossl_sm9_z256_t k)
{
	ossl_sm9_z256_twist_point_mul(R, k, &OSSL_SM9_Z256_MONT_P2);
}

#if 0
void ossl_sm9_z256_eval_g_tangent(ossl_sm9_z256_fp12_t num, ossl_sm9_z256_fp12_t den,
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_POINT *Q)
{
	ossl_sm9_z256_t x;
	ossl_sm9_z256_t y;

	// FIXME: use full formula
	ossl_sm9_z256_point_get_xy(Q, x, y);
	ossl_sm9_z256_modp_to_mont(x, x);
	ossl_sm9_z256_modp_to_mont(y, y);

	const ossl_sm9_z256_t *XP = P->X;
	const ossl_sm9_z256_t *YP = P->Y;
	const ossl_sm9_z256_t *ZP = P->Z;
	const uint64_t *xQ = x;
	const uint64_t *yQ = y;

	ossl_sm9_z256_t *a0 = num[0][0];
	ossl_sm9_z256_t *a1 = num[0][1];
	ossl_sm9_z256_t *a4 = num[2][0];
	ossl_sm9_z256_t *b1 = den[0][1];

	ossl_sm9_z256_fp2_t t0;
	ossl_sm9_z256_fp2_t t1;
	ossl_sm9_z256_fp2_t t2;

	ossl_sm9_z256_fp12_set_zero(num);
	ossl_sm9_z256_fp12_set_zero(den);

	ossl_sm9_z256_fp2_sqr(t0, ZP);
	ossl_sm9_z256_fp2_mul(t1, t0, ZP);
	ossl_sm9_z256_fp2_mul(b1, t1, YP);

	ossl_sm9_z256_fp2_mul_fp(t2, b1, yQ);
	ossl_sm9_z256_fp2_neg(a1, t2);

	ossl_sm9_z256_fp2_sqr(t1, XP);
	ossl_sm9_z256_fp2_mul(t0, t0, t1);
	ossl_sm9_z256_fp2_mul_fp(t0, t0, xQ);
	ossl_sm9_z256_fp2_tri(t0, t0);
	ossl_sm9_z256_fp2_haf(a4, t0);

	ossl_sm9_z256_fp2_mul(t1, t1, XP);
	ossl_sm9_z256_fp2_tri(t1, t1);
	ossl_sm9_z256_fp2_haf(t1, t1);
	ossl_sm9_z256_fp2_sqr(t0, YP);
	ossl_sm9_z256_fp2_sub(a0, t0, t1);
}

void ossl_sm9_z256_eval_g_line(ossl_sm9_z256_fp12_t num, ossl_sm9_z256_fp12_t den,
	const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_POINT *Q)
{
	ossl_sm9_z256_t x;
	ossl_sm9_z256_t y;

	// FIXME: use full formula
	ossl_sm9_z256_point_get_xy(Q, x, y);
	ossl_sm9_z256_modp_to_mont(x, x);
	ossl_sm9_z256_modp_to_mont(y, y);

	const ossl_sm9_z256_t *XT = T->X;
	const ossl_sm9_z256_t *YT = T->Y;
	const ossl_sm9_z256_t *ZT = T->Z;
	const ossl_sm9_z256_t *XP = P->X;
	const ossl_sm9_z256_t *YP = P->Y;
	const ossl_sm9_z256_t *ZP = P->Z;
	const uint64_t *xQ = x;
	const uint64_t *yQ = y;

	ossl_sm9_z256_t *a0 = num[0][0];
	ossl_sm9_z256_t *a1 = num[0][1];
	ossl_sm9_z256_t *a4 = num[2][0];
	ossl_sm9_z256_t *b1 = den[0][1];

	ossl_sm9_z256_fp2_t T0, T1, T2, T3, T4;


	ossl_sm9_z256_fp12_set_zero(num);
	ossl_sm9_z256_fp12_set_zero(den);

	ossl_sm9_z256_fp2_sqr(T0, ZP);
	ossl_sm9_z256_fp2_mul(T1, T0, XT);
	ossl_sm9_z256_fp2_mul(T0, T0, ZP);
	ossl_sm9_z256_fp2_sqr(T2, ZT);
	ossl_sm9_z256_fp2_mul(T3, T2, XP);
	ossl_sm9_z256_fp2_mul(T2, T2, ZT);
	ossl_sm9_z256_fp2_mul(T2, T2, YP);
	ossl_sm9_z256_fp2_sub(T1, T1, T3);
	ossl_sm9_z256_fp2_mul(T1, T1, ZT);
	ossl_sm9_z256_fp2_mul(T1, T1, ZP);
	ossl_sm9_z256_fp2_mul(T4, T1, T0);
	ossl_sm9_z256_fp2_copy(b1, T4);
	ossl_sm9_z256_fp2_mul(T1, T1, YP);
	ossl_sm9_z256_fp2_mul(T3, T0, YT);
	ossl_sm9_z256_fp2_sub(T3, T3, T2);
	ossl_sm9_z256_fp2_mul(T0, T0, T3);
	ossl_sm9_z256_fp2_mul_fp(T0, T0, xQ);
	ossl_sm9_z256_fp2_copy(a4, T0);
	ossl_sm9_z256_fp2_mul(T3, T3, XP);
	ossl_sm9_z256_fp2_mul(T3, T3, ZP);
	ossl_sm9_z256_fp2_sub(T1, T1, T3);
	ossl_sm9_z256_fp2_copy(a0, T1);
	ossl_sm9_z256_fp2_mul_fp(T2, T4, yQ);
	ossl_sm9_z256_fp2_neg(T2, T2);
	ossl_sm9_z256_fp2_copy(a1, T2);
}
#endif

// g_line = lw[0] + lw[1] * w^2 + lw[2] * w^3, R = 2P
void ossl_sm9_z256_eval_g_tangent(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;

	ossl_sm9_z256_fp2_t X3, Y3, Z3, A, B, C, D, T1;

	ossl_sm9_z256_fp2_sqr(T1, Z1);
	ossl_sm9_z256_fp2_sqr(A, X1);
	ossl_sm9_z256_fp2_sqr(B, Y1);
	ossl_sm9_z256_fp2_sqr(C, B);
	ossl_sm9_z256_fp2_add(D, X1, B);
	ossl_sm9_z256_fp2_sqr(D, D);
	ossl_sm9_z256_fp2_sub(D, D, A);
	ossl_sm9_z256_fp2_sub(D, D, C);
	ossl_sm9_z256_fp2_dbl(D, D);
	ossl_sm9_z256_fp2_add(Z3, Y1, Z1);
	ossl_sm9_z256_fp2_sqr(Z3, Z3);
	ossl_sm9_z256_fp2_sub(Z3, Z3, B);
	ossl_sm9_z256_fp2_sub(Z3, Z3, T1);
	ossl_sm9_z256_fp2_dbl(lw[0], B);
	ossl_sm9_z256_fp2_dbl(lw[0], lw[0]);
	ossl_sm9_z256_fp2_add(lw[0], lw[0], A);
	ossl_sm9_z256_fp2_tri(A, A);
	ossl_sm9_z256_fp2_sqr(B, A);
	ossl_sm9_z256_fp2_dbl(X3, D);
	ossl_sm9_z256_fp2_sub(X3, B, X3);
	ossl_sm9_z256_fp2_add(lw[0], lw[0], B);
	ossl_sm9_z256_fp2_sub(Y3, D, X3);
	ossl_sm9_z256_fp2_mul(Y3, Y3, A);
	ossl_sm9_z256_fp2_dbl(C, C);
	ossl_sm9_z256_fp2_dbl(C, C);
	ossl_sm9_z256_fp2_dbl(C, C);
	ossl_sm9_z256_fp2_sub(Y3, Y3, C);
	ossl_sm9_z256_fp2_mul(lw[2], Z3, T1);
	ossl_sm9_z256_fp2_dbl(lw[2], lw[2]);
	ossl_sm9_z256_fp2_mul(lw[1], A, T1);
	ossl_sm9_z256_fp2_dbl(lw[1], lw[1]);
	ossl_sm9_z256_fp2_neg(lw[1], lw[1]);
	ossl_sm9_z256_fp2_add(A, X1, A);
	ossl_sm9_z256_fp2_sqr(A, A);
	ossl_sm9_z256_fp2_sub(lw[0], A, lw[0]);
	ossl_sm9_z256_fp2_mul_fp(lw[1], lw[1], Q->X);
	ossl_sm9_z256_fp2_mul_fp(lw[2], lw[2], Q->Y);

	ossl_sm9_z256_fp2_copy(R->X, X3);
	ossl_sm9_z256_fp2_copy(R->Y, Y3);
	ossl_sm9_z256_fp2_copy(R->Z, Z3);
}

// g_line = lw[0] + lw[1] * w^2 + lw[2] * w^3, R = P+T
void ossl_sm9_z256_eval_g_line(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3], ossl_sm9_z256_fp2_t pre[5],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_AFFINE_POINT *Q)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;
	const ossl_sm9_z256_t *X2 = T->X;
	const ossl_sm9_z256_t *Y2 = T->Y;
	const ossl_sm9_z256_t *Z2 = T->Z;

	ossl_sm9_z256_fp2_t X3, Y3, Z3, T1, T2, A, B, C, D;

	ossl_sm9_z256_fp2_sqr(T1, Z1);
	ossl_sm9_z256_fp2_sqr(T2, Z2);
	ossl_sm9_z256_fp2_add(Z3, Z1, Z2);
	ossl_sm9_z256_fp2_sqr(Z3, Z3);
	ossl_sm9_z256_fp2_sub(Z3, Z3, T1);
	ossl_sm9_z256_fp2_sub(Z3, Z3, T2);
	ossl_sm9_z256_fp2_mul(A, X1, T2);
	ossl_sm9_z256_fp2_mul(B, X2, T1);
	ossl_sm9_z256_fp2_mul(C, Y1, pre[1]);
	ossl_sm9_z256_fp2_dbl(C, C);
	ossl_sm9_z256_fp2_add(D, Y2, Z1);
	ossl_sm9_z256_fp2_sqr(D, D);
	ossl_sm9_z256_fp2_sub(D, D, pre[0]);
	ossl_sm9_z256_fp2_sub(D, D, T1);
	ossl_sm9_z256_fp2_mul(D, D, T1);
	ossl_sm9_z256_fp2_sub(B, B, A);
	ossl_sm9_z256_fp2_mul(Z3, Z3, B);
	ossl_sm9_z256_fp2_dbl(T1, B);
	ossl_sm9_z256_fp2_sqr(T1, T1);
	ossl_sm9_z256_fp2_mul(X3, B, T1);
	ossl_sm9_z256_fp2_mul(Y3, C, X3);
	ossl_sm9_z256_fp2_mul(A, A, T1);
	ossl_sm9_z256_fp2_sub(B, D, C);
	ossl_sm9_z256_fp2_dbl(T2, A);
	ossl_sm9_z256_fp2_add(X3, X3, T2);
	ossl_sm9_z256_fp2_sqr(T2, B);
	ossl_sm9_z256_fp2_sub(X3, T2, X3);
	ossl_sm9_z256_fp2_sub(T2, A, X3);
	ossl_sm9_z256_fp2_mul(T2, T2, B);
	ossl_sm9_z256_fp2_sub(Y3, T2, Y3);
	ossl_sm9_z256_fp2_mul(lw[2], Z3, pre[2]);
	ossl_sm9_z256_fp2_mul(lw[1], B, pre[3]);
	ossl_sm9_z256_fp2_mul(B, B, pre[4]);
	ossl_sm9_z256_fp2_mul(lw[0], Y2, Z3);
	ossl_sm9_z256_fp2_dbl(lw[0], lw[0]);
	ossl_sm9_z256_fp2_sub(lw[0], B, lw[0]);

	ossl_sm9_z256_fp2_copy(R->X, X3);
	ossl_sm9_z256_fp2_copy(R->Y, Y3);
	ossl_sm9_z256_fp2_copy(R->Z, Z3);
}

void ossl_sm9_z256_eval_g_line_no_pre(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_AFFINE_POINT *Q)
{
	const ossl_sm9_z256_t *X1 = P->X;
	const ossl_sm9_z256_t *Y1 = P->Y;
	const ossl_sm9_z256_t *Z1 = P->Z;
	const ossl_sm9_z256_t *X2 = T->X;
	const ossl_sm9_z256_t *Y2 = T->Y;
	const ossl_sm9_z256_t *Z2 = T->Z;

	ossl_sm9_z256_fp2_t pre[5];
	ossl_sm9_z256_fp2_sqr(pre[0], T->Y);
	ossl_sm9_z256_fp2_mul(pre[4], T->X, T->Z);
	ossl_sm9_z256_fp2_dbl(pre[4], pre[4]);
	ossl_sm9_z256_fp2_sqr(pre[1], T->Z);
	ossl_sm9_z256_fp2_mul(pre[1], pre[1], T->Z);
	ossl_sm9_z256_fp2_mul_fp(pre[2], pre[1], Q->Y);
	ossl_sm9_z256_fp2_dbl(pre[2], pre[2]);
	ossl_sm9_z256_fp2_mul_fp(pre[3], pre[1], Q->X);
	ossl_sm9_z256_fp2_dbl(pre[3], pre[3]);
	ossl_sm9_z256_fp2_neg(pre[3], pre[3]);

	ossl_sm9_z256_fp2_t X3, Y3, Z3, T1, T2, A, B, C, D;

	ossl_sm9_z256_fp2_sqr(T1, Z1);
	ossl_sm9_z256_fp2_sqr(T2, Z2);
	ossl_sm9_z256_fp2_add(Z3, Z1, Z2);
	ossl_sm9_z256_fp2_sqr(Z3, Z3);
	ossl_sm9_z256_fp2_sub(Z3, Z3, T1);
	ossl_sm9_z256_fp2_sub(Z3, Z3, T2);
	ossl_sm9_z256_fp2_mul(A, X1, T2);
	ossl_sm9_z256_fp2_mul(B, X2, T1);
	ossl_sm9_z256_fp2_mul(C, Y1, pre[1]);
	ossl_sm9_z256_fp2_dbl(C, C);
	ossl_sm9_z256_fp2_add(D, Y2, Z1);
	ossl_sm9_z256_fp2_sqr(D, D);
	ossl_sm9_z256_fp2_sub(D, D, pre[0]);
	ossl_sm9_z256_fp2_sub(D, D, T1);
	ossl_sm9_z256_fp2_mul(D, D, T1);
	ossl_sm9_z256_fp2_sub(B, B, A);
	ossl_sm9_z256_fp2_mul(Z3, Z3, B);
	ossl_sm9_z256_fp2_dbl(T1, B);
	ossl_sm9_z256_fp2_sqr(T1, T1);
	ossl_sm9_z256_fp2_mul(X3, B, T1);
	ossl_sm9_z256_fp2_mul(Y3, C, X3);
	ossl_sm9_z256_fp2_mul(A, A, T1);
	ossl_sm9_z256_fp2_sub(B, D, C);
	ossl_sm9_z256_fp2_dbl(T2, A);
	ossl_sm9_z256_fp2_add(X3, X3, T2);
	ossl_sm9_z256_fp2_sqr(T2, B);
	ossl_sm9_z256_fp2_sub(X3, T2, X3);
	ossl_sm9_z256_fp2_sub(T2, A, X3);
	ossl_sm9_z256_fp2_mul(T2, T2, B);
	ossl_sm9_z256_fp2_sub(Y3, T2, Y3);
	ossl_sm9_z256_fp2_mul(lw[2], Z3, pre[2]);
	ossl_sm9_z256_fp2_mul(lw[1], B, pre[3]);
	ossl_sm9_z256_fp2_mul(B, B, pre[4]);
	ossl_sm9_z256_fp2_mul(lw[0], Y2, Z3);
	ossl_sm9_z256_fp2_dbl(lw[0], lw[0]);
	ossl_sm9_z256_fp2_sub(lw[0], B, lw[0]);

	ossl_sm9_z256_fp2_copy(R->X, X3);
	ossl_sm9_z256_fp2_copy(R->Y, Y3);
	ossl_sm9_z256_fp2_copy(R->Z, Z3);
}

void ossl_sm9_z256_twist_point_pi1(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	// c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
	// mont version
	const ossl_sm9_z256_t c = {0x1a98dfbd4575299f, 0x9ec8547b245c54fd, 0xf51f5eac13df846c, 0x9ef74015d5a16393};
	ossl_sm9_z256_fp2_conjugate(R->X, P->X);
	ossl_sm9_z256_fp2_conjugate(R->Y, P->Y);
	ossl_sm9_z256_fp2_conjugate(R->Z, P->Z);
	ossl_sm9_z256_fp2_mul_fp(R->Z, R->Z, c);

}

void ossl_sm9_z256_twist_point_pi2(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	// c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	// mont version
	const ossl_sm9_z256_t c = {0xb626197dce4736ca, 0x8296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992};
	ossl_sm9_z256_fp2_copy(R->X, P->X);
	ossl_sm9_z256_fp2_copy(R->Y, P->Y);
	ossl_sm9_z256_fp2_mul_fp(R->Z, P->Z, c);
}

void ossl_sm9_z256_twist_point_neg_pi2(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P)
{
	// c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
	// mont version
	const ossl_sm9_z256_t c = {0xb626197dce4736ca, 0x8296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992};
	ossl_sm9_z256_fp2_copy(R->X, P->X);
	ossl_sm9_z256_fp2_neg(R->Y, P->Y);
	ossl_sm9_z256_fp2_mul_fp(R->Z, P->Z, c);
}


void ossl_sm9_z256_final_exponent_hard_part(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t f)
{
	// a2 = 0xd8000000019062ed0000b98b0cb27659
	// a3 = 0x2400000000215d941
	const ossl_sm9_z256_t a2 = {0x0000b98b0cb27659, 0xd8000000019062ed, 0, 0};
	const ossl_sm9_z256_t a3 = {0x400000000215d941, 0x2, 0, 0};
	const ossl_sm9_z256_t nine = {9,0,0,0};
	ossl_sm9_z256_fp12_t t0, t1, t2, t3;

	ossl_sm9_z256_fp12_pow(t0, f, a3);
	ossl_sm9_z256_fp12_inv(t0, t0);
	ossl_sm9_z256_fp12_frobenius(t1, t0);
	ossl_sm9_z256_fp12_mul(t1, t0, t1);

	ossl_sm9_z256_fp12_mul(t0, t0, t1);
	ossl_sm9_z256_fp12_frobenius(t2, f);
	ossl_sm9_z256_fp12_mul(t3, t2, f);
	ossl_sm9_z256_fp12_pow(t3, t3, nine);

	ossl_sm9_z256_fp12_mul(t0, t0, t3);
	ossl_sm9_z256_fp12_sqr(t3, f);
	ossl_sm9_z256_fp12_sqr(t3, t3);
	ossl_sm9_z256_fp12_mul(t0, t0, t3);
	ossl_sm9_z256_fp12_sqr(t2, t2);
	ossl_sm9_z256_fp12_mul(t2, t2, t1);
	ossl_sm9_z256_fp12_frobenius2(t1, f);
	ossl_sm9_z256_fp12_mul(t1, t1, t2);

	ossl_sm9_z256_fp12_pow(t2, t1, a2);
	ossl_sm9_z256_fp12_mul(t0, t2, t0);
	ossl_sm9_z256_fp12_frobenius3(t1, f);
	ossl_sm9_z256_fp12_mul(t1, t1, t0);

	ossl_sm9_z256_fp12_copy(r, t1);
}

void ossl_sm9_z256_final_exponent(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t f)
{
	ossl_sm9_z256_fp12_t t0;
	ossl_sm9_z256_fp12_t t1;

	ossl_sm9_z256_fp12_frobenius6(t0, f);
	ossl_sm9_z256_fp12_inv(t1, f);
	ossl_sm9_z256_fp12_mul(t0, t0, t1);
	ossl_sm9_z256_fp12_frobenius2(t1, t0);
	ossl_sm9_z256_fp12_mul(t0, t0, t1);
	ossl_sm9_z256_final_exponent_hard_part(t0, t0);

	ossl_sm9_z256_fp12_copy(r, t0);
}

#if 0
void ossl_sm9_z256_pairing(ossl_sm9_z256_fp12_t r, const OSSL_SM9_Z256_TWIST_POINT *Q, const OSSL_SM9_Z256_POINT *P)
{
	const char *abits = "00100000000000000000000000000000000000010000101100020200101000020";

	OSSL_SM9_Z256_TWIST_POINT T;
	OSSL_SM9_Z256_TWIST_POINT Q1;
	OSSL_SM9_Z256_TWIST_POINT Q2;

	ossl_sm9_z256_fp12_t f_num;
	ossl_sm9_z256_fp12_t f_den;
	ossl_sm9_z256_fp12_t g_num;
	ossl_sm9_z256_fp12_t g_den;
	int i;

	T = *Q;

	ossl_sm9_z256_fp12_set_one(f_num);
	ossl_sm9_z256_fp12_set_one(f_den);

	for (i = 0; i < strlen(abits); i++) {
		ossl_sm9_z256_fp12_sqr(f_num, f_num);
		ossl_sm9_z256_fp12_sqr(f_den, f_den);
		ossl_sm9_z256_eval_g_tangent(g_num, g_den, &T, P);
		ossl_sm9_z256_fp12_mul(f_num, f_num, g_num);
		ossl_sm9_z256_fp12_mul(f_den, f_den, g_den);

		ossl_sm9_z256_twist_point_dbl(&T, &T);

		if (abits[i] == '1') {
			ossl_sm9_z256_eval_g_line(g_num, g_den, &T, Q, P);
			ossl_sm9_z256_fp12_mul(f_num, f_num, g_num);
			ossl_sm9_z256_fp12_mul(f_den, f_den, g_den);
			ossl_sm9_z256_twist_point_add_full(&T, &T, Q);
		} else if (abits[i] == '2') {
			ossl_sm9_z256_twist_point_neg(&Q1, Q);
			ossl_sm9_z256_eval_g_line(g_num, g_den, &T, &Q1, P);
			ossl_sm9_z256_fp12_mul(f_num, f_num, g_num);
			ossl_sm9_z256_fp12_mul(f_den, f_den, g_den);
			ossl_sm9_z256_twist_point_add_full(&T, &T, &Q1);
		}
	}

	ossl_sm9_z256_twist_point_pi1(&Q1, Q);
	ossl_sm9_z256_twist_point_neg_pi2(&Q2, Q);

	ossl_sm9_z256_eval_g_line(g_num, g_den, &T, &Q1, P);
	ossl_sm9_z256_fp12_mul(f_num, f_num, g_num);
	ossl_sm9_z256_fp12_mul(f_den, f_den, g_den);
	ossl_sm9_z256_twist_point_add_full(&T, &T, &Q1);

	ossl_sm9_z256_eval_g_line(g_num, g_den, &T, &Q2, P);
	ossl_sm9_z256_fp12_mul(f_num, f_num, g_num);
	ossl_sm9_z256_fp12_mul(f_den, f_den, g_den);
	ossl_sm9_z256_twist_point_add_full(&T, &T, &Q2);

	ossl_sm9_z256_fp12_inv(f_den, f_den);
	ossl_sm9_z256_fp12_mul(r, f_num, f_den);

	ossl_sm9_z256_final_exponent(r, r);
}
#endif

void ossl_sm9_z256_point_to_affine(OSSL_SM9_Z256_AFFINE_POINT *Q, const OSSL_SM9_Z256_POINT *P)
{
	ossl_sm9_z256_t z_inv;

	assert(!ossl_sm9_z256_is_zero(P->Z));

	if (ossl_sm9_z256_equ(P->Z, OSSL_SM9_Z256_MODP_MONT_ONE)) {
		ossl_sm9_z256_copy(Q->X, P->X);
		ossl_sm9_z256_copy(Q->Y, P->Y);
		return;
	}

	ossl_sm9_z256_modp_mont_inv(z_inv, P->Z);
	ossl_sm9_z256_modp_mont_mul(Q->Y, P->Y, z_inv);
	ossl_sm9_z256_modp_mont_sqr(z_inv, z_inv);
	ossl_sm9_z256_modp_mont_mul(Q->X, P->X, z_inv);
	ossl_sm9_z256_modp_mont_mul(Q->Y, Q->Y, z_inv);
}

// Multiplication with lw[0] + lw[1] * w^2 + lw[2] * w^3
void ossl_sm9_z256_fp12_line_mul(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp2_t lw[3])
{
	ossl_sm9_z256_fp4_t r0, r1, r2;
	ossl_sm9_z256_fp2_t t;

	ossl_sm9_z256_fp4_t lw4;
	ossl_sm9_z256_fp2_copy(lw4[0], lw[0]);
	ossl_sm9_z256_fp2_copy(lw4[1], lw[2]);

	ossl_sm9_z256_fp4_mul(r0, a[0], lw4);
	ossl_sm9_z256_fp4_mul(r1, a[1], lw4);
	ossl_sm9_z256_fp4_mul(r2, a[2], lw4);

	ossl_sm9_z256_fp2_mul  (t, a[0][0], lw[1]);
	ossl_sm9_z256_fp2_add  (r2[0], r2[0], t);
	ossl_sm9_z256_fp2_mul  (t, a[0][1], lw[1]);
	ossl_sm9_z256_fp2_add  (r2[1], r2[1], t);
	ossl_sm9_z256_fp2_mul  (t, a[1][0], lw[1]);
	ossl_sm9_z256_fp2_add  (r0[1], r0[1], t);
	ossl_sm9_z256_fp2_mul_u(t, a[1][1], lw[1]);
	ossl_sm9_z256_fp2_add  (r0[0], r0[0], t);
	ossl_sm9_z256_fp2_mul  (t, a[2][0], lw[1]);
	ossl_sm9_z256_fp2_add  (r1[1], r1[1], t);
	ossl_sm9_z256_fp2_mul_u(t, a[2][1], lw[1]);
	ossl_sm9_z256_fp2_add  (r1[0], r1[0], t);

	ossl_sm9_z256_fp4_copy(r[0], r0);
	ossl_sm9_z256_fp4_copy(r[1], r1);
	ossl_sm9_z256_fp4_copy(r[2], r2);
}

void ossl_sm9_z256_pairing(ossl_sm9_z256_fp12_t r, const OSSL_SM9_Z256_TWIST_POINT *Q, const OSSL_SM9_Z256_POINT *P)
{
	const char *abits = "00100000000000000000000000000000000000010000101100020200101000020";

	OSSL_SM9_Z256_TWIST_POINT T;
	OSSL_SM9_Z256_TWIST_POINT Q1;
	OSSL_SM9_Z256_TWIST_POINT Q2;
	OSSL_SM9_Z256_AFFINE_POINT P_;
	ossl_sm9_z256_fp2_t lw[3];
	ossl_sm9_z256_fp2_t pre[5]; // same for Q and -Q
	size_t i;

	ossl_sm9_z256_fp2_copy(T.X, Q->X);
	ossl_sm9_z256_fp2_copy(T.Y, Q->Y);
	ossl_sm9_z256_fp2_copy(T.Z, Q->Z);

	ossl_sm9_z256_point_to_affine(&P_, P);
	ossl_sm9_z256_twist_point_neg(&Q1, Q);

	ossl_sm9_z256_fp2_sqr(pre[0], Q->Y);
	ossl_sm9_z256_fp2_mul(pre[4], Q->X, Q->Z);
	ossl_sm9_z256_fp2_dbl(pre[4], pre[4]);
	ossl_sm9_z256_fp2_sqr(pre[1], Q->Z);
	ossl_sm9_z256_fp2_mul(pre[1], pre[1], Q->Z);
	ossl_sm9_z256_fp2_mul_fp(pre[2], pre[1], P_.Y);
	ossl_sm9_z256_fp2_dbl(pre[2], pre[2]);
	ossl_sm9_z256_fp2_mul_fp(pre[3], pre[1], P_.X);
	ossl_sm9_z256_fp2_dbl(pre[3], pre[3]);
	ossl_sm9_z256_fp2_neg(pre[3], pre[3]);

	ossl_sm9_z256_fp12_set_one(r);

	for (i = 0; i < strlen(abits); i++) {
		ossl_sm9_z256_fp12_sqr(r, r);
		ossl_sm9_z256_eval_g_tangent(&T, lw, &T, &P_);
		ossl_sm9_z256_fp12_line_mul(r, r, lw);

		if (abits[i] == '1') {
			//ossl_sm9_z256_eval_g_line_no_pre(&T, lw, &T, Q, &P_);
			ossl_sm9_z256_eval_g_line(&T, lw, pre, &T, Q, &P_);
			ossl_sm9_z256_fp12_line_mul(r, r, lw);
		} else if (abits[i] == '2') {
			//ossl_sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
			ossl_sm9_z256_eval_g_line(&T, lw, pre, &T, &Q1, &P_);
			ossl_sm9_z256_fp12_line_mul(r, r, lw);
		}
	}

	ossl_sm9_z256_twist_point_pi1(&Q1, Q);
	ossl_sm9_z256_twist_point_neg_pi2(&Q2, Q);

	ossl_sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
	ossl_sm9_z256_fp12_line_mul(r, r, lw);

	ossl_sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q2, &P_);
	ossl_sm9_z256_fp12_line_mul(r, r, lw);

	ossl_sm9_z256_final_exponent(r, r);
}

void ossl_sm9_z256_modn_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t c;
	c = ossl_sm9_z256_add(r, a, b);

	if (c) {
		// a + b - n = (a + b - 2^256) + (2^256 - n)
		(void)ossl_sm9_z256_add(r, r, OSSL_SM9_Z256_NEG_N);
		return;
	}
	if (ossl_sm9_z256_cmp(r, OSSL_SM9_Z256_N) >= 0) {
		(void)ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_N);
	}
}

void ossl_sm9_z256_modn_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t c;
	c = ossl_sm9_z256_sub(r, a, b);

	if (c) {
		// a - b + n = (a - b + 2^256) - (2^256 - n)
		(void)ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_NEG_N);
	}
}

static void sm9_z320_mul(uint64_t r[10], const uint64_t a[5], const uint64_t b[5])
{
	uint64_t a_[10];
	uint64_t b_[10];
	uint64_t s[20] = {0};
	uint64_t u;
	int i, j;

	for (i = 0; i < 5; i++) {
		a_[2 * i] = a[i] & 0xffffffff;
		b_[2 * i] = b[i] & 0xffffffff;
		a_[2 * i + 1] = a[i] >> 32;
		b_[2 * i + 1] = b[i] >> 32;
	}

	for (i = 0; i < 10; i++) {
		u = 0;
		for (j = 0; j < 10; j++) {
			u = s[i + j] + a_[i] * b_[j] + u;
			s[i + j] = u & 0xffffffff;
			u >>= 32;
		}
		s[i + 10] = u;
	}

	for (i = 0; i < 10; i++) {
		r[i] = (s[2 * i + 1] << 32) | s[2 * i];
	}
}

static const uint64_t OSSL_SM9_Z256_N_BARRETT_MU[5] = {
	0x74df4fd4dfc97c2f, 0x9c95d85ec9c073b0, 0x55f73aebdcd1312c, 0x67980e0beb5759a6, 0x1,
};

void ossl_sm9_z256_modn_mul(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b)
{
	uint64_t z[8], h[10], s[8];
	uint64_t t, c = 0;

	ossl_sm9_z256_mul(z, a, b);

	// (z // 2^192) = z[3-7]
	sm9_z320_mul(h, z + 3, OSSL_SM9_Z256_N_BARRETT_MU);

	// (h // 2^320) = h[5-9]
	ossl_sm9_z256_mul(s, h + 5, OSSL_SM9_Z256_N);

	// h[5-9] * N % 2^320 = (h[5-8]*N + 2^256 * (N[0]*h[9])%2^64) % 2^320
	s[4] += OSSL_SM9_Z256_N[0] * h[9];

	// s[0-4] = z[0-4] - s[0-4] (% 2^320)
	t = z[0] - s[0];
	c = t > z[0];
	r[0] = t;

	t = z[1] - c;
	c = t > z[1];
	r[1] = t - s[1];
	c += r[1] > t;

	t = z[2] - c;
	c = t > z[2];
	r[2] = t - s[2];
	c += r[2] > t;

	t = z[3] - c;
	c = t > z[3];
	r[3] = t - s[3];
	c += r[3] > t;

	t = z[4] - c;
	s[4] = t - s[4]; // we put r[4] in s[4]

	if (s[4] > 0 || ossl_sm9_z256_cmp(r, OSSL_SM9_Z256_N) >= 0) { // r >= N
		ossl_sm9_z256_sub(r, r, OSSL_SM9_Z256_N);
	}
}


void ossl_sm9_z256_modn_pow(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t e)
{
	ossl_sm9_z256_t t;
	uint64_t w;
	int i, j;

	ossl_sm9_z256_copy(t, OSSL_SM9_Z256_ONE);

	for (i = 3; i >= 0; i--) {
		w = e[i];
		for (j = 0; j < 64; j++) {
			ossl_sm9_z256_modn_mul(t, t, t);
			if (w & 0x8000000000000000) {
				ossl_sm9_z256_modn_mul(t, t, a);
			}
			w <<= 1;
		}
	}
	ossl_sm9_z256_copy(r, t);
}

// a^-1 (mod n) = a^(n - 2) (mod n)
// n - 2 =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf23
static const ossl_sm9_z256_t OSSL_SM9_Z256_N_MINUS_TWO = {
	0xe56ee19cd69ecf23, 0x49f2934b18ea8bee, 0xd603ab4ff58ec744, 0xb640000002a3a6f1
};

void ossl_sm9_z256_modn_inv(ossl_sm9_z256_t r, const ossl_sm9_z256_t a)
{
	ossl_sm9_z256_modn_pow(r, a, OSSL_SM9_Z256_N_MINUS_TWO);
}

const ossl_sm9_z256_t OSSL_SM9_Z256_N_MINUS_ONE_BARRETT_MU = {
	0x74df4fd4dfc97c31, 0x9c95d85ec9c073b0, 0x55f73aebdcd1312c, 0x67980e0beb5759a6
};

void ossl_sm9_z256_modn_from_hash(ossl_sm9_z256_t h, const uint8_t Ha[40])
{
	int i;
	uint64_t z[8] = {0};
	uint64_t r[9] = {0};
	uint64_t c = 0, t = 0;

	for (i = 0; i < 5; i++) {
		z[4-i] = GETU64(Ha + (8*i));
	}

	// (z // 2^192) = z[3], z[4]
	ossl_sm9_z256_mul(r, z + 3, OSSL_SM9_Z256_N_MINUS_ONE_BARRETT_MU); // most to r[5]
	// (r[4], r[5]) += (z[3], z[4])
	r[4] += z[3];
	c = r[4] < z[3];
	t = z[4] + c;
	c = t < z[4];
	r[5] += t;
	c += r[5] < t;
	r[6] = c;

	// (r // 2^320) = (r[5], r[6])
	ossl_sm9_z256_mul(r, r + 5, OSSL_SM9_Z256_N_MINUS_ONE);
	ossl_sm9_z256_sub(h, z, r);

	ossl_sm9_z256_modn_add(h, h, OSSL_SM9_Z256_ONE);
}

int ossl_sm9_z256_point_to_uncompressed_octets(const OSSL_SM9_Z256_POINT *P, uint8_t octets[65])
{
	ossl_sm9_z256_t x;
	ossl_sm9_z256_t y;

	ossl_sm9_z256_point_get_xy(P, x, y);

	octets[0] = 0x04;
	ossl_sm9_z256_to_bytes(x, octets + 1);
	ossl_sm9_z256_to_bytes(y, octets + 32 + 1);
	return 1;
}

int ossl_sm9_z256_point_from_uncompressed_octets(OSSL_SM9_Z256_POINT *P, const uint8_t octets[65])
{
	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}

	ossl_sm9_z256_from_bytes(P->X, octets + 1);
	if (ossl_sm9_z256_cmp(P->X, OSSL_SM9_Z256_P) >= 0) {
		error_print();
		return -1;
	}
	ossl_sm9_z256_modp_to_mont(P->X, P->X);

	ossl_sm9_z256_from_bytes(P->Y, octets + 32 + 1);
	if (ossl_sm9_z256_cmp(P->Y, OSSL_SM9_Z256_P) >= 0) {
		error_print();
		return -1;
	}
	ossl_sm9_z256_modp_to_mont(P->Y, P->Y);

	ossl_sm9_z256_copy(P->Z, OSSL_SM9_Z256_MODP_MONT_ONE);

	if (!ossl_sm9_z256_point_is_on_curve(P)) {
		error_print();
		return -1;
	}
	return 1;
}

int ossl_sm9_z256_twist_point_to_uncompressed_octets(const OSSL_SM9_Z256_TWIST_POINT *P, uint8_t octets[129])
{
	octets[0] = 0x04;
	ossl_sm9_z256_fp2_t x;
	ossl_sm9_z256_fp2_t y;
	ossl_sm9_z256_twist_point_get_xy(P, x, y);
	ossl_sm9_z256_fp2_to_bytes(x, octets + 1);
	ossl_sm9_z256_fp2_to_bytes(y, octets + 32 * 2 + 1);
	return 1;
}

int ossl_sm9_z256_twist_point_from_uncompressed_octets(OSSL_SM9_Z256_TWIST_POINT *P, const uint8_t octets[129])
{
	if (octets[0] != 0x04) {
		error_print();
		return -1;
	}

	if (ossl_sm9_z256_fp2_from_bytes(P->X, octets + 1) != 1) {
		error_print();
		return -1;
	}
	if (ossl_sm9_z256_fp2_from_bytes(P->Y, octets + 32 * 2 + 1) != 1) {
		error_print();
		return -1;
	}
	ossl_sm9_z256_fp2_set_one(P->Z);

	if (!ossl_sm9_z256_twist_point_is_on_curve(P)) {
		error_print();
		return -1;
	}
	return 1;
}

void ossl_sm9_z256_point_mul_generator(OSSL_SM9_Z256_POINT *r, const ossl_sm9_z256_t k)
{
    ossl_sm9_z256_point_mul(r, k, ossl_sm9_z256_generator());
}
