/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OSSL_CRYPTO_PAIRING_SM9_LOCAL_H
#define OSSL_CRYPTO_PAIRING_SM9_LOCAL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef uint64_t ossl_sm9_z256_t[4];

void ossl_sm9_z256_set_one(ossl_sm9_z256_t r);
void ossl_sm9_z256_set_zero(ossl_sm9_z256_t r);
void ossl_sm9_z256_copy(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_copy_conditional(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, uint64_t move);
int  ossl_sm9_z256_cmp(const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
uint64_t ossl_sm9_z256_is_zero(const ossl_sm9_z256_t a);
uint64_t ossl_sm9_z256_equ(const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
uint64_t ossl_sm9_z256_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
uint64_t ossl_sm9_z256_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_mul(uint64_t r[8], const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_from_bytes(ossl_sm9_z256_t r, const uint8_t in[32]);
void ossl_sm9_z256_to_bytes(const ossl_sm9_z256_t a, uint8_t out[32]);
void ossl_sm9_z256_to_bits(const ossl_sm9_z256_t a, char bits[256]);

const uint64_t *ossl_sm9_z256_prime(void);

void ossl_sm9_z256_modp_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modp_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modp_dbl(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_tri(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_haf(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_neg(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);

void ossl_sm9_z256_modp_to_mont(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_from_mont(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_mont_mul(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modp_mont_sqr(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modp_mont_pow(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t e);
void ossl_sm9_z256_modp_mont_inv(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);

const uint64_t *ossl_sm9_z256_order(void);

void ossl_sm9_z256_modn_add(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modn_sub(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modn_mul(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t b);
void ossl_sm9_z256_modn_pow(ossl_sm9_z256_t r, const ossl_sm9_z256_t a, const ossl_sm9_z256_t e);
void ossl_sm9_z256_modn_inv(ossl_sm9_z256_t r, const ossl_sm9_z256_t a);
void ossl_sm9_z256_modn_from_hash(ossl_sm9_z256_t h, const uint8_t Ha[40]);


typedef ossl_sm9_z256_t ossl_sm9_z256_fp2_t[2];

void ossl_sm9_z256_fp2_set_one(ossl_sm9_z256_fp2_t r);
void ossl_sm9_z256_fp2_set_zero(ossl_sm9_z256_fp2_t r);
int  ossl_sm9_z256_fp2_is_one(const ossl_sm9_z256_fp2_t a);
int  ossl_sm9_z256_fp2_is_zero(const ossl_sm9_z256_fp2_t a);
int  ossl_sm9_z256_fp2_equ(const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_copy(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_to_bytes(const ossl_sm9_z256_fp2_t a, uint8_t buf[64]);
int  ossl_sm9_z256_fp2_from_bytes(ossl_sm9_z256_fp2_t r, const uint8_t buf[64]);
void ossl_sm9_z256_fp2_add(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_dbl(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_tri(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_sub(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_neg(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_a_mul_u(ossl_sm9_z256_fp2_t r, ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_mul(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_mul_u(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_mul_fp(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_t k);
void ossl_sm9_z256_fp2_sqr(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_sqr_u(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_inv(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_div(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a, const ossl_sm9_z256_fp2_t b);
void ossl_sm9_z256_fp2_haf(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_conjugate(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);
void ossl_sm9_z256_fp2_frobenius(ossl_sm9_z256_fp2_t r, const ossl_sm9_z256_fp2_t a);


typedef ossl_sm9_z256_fp2_t ossl_sm9_z256_fp4_t[2];

int  ossl_sm9_z256_fp4_is_zero(const ossl_sm9_z256_fp4_t a);
int  ossl_sm9_z256_fp4_equ(const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b);
void ossl_sm9_z256_fp4_copy(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_to_bytes(const ossl_sm9_z256_fp4_t a, uint8_t buf[128]);
int  ossl_sm9_z256_fp4_from_bytes(ossl_sm9_z256_fp4_t r, const uint8_t buf[128]);
void ossl_sm9_z256_fp4_add(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b);
void ossl_sm9_z256_fp4_dbl(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_sub(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b);
void ossl_sm9_z256_fp4_neg(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_haf(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_a_mul_v(ossl_sm9_z256_fp4_t r, ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_mul(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b);
void ossl_sm9_z256_fp4_mul_fp(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_t k);
void ossl_sm9_z256_fp4_mul_fp2(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp2_t b0);
void ossl_sm9_z256_fp4_mul_v(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a, const ossl_sm9_z256_fp4_t b);
void ossl_sm9_z256_fp4_sqr(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_sqr_v(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_inv(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_frobenius(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_conjugate(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_frobenius2(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);
void ossl_sm9_z256_fp4_frobenius3(ossl_sm9_z256_fp4_t r, const ossl_sm9_z256_fp4_t a);


typedef ossl_sm9_z256_fp4_t ossl_sm9_z256_fp12_t[3];

void ossl_sm9_z256_fp12_set_one(ossl_sm9_z256_fp12_t r);
void ossl_sm9_z256_fp12_set_zero(ossl_sm9_z256_fp12_t r);
void ossl_sm9_z256_fp12_copy(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_to_bytes(const ossl_sm9_z256_fp12_t a, uint8_t buf[384]);
int  ossl_sm9_z256_fp12_from_bytes(ossl_sm9_z256_fp12_t r, const uint8_t buf[384]);

void ossl_sm9_z256_fp12_set(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp4_t a0, const ossl_sm9_z256_fp4_t a1, const ossl_sm9_z256_fp4_t a2);
int  ossl_sm9_z256_fp12_equ(const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b);
void ossl_sm9_z256_fp12_add(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b);
void ossl_sm9_z256_fp12_dbl(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_tri(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_sub(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b);
void ossl_sm9_z256_fp12_neg(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_mul(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp12_t b);
void ossl_sm9_z256_fp12_sqr(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_inv(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a);
void ossl_sm9_z256_fp12_pow(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_t k);
void ossl_sm9_z256_fp12_frobenius(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x);
void ossl_sm9_z256_fp12_frobenius2(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x);
void ossl_sm9_z256_fp12_frobenius3(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x);
void ossl_sm9_z256_fp12_frobenius6(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t x);


// E(F_p): y^2 = x^3 + 5

typedef struct {
	ossl_sm9_z256_t X; // is mont(X)
	ossl_sm9_z256_t Y; // is mont(Y)
	ossl_sm9_z256_t Z; // is mont(Z)
} OSSL_SM9_Z256_POINT;

const OSSL_SM9_Z256_POINT *ossl_sm9_z256_generator(void);

int  ossl_sm9_z256_point_is_at_infinity(const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_point_set_infinity(OSSL_SM9_Z256_POINT *R);
void ossl_sm9_z256_point_get_xy(const OSSL_SM9_Z256_POINT *P, ossl_sm9_z256_t x, ossl_sm9_z256_t y);
int  ossl_sm9_z256_point_equ(const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q);
int  ossl_sm9_z256_point_is_on_curve(const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_point_dbl(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_point_neg(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_point_add(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q);
void ossl_sm9_z256_point_sub(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_POINT *Q);
void ossl_sm9_z256_point_mul(OSSL_SM9_Z256_POINT *R, const ossl_sm9_z256_t k, const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_point_mul_generator(OSSL_SM9_Z256_POINT *R, const ossl_sm9_z256_t k);
int  ossl_sm9_z256_point_to_uncompressed_octets(const OSSL_SM9_Z256_POINT *P, uint8_t octets[65]);
int  ossl_sm9_z256_point_from_uncompressed_octets(OSSL_SM9_Z256_POINT *P, const uint8_t octets[65]);


typedef struct {
	uint64_t X[4];
	uint64_t Y[4];
} OSSL_SM9_Z256_AFFINE_POINT;

void ossl_sm9_z256_point_copy_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_AFFINE_POINT *P);
void ossl_sm9_z256_point_add_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q);
void ossl_sm9_z256_point_sub_affine(OSSL_SM9_Z256_POINT *R, const OSSL_SM9_Z256_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q);


typedef struct {
	ossl_sm9_z256_fp2_t X;
	ossl_sm9_z256_fp2_t Y;
	ossl_sm9_z256_fp2_t Z;
} OSSL_SM9_Z256_TWIST_POINT;

const OSSL_SM9_Z256_TWIST_POINT *ossl_sm9_z256_twist_generator(void);

int ossl_sm9_z256_twist_point_to_uncompressed_octets(const OSSL_SM9_Z256_TWIST_POINT *P, uint8_t octets[129]);
int ossl_sm9_z256_twist_point_from_uncompressed_octets(OSSL_SM9_Z256_TWIST_POINT *P, const uint8_t octets[129]);

int  ossl_sm9_z256_twist_point_is_at_infinity(const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_set_infinity(OSSL_SM9_Z256_TWIST_POINT *R);
void ossl_sm9_z256_twist_point_get_xy(const OSSL_SM9_Z256_TWIST_POINT *P, ossl_sm9_z256_fp2_t x, ossl_sm9_z256_fp2_t y);
int  ossl_sm9_z256_twist_point_equ(const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q);
int  ossl_sm9_z256_twist_point_is_on_curve(const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_neg(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_dbl(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_add(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q);
void ossl_sm9_z256_twist_point_sub(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q);
void ossl_sm9_z256_twist_point_add_full(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *Q);
void ossl_sm9_z256_twist_point_mul(OSSL_SM9_Z256_TWIST_POINT *R, const ossl_sm9_z256_t k, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_mul_generator(OSSL_SM9_Z256_TWIST_POINT *R, const ossl_sm9_z256_t k);


void ossl_sm9_z256_point_to_affine(OSSL_SM9_Z256_AFFINE_POINT *Q, const OSSL_SM9_Z256_POINT *P);
void ossl_sm9_z256_eval_g_tangent(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_AFFINE_POINT *Q);
void ossl_sm9_z256_eval_g_line(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3], ossl_sm9_z256_fp2_t pre[5],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_AFFINE_POINT *Q);
void ossl_sm9_z256_eval_g_line_no_pre(OSSL_SM9_Z256_TWIST_POINT *R, ossl_sm9_z256_fp2_t lw[3],
	const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_AFFINE_POINT *Q);
void ossl_sm9_z256_fp12_line_mul(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t a, const ossl_sm9_z256_fp2_t lw[3]);
//void ossl_sm9_z256_eval_g_tangent(ossl_sm9_z256_fp12_t num, ossl_sm9_z256_fp12_t den, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_POINT *Q);
//void ossl_sm9_z256_eval_g_line(ossl_sm9_z256_fp12_t num, ossl_sm9_z256_fp12_t den, const OSSL_SM9_Z256_TWIST_POINT *T, const OSSL_SM9_Z256_TWIST_POINT *P, const OSSL_SM9_Z256_POINT *Q);
void ossl_sm9_z256_twist_point_pi1(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_pi2(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_twist_point_neg_pi2(OSSL_SM9_Z256_TWIST_POINT *R, const OSSL_SM9_Z256_TWIST_POINT *P);
void ossl_sm9_z256_final_exponent_hard_part(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t f);
void ossl_sm9_z256_final_exponent(ossl_sm9_z256_fp12_t r, const ossl_sm9_z256_fp12_t f);
void ossl_sm9_z256_pairing(ossl_sm9_z256_fp12_t r, const OSSL_SM9_Z256_TWIST_POINT *Q, const OSSL_SM9_Z256_POINT *P);


#ifdef  __cplusplus
}
#endif
#endif
