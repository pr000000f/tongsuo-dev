/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License"). See LICENSE.txt.
 */
#ifndef OPENSSL_PAIRING_H
# define OPENSSL_PAIRING_H
# include <openssl/opensslconf.h>
# include <openssl/ec.h>
# include <openssl/bn.h>
# ifndef OPENSSL_NO_PAIRING
# ifdef __cplusplus
extern "C" {
# endif

/* SM9 BN256, GM/T 0044.5: G1 over Fp, G2 over Fp2, GT in Fp12.
 * This experimental arithmetic backend is not a constant-time implementation.
 * G1 uses the existing EC_GROUP/EC_POINT API. Scalars are canonical [0,n).
 * Encodings: G1 SEC1 (65), G2 04||x1||x0||y1||y0 (129), GT SM9 (384).
 * Decoders reject infinity/zero and elements outside the prime-order subgroup.
 */
typedef struct pairing_g2_st PAIRING_G2;
typedef struct pairing_gt_st PAIRING_GT;
EC_GROUP *PAIRING_GROUP_new_sm9(void);
PAIRING_G2 *PAIRING_G2_new(void);
void PAIRING_G2_free(PAIRING_G2 *p);
int PAIRING_G2_generator(PAIRING_G2 *p);
int PAIRING_G2_mul(PAIRING_G2 *r, const PAIRING_G2 *p, const BIGNUM *k);
int PAIRING_G2_to_bytes(const PAIRING_G2 *p, unsigned char out[129]);
int PAIRING_G2_from_bytes(PAIRING_G2 *p, const unsigned char *in, size_t len);
PAIRING_GT *PAIRING_GT_new(void);
void PAIRING_GT_free(PAIRING_GT *a);
int PAIRING_apply(PAIRING_GT *r, const EC_POINT *p, const PAIRING_G2 *q);
int PAIRING_GT_mul(PAIRING_GT *r, const PAIRING_GT *a, const PAIRING_GT *b);
int PAIRING_GT_inv(PAIRING_GT *r, const PAIRING_GT *a);
int PAIRING_GT_pow(PAIRING_GT *r, const PAIRING_GT *a, const BIGNUM *k);
int PAIRING_GT_cmp(const PAIRING_GT *a, const PAIRING_GT *b);
int PAIRING_GT_to_bytes(const PAIRING_GT *a, unsigned char out[384]);
int PAIRING_GT_from_bytes(PAIRING_GT *a, const unsigned char *in, size_t len);
# ifdef __cplusplus
}
# endif
# endif
#endif
