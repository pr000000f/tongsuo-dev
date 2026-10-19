/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#ifndef OSSL_PAEA_ELGAMAL_H
# define OSSL_PAEA_ELGAMAL_H
# include <openssl/bn.h>
/* Fixed RFC 3526 group 15, generator 4, 3072-bit modulus P.  P > q^2
 * for the SM9 order q: decrypting Enc(r)*Enc(s) recovers the integer r*s.
 * This is the draft's textbook multiplicative ElGamal, not EC_ELGAMAL.
 * Ciphertext is c1||c2 (384 bytes each); plaintext is an integer [1,P).
 */
# define PAEA_HE_BYTES 384
# define PAEA_HE_CT_BYTES (2 * PAEA_HE_BYTES)
typedef struct {
    BIGNUM *p, *order, *pub, *priv;
} PAEA_HE_KEY;
PAEA_HE_KEY *ossl_paea_he_new(void);
void ossl_paea_he_free(PAEA_HE_KEY *key);
int ossl_paea_he_generate(PAEA_HE_KEY *key);
int ossl_paea_he_set_public(PAEA_HE_KEY *key, const unsigned char in[384]);
int ossl_paea_he_encrypt(const PAEA_HE_KEY *key, const BIGNUM *m,
                         unsigned char out[768]);
int ossl_paea_he_decrypt(const PAEA_HE_KEY *key, const unsigned char in[768],
                         BIGNUM *m);
int ossl_paea_he_mul(const PAEA_HE_KEY *key, const unsigned char a[768],
                     const unsigned char b[768], unsigned char out[768]);
#endif
