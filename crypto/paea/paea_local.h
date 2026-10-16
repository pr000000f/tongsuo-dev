/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OSSL_CRYPTO_PAEA_LOCAL_H
# define OSSL_CRYPTO_PAEA_LOCAL_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_PAEA

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/paea.h>
# include "crypto/paeaerr.h"

/*
 * ZYHW mechanism (GB/T 34953.4-XXXX, 7.3), based on the auxiliary storage
 * PAEA model.  In the elliptic curve instantiation the multiplicative
 * notation of the standard text maps to the EC additive group as follows:
 *
 *   g^k          -> k * g          (generator g = generator of the curve)
 *   g1 * g2      -> G1 + G2
 *   g1 / g2      -> G1 - G2
 *   x^(1/y)      -> x * 1/y        (scalars reduced mod q, the group order)
 *
 * Cross reference to the standard text:
 *   7.3.2 setup:          r, w = g^r, signing key pair (pk, sk)
 *   7.3.3 registration:   m = BS2IP(H_lamda(I_U)) mod q,
 *                         sigma = (1/(r+m)) * g,
 *                         sigma_pw = sigma + H_g(pw),
 *                         W = (1/(r+m)) * B_n     (revocation only)
 *   7.3.4 authentication: 3-pass protocol Sign_sk / ZK proof of (m, a, ...)
 *   7.3.5 revocation:     the same r (and w = g^r already in params).
 *                         CRL = { <m_i, B_i> }, with
 *                         B_i = (1/prod_{j<=i}(r+m_j)) * g    (B_n = g on an
 *                         empty CRL, i.e. the empty product is 1), and the
 *                         witness update W' = (W - B_{j+1}) * 1/(m_{j+1}-m)
 *                         Server check: P = r * M.
 *
 * The standard does not define a wire encoding. Lengths that the curve
 * or the digest already determine are written with no length prefix:
 *   point    uncompressed GB/T 32918.1 4.2.9, width fixed by the field
 *   scalar   |q| bytes (q = group order, not the field prime)
 *   c        |H| bytes, the hash as an integer, not reduced mod q
 * A field whose size is not determined that way (DER, a name) is a
 * 4-byte length followed by the value.
 */

/*
 * Object format version for the serialised params/crl blobs.
 * Bumped whenever those layouts change.
 */
# define PAEA_BLOB_VERSION          3

/*
 * Maximum number of retries for the hash-to-group "try and increment"
 * construction of H_g().  2^256 attempts are way beyond a collision, 64
 * is already overkill for any sane curve.
 */
# define PAEA_MAX_HG_TRIES           64

/* Reasonable sanity limits for parsed blobs and CRLs.
 * Integers are scalars or a hash; 128 covers P-521 and EVP_MAX_MD_SIZE. */
# define PAEA_MAX_BLOB_LEN           (1 << 20)
# define PAEA_MAX_INT_LEN            128
# define PAEA_MAX_CRL_ENTRIES        (1 << 20)

/*
 * SM2 signing user id.  Both ends use the GB/T 32918.2 default,
 * "1234567812345678".
 */
# define PAEA_SM2_DEFAULT_ID         "1234567812345678"

/* Fixed widths, no length prefix. Return the number of bytes written, or 0.
 * paea_point_len is the uncompressed size of a finite point on group.
 * paea_put_bn / paea_get_bn use the caller-supplied width (|q| or |H|). */
size_t paea_point_len(const EC_GROUP *group);
size_t paea_put_point(const EC_GROUP *group, unsigned char *p,
                     const EC_POINT *pt);
size_t paea_put_bn(size_t len, unsigned char *p, const BIGNUM *bn);

/* On success *pp / *rem move past the field. *data points into the
 * caller's buffer; nothing is copied. paea_get_bytes is for a field
 * that still carries a 4-byte length. */
int paea_get_bytes(const unsigned char **pp, size_t *rem,
                 const unsigned char **data, size_t *len);
int paea_get_point(const EC_GROUP *group, const unsigned char **pp,
                       size_t *rem, EC_POINT *pt);
int paea_get_bn(const unsigned char **pp, size_t *rem, size_t len, BIGNUM *bn);

/* Low level primitives */
int paea_check_group(const EC_GROUP *group);
int paea_rand_in_zq_star(const BIGNUM *q, BIGNUM *out);
int paea_h_g(const EC_GROUP *group, const EVP_MD *md,
             const unsigned char *in, size_t in_len, EC_POINT *out);

int paea_sig_sign(EVP_PKEY *pkey, const EVP_MD *md,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char **out, size_t *out_len);
int paea_sig_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t sig_len,
                    const unsigned char *msg, size_t msg_len);

# endif /* OPENSSL_NO_PAEA */
#endif /* OSSL_CRYPTO_PAEA_LOCAL_H */
