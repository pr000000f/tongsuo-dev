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

/*
 * ZYHW (GB/T 34953.4-XXXX 7.3) common helpers: fixed-width point and
 * integer fields, H_g(), H_lamda(I_U), sampling from Z_q* and the
 * server signature helpers.
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

/* EC_GROUP_method_of() and EC_POINTs_mul() are used below; they are the
 * recommended EC primitives inside libcrypto. */
#include "internal/deprecated.h"

#include "paea_local.h"

#define PAEA_MAX_RAND_TRIES     128

/*
 * 7.3.2 (via 6.2.1 a): prime-field curve, cofactor 1, or 2 when a
 * cofactor-1 curve is not available.
 */
int paea_check_group(const EC_GROUP *group)
{
    BIGNUM *cofactor = NULL;
    int ok = 0;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
            != NID_X9_62_prime_field)
        goto end;
    cofactor = BN_new();
    if (cofactor == NULL
        || EC_GROUP_get_cofactor(group, cofactor, NULL) != 1)
        goto end;
    if (BN_is_one(cofactor) || BN_is_word(cofactor, 2))
        ok = 1;

 end:
    BN_free(cofactor);
    return ok;
}

/* The SM2 profile uses SM3 for all ZYHW hashes, including explicit groups. */
int paea_check_digest(const EC_GROUP *group, const EVP_MD *md)
{
    int nid;

    if (EVP_MD_is_a(md, "SM3"))
        return 1;
    nid = EC_GROUP_check_named_curve(group, 0, NULL);
    if (nid < 0)
        return 0;
    if (nid == NID_sm2) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_UNSUPPORTED);
        return 0;
    }
    return 1;
}

size_t paea_point_len(const EC_GROUP *group)
{
    const EC_POINT *g = EC_GROUP_get0_generator(group);

    if (g == NULL)
        return 0;
    return EC_POINT_point2oct(group, g, POINT_CONVERSION_UNCOMPRESSED,
                              NULL, 0, NULL);
}

size_t paea_put_point(const EC_GROUP *group, unsigned char *p, const EC_POINT *pt)
{
    size_t n = paea_point_len(group);

    if (n == 0
        || EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                              p, n, NULL) != n)
        return 0;
    return n;
}

/* Exactly `len` bytes. Scalars use |q|; the challenge uses |H|. */
size_t paea_put_bn(size_t len, unsigned char *p, const BIGNUM *bn)
{
    if (len == 0 || len > PAEA_MAX_INT_LEN
        || bn == NULL || BN_is_negative(bn))
        return 0;
    if (BN_bn2binpad(bn, p, (int)len) != (int)len)
        return 0;
    return len;
}

int paea_get_bytes(const unsigned char **pp, size_t *rem,
                 const unsigned char **data, size_t *len)
{
    const unsigned char *p = *pp;
    size_t left = *rem;
    uint32_t n;

    if (left < 4)
        return 0;
    p = OPENSSL_load_u32_be(&n, p);
    left -= 4;
    if ((size_t)n > PAEA_MAX_BLOB_LEN || left < n)
        return 0;
    *data = p;
    *len = n;
    *pp = p + n;
    *rem = left - n;
    return 1;
}

int paea_get_point(const EC_GROUP *group, const unsigned char **pp,
                       size_t *rem, EC_POINT *pt)
{
    size_t n = paea_point_len(group);

    if (n == 0 || *rem < n)
        return 0;
    if (EC_POINT_oct2point(group, pt, *pp, n, NULL) != 1)
        return 0;
    *pp += n;
    *rem -= n;
    return 1;
}

int paea_get_bn(const unsigned char **pp, size_t *rem, size_t len, BIGNUM *bn)
{
    if (len == 0 || len > PAEA_MAX_INT_LEN || *rem < len)
        return 0;
    if (BN_bin2bn(*pp, (int)len, bn) == NULL)
        return 0;
    *pp += len;
    *rem -= len;
    return 1;
}

/*
 * m = BS2IP(H_lamda(I_U)) mod q
 *
 * The standard text (7.3.3) does not spell out whether the hash output
 * needs reduction mod q; all the group arithmetic later is mod q, so the
 * identifier is reduced here (see implementation notes, issue #2).
 */
int paea_m_of_uid(const EVP_MD *md, const EC_GROUP *group,
                  const unsigned char *uid, size_t uid_len, BIGNUM *m)
{
    const BIGNUM *q = EC_GROUP_get0_order(group);
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    if (!paea_check_digest(group, md))
        return 0;
    if (q == NULL || EVP_Digest(uid, uid_len, dig, &dlen, md, NULL) != 1)
        goto end;
    tmp = BN_bin2bn(dig, (int)dlen, NULL);
    bctx = BN_CTX_new();
    if (tmp == NULL || bctx == NULL || BN_mod(m, tmp, q, bctx) != 1)
        goto end;
    ret = 1;

 end:
    OPENSSL_cleanse(dig, sizeof(dig));
    BN_free(tmp);
    BN_CTX_free(bctx);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
    return ret;
}

/*
 * Random sampling from Z_q* (non-zero).
 */
int paea_rand_in_zq_star(const BIGNUM *q, BIGNUM *out)
{
    int i;

    for (i = 0; i < PAEA_MAX_RAND_TRIES; i++) {
        if (BN_priv_rand_range(out, q) != 1)
            break;
        if (!BN_is_zero(out))
            return 1;
    }
    ERR_raise(ERR_LIB_PAEA, PAEA_R_RANDOM_FAILED);
    return 0;
}

/*
 * H_g(): maps a byte string to a generator of G.
 *
 * The standard text only references the R_1EC primitive of ISO/IEC
 * 11770-4 for this mapping without defining it.  We use the classic
 * "try and increment" construction: input || ctr is hashed (share the
 * H_lamda digest), the output is interpreted as an x coordinate by
 * rejection sampling and lifted with the fixed compression bit 0.  On
 * curves with cofactor 2 the point is multiplied by the cofactor and
 * rejected if the result is the point at infinity (see implementation
 * notes, issue #1).
 */
int paea_h_g(const EC_GROUP *group, const EVP_MD *md,
             const unsigned char *in, size_t in_len, EC_POINT *out)
{
    const BIGNUM *cofactor;
    BIGNUM *p = NULL, *x = NULL;
    EC_POINT *pt = NULL;
    BN_CTX *bctx = NULL;
    unsigned char *buf = NULL;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int dlen;
    int ctr;
    int ret = 0;

    if (group == NULL || md == NULL || out == NULL)
        goto end;
    if (!paea_check_digest(group, md))
        return 0;
    cofactor = EC_GROUP_get0_cofactor(group);

    buf = OPENSSL_malloc(in_len + 1);
    if (buf == NULL)
        goto end;
    if (in_len > 0)
        memcpy(buf, in, in_len);

    p = BN_new();
    x = BN_new();
    bctx = BN_CTX_new();
    pt = EC_POINT_new(group);
    if (p == NULL || x == NULL || bctx == NULL || pt == NULL)
        goto end;
    if (EC_GROUP_get_curve(group, p, NULL, NULL, NULL) != 1)
        goto end;

    for (ctr = 0; ctr < PAEA_MAX_HG_TRIES; ctr++) {
        buf[in_len] = (unsigned char)ctr;
        if (EVP_Digest(buf, in_len + 1, dig, &dlen, md, NULL) != 1)
            goto end;
        if (BN_bin2bn(dig, (int)dlen, x) == NULL)
            goto end;
        /* rejection sampling, keeps the distribution flat */
        if (BN_is_zero(x) || BN_ucmp(x, p) >= 0)
            continue;
        if (EC_POINT_set_compressed_coordinates(group, pt, x, 0,
                                                bctx) != 1) {
            /*
             * Expected during the search (roughly every second candidate
             * is not the x coordinate of a curve point): retry with the
             * next counter instead of leaving errors in the queue.
             */
            ERR_clear_error();
            continue;
        }
        if (cofactor != NULL && !BN_is_one(cofactor)) {
            /* ensure the point is in the prime order subgroup */
            if (EC_POINT_mul(group, pt, NULL, pt, cofactor, bctx) != 1)
                goto end;
            if (EC_POINT_is_at_infinity(group, pt) == 1)
                continue;
        }
        if (EC_POINT_copy(out, pt) != 1)
            goto end;
        ret = 1;
        goto end;
    }
    ERR_raise(ERR_LIB_PAEA, PAEA_R_COORDINATE_FAILED);

 end:
    OPENSSL_cleanse(dig, sizeof(dig));
    OPENSSL_free(buf);
    BN_free(p);
    BN_clear_free(x);          /* x is a hash output, still cleanse */
    EC_POINT_free(pt);
    BN_CTX_free(bctx);
    return ret;
}

/* SM2 needs the GB/T 32918.2 default id; ECDSA does not. */
static int paea_sig_begin(EVP_MD_CTX *mctx, EVP_PKEY *pkey, const EVP_MD *md,
                          int sign)
{
    EVP_PKEY_CTX *pctx = NULL;

    if (mctx == NULL || pkey == NULL || md == NULL)
        return 0;
    if ((sign ? EVP_DigestSignInit(mctx, &pctx, md, NULL, pkey)
              : EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey)) != 1)
        return 0;
    if (EVP_PKEY_is_a(pkey, "SM2") && pctx != NULL
        && EVP_PKEY_CTX_set1_id(pctx, PAEA_SM2_DEFAULT_ID,
                                (int)(sizeof(PAEA_SM2_DEFAULT_ID) - 1)) != 1)
        return 0;
    return 1;
}

/*
 * One shot sign.  SM2/ECDSA signatures never exceed 256 bytes for any
 * supported curve; a larger buffer failing to fit is an error.
 */
int paea_sig_sign(EVP_PKEY *pkey, const EVP_MD *md,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char **out, size_t *out_len)
{
    EVP_MD_CTX *mctx = NULL;
    unsigned char buf[256];
    size_t len = sizeof(buf);
    int ret = 0;

    *out = NULL;
    *out_len = 0;
    mctx = EVP_MD_CTX_new();
    if (!paea_sig_begin(mctx, pkey, md, 1))
        goto end;
    if (EVP_DigestSign(mctx, buf, &len, msg, msg_len) != 1) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_SIGN_FAILED);
        goto end;
    }
    *out = OPENSSL_memdup(buf, len);
    if (*out == NULL)
        goto end;
    *out_len = len;
    ret = 1;

 end:
    EVP_MD_CTX_free(mctx);
    return ret;
}

int paea_sig_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t sig_len,
                    const unsigned char *msg, size_t msg_len)
{
    EVP_MD_CTX *mctx = NULL;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if (!paea_sig_begin(mctx, pkey, md, 0))
        goto end;
    if (EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len) == 1) {
        ret = 1;
    } else {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_VERIFY_FAILED);
    }

 end:
    EVP_MD_CTX_free(mctx);
    return ret;
}
