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
 * ZYHW anonymous entity authentication (GB/T 34953.4-XXXX, 7.3.4 and, for
 * user revocation enabled deployments, 7.3.5).  Three pass exchange:
 *
 *   S -> U:  <Y, sigma_S>            Y = g^y,  sigma_S = Sign_sk(GE2OSP(Y))
 *   U -> S:  <X, sigma_U>            a proof of knowledge of the
 *                                     credential member of the group of
 *                                     valid (non revoked) users
 *   both:    optional shared session key
 *
 * In EC notation (additive group, scalars reduced mod q):
 *
 *   user:   sigma = sigma_pw - H_g(pw),  T = a*sigma,  R = r_a*g - r_m*T
 *           [M = z*W,  N = r_z*B_n - r_m*M]
 *           c = BS2IP(H_lamda(g || T || [M ||] R || [N ||] X || Y || sig_S))
 *           s_m = r_m + c*m,  s_a = r_a + c*a,  [s_z = r_z + c*z]   mod q
 *   server: V = r*T, P = r*M
 *           R' = s_a*g - s_m*T - c*V
 *           [N' = s_z*B_n - s_m*M - c*P]
 *           c' = BS2IP(H_lamda(g || T || [M ||] R' || [N' ||] X || Y || sig))accept iff c' = c
 *
 * The session key is
 *   SK = H_lamda(Y || sigma_S || X || sigma_U || x*Y)      ( == y*X )
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"

/* EC_POINTs_mul() is public but deprecated; libcrypto internals use it */
#include "internal/deprecated.h"

/* Hash GE2OSP(pt).  Finite points on one curve share buf_len. */
static int paea_digest_point(EVP_MD_CTX *hash, const EC_GROUP *group,
                             const EC_POINT *pt,
                             unsigned char *buf, size_t buf_len)
{
    size_t n = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL);

    return n != 0 && EVP_DigestUpdate(hash, buf, n);
}

/*
 * Fiat-Shamir challenge c = BS2IP(H_lamda(...)).
 *
 * 7.3.4: H(g || T || R || X || Y || sigma_S)
 * 7.3.5: H(g || T || M || R || N || X || Y || sigma_S)
 *
 * Which transcript is used follows revocation. sigma_S is the signature
 * bytes as sent (implementation notes, issue #4).
 */
static int paea_zyhw_challenge(const EC_GROUP *group, const EVP_MD *md,
                               int revocation,
                               const EC_POINT *t_pt, const EC_POINT *r_pt,
                               const EC_POINT *m_pt, const EC_POINT *n_pt,
                               const EC_POINT *x_pt, const EC_POINT *y_pt,
                               const unsigned char *sig, size_t sig_len,
                               BIGNUM *c)
{
    int rc = 0;
    const EC_POINT *g;
    EVP_MD_CTX *hash = NULL;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned char *buf = NULL;
    size_t buf_len;
    unsigned int mdlen = 0;

    if (group == NULL || (g = EC_GROUP_get0_generator(group)) == NULL)
        return 0;

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /* One group, one uncompressed length; reuse the scratch buffer. */
    buf_len = EC_POINT_point2oct(group, g,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 NULL, 0, NULL);
    if (buf_len == 0) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EC_LIB);
        goto done;
    }
    buf = OPENSSL_malloc(buf_len);
    if (buf == NULL)
        goto done;

    if (!EVP_DigestInit(hash, md)) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /* g || T || [M ||] R || [N ||] X || Y || sigma_S */
    if (!paea_digest_point(hash, group, g, buf, buf_len)
        || !paea_digest_point(hash, group, t_pt, buf, buf_len))
        goto err;
    if (revocation && !paea_digest_point(hash, group, m_pt, buf, buf_len))
        goto err;
    if (!paea_digest_point(hash, group, r_pt, buf, buf_len))
        goto err;
    if (revocation && !paea_digest_point(hash, group, n_pt, buf, buf_len))
        goto err;
    if (!paea_digest_point(hash, group, x_pt, buf, buf_len)
        || !paea_digest_point(hash, group, y_pt, buf, buf_len)
        || !EVP_DigestUpdate(hash, sig, sig_len)
        || !EVP_DigestFinal(hash, dig, &mdlen)
        || BN_bin2bn(dig, (int)mdlen, c) == NULL)
        goto err;

    rc = 1;
    goto done;

 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
 done:
    OPENSSL_cleanse(dig, sizeof(dig));
    OPENSSL_free(buf);
    EVP_MD_CTX_free(hash);
    return rc;
}

/*
 * Session key (7.3.4 optional output):
 *   SK = H_lamda(GE2OSP(Y) || GE2OSP(sigma_S) || GE2OSP(X)
 *                || GE2OSP(sigma_U) || GE2OSP(<the DH term>))
 * sigma_U is the proof bytes as sent (implementation notes, issue #5).
 * The DH term is x*Y on the user side and y*X on the server side.
 */
static int paea_zyhw_session_key(const EC_GROUP *group, const EVP_MD *md,
                                 const EC_POINT *y_pt, const EC_POINT *x_pt,
                                 const unsigned char *sig, size_t sig_len,
                                 const unsigned char *su, size_t su_len,
                                 const EC_POINT *dh,
                                 unsigned char **out, size_t *out_len)
{
    int rc = 0;
    EVP_MD_CTX *hash = NULL;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned char *buf = NULL;
    unsigned char *sk = NULL;
    size_t buf_len;
    unsigned int mdlen = 0;

    *out = NULL;
    *out_len = 0;

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    buf_len = EC_POINT_point2oct(group, y_pt,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 NULL, 0, NULL);
    if (buf_len == 0) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EC_LIB);
        goto done;
    }
    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL)
        goto done;

    if (!EVP_DigestInit(hash, md)) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /* Y || sigma_S || X || sigma_U || DH, with DH = x*Y or y*X. */
    if (!paea_digest_point(hash, group, y_pt, buf, buf_len)
        || !EVP_DigestUpdate(hash, sig, sig_len)
        || !paea_digest_point(hash, group, x_pt, buf, buf_len)
        || !EVP_DigestUpdate(hash, su, su_len)
        || !paea_digest_point(hash, group, dh, buf, buf_len)
        || !EVP_DigestFinal(hash, dig, &mdlen)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
        goto done;
    }

    sk = OPENSSL_memdup(dig, mdlen);
    if (sk == NULL)
        goto done;
    *out = sk;
    *out_len = mdlen;
    rc = 1;

 done:
    OPENSSL_cleanse(dig, sizeof(dig));
    OPENSSL_free(buf);
    EVP_MD_CTX_free(hash);
    return rc;
}

/*
 * sigma_U: T, [M], c, s_m, s_a, [s_z].
 * Both ends build these bytes the same way; the session key hashes them.
 */
static int zyhw_sigma_u(const EC_GROUP *group, const EVP_MD *md,
                        int revocation,
                        const EC_POINT *t_pt, const EC_POINT *m_pt,
                        const BIGNUM *c,
                        const BIGNUM *s_m, const BIGNUM *s_a,
                        const BIGNUM *s_z, unsigned char **out,
                        size_t *out_len)
{
    const BIGNUM *q = EC_GROUP_get0_order(group);
    size_t qlen, ptlen, clen, total, off;
    int mdsize;
    unsigned char *buf;

    *out = NULL;
    *out_len = 0;
    if (q == NULL || md == NULL)
        return 0;
    qlen = (size_t)BN_num_bytes(q);
    ptlen = paea_point_len(group);
    mdsize = EVP_MD_get_size(md);
    /* s_* are in Z_q. c is the hash integer, so its width is |H|. */
    if (qlen == 0 || ptlen == 0 || mdsize <= 0)
        return 0;
    clen = (size_t)mdsize;
    total = ptlen + clen + 2 * qlen;
    if (revocation)
        total += ptlen + qlen;

    buf = OPENSSL_malloc(total);
    if (buf == NULL)
        return 0;
    off = 0;
    if (paea_put_point(group, buf + off, t_pt) != ptlen)
        goto err;
    off += ptlen;
    if (revocation) {
        if (paea_put_point(group, buf + off, m_pt) != ptlen)
            goto err;
        off += ptlen;
    }
    if (paea_put_bn(clen, buf + off, c) != clen)
        goto err;
    off += clen;
    if (paea_put_bn(qlen, buf + off, s_m) != qlen)
        goto err;
    off += qlen;
    if (paea_put_bn(qlen, buf + off, s_a) != qlen)
        goto err;
    off += qlen;
    if (revocation && paea_put_bn(qlen, buf + off, s_z) != qlen)
        goto err;
    *out = buf;
    *out_len = total;
    return 1;

 err:
    OPENSSL_free(buf);
    return 0;
}

/*
 * Pass 1 (server): a fresh Y with a server signature over it.
 *
 *   Y, sigma_S
 */
int paea_zyhw_server_auth_init(const EC_GROUP *group, EVP_PKEY *sign_key,
                               const EVP_MD *md,
                               unsigned char **out, size_t *out_len,
                               BIGNUM **y_out, EC_POINT **y_pt_out,
                               unsigned char **sigma_s, size_t *sigma_s_len)
{
    const BIGNUM *q;
    BIGNUM *y = NULL;
    EC_POINT *y_pt = NULL;
    unsigned char *yenc = NULL, *sig = NULL, *msg = NULL;
    size_t yenc_len = 0, sig_len = 0, msg_len;

    *out = NULL;
    *out_len = 0;
    *y_out = NULL;
    *y_pt_out = NULL;
    *sigma_s = NULL;
    *sigma_s_len = 0;

    if (group == NULL || sign_key == NULL || md == NULL
        || (q = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }

    y = BN_new();
    y_pt = EC_POINT_new(group);
    if (y == NULL || y_pt == NULL)
        goto err;
    if (!paea_rand_in_zq_star(q, y)
        || EC_POINT_mul(group, y_pt, y, NULL, NULL, NULL) != 1)
        goto err;

    /* sigma_S = Sign_sk(GE2OSP(Y)) over the canonical point encoding */
    yenc_len = EC_POINT_point2oct(group, y_pt,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  NULL, 0, NULL);
    if (yenc_len == 0)
        goto err;
    yenc = OPENSSL_malloc(yenc_len);
    if (yenc == NULL
        || EC_POINT_point2oct(group, y_pt, POINT_CONVERSION_UNCOMPRESSED,
                              yenc, yenc_len, NULL) == 0)
        goto err;

    if (!paea_sig_sign(sign_key, md, yenc, yenc_len, &sig, &sig_len))
        goto err;

    msg_len = yenc_len + 4 + sig_len;
    msg = OPENSSL_malloc(msg_len);
    if (msg == NULL)
        goto err;
    memcpy(msg, yenc, yenc_len);
    OPENSSL_store_u32_be(msg + yenc_len, (uint32_t)sig_len);
    memcpy(msg + yenc_len + 4, sig, sig_len);

    OPENSSL_free(yenc);
    *out = msg;
    *out_len = msg_len;
    *y_out = y;
    *y_pt_out = y_pt;
    *sigma_s = sig;
    *sigma_s_len = sig_len;
    return 1;

 err:
    BN_clear_free(y);
    EC_POINT_free(y_pt);
    OPENSSL_free(yenc);
    OPENSSL_free(sig);
    OPENSSL_free(msg);
    return 0;
}

/*
 * Pass 2 (user): recover sigma, blind it, prove knowledge of (m, a) [and
 * the revocation witness (m, z)] in sigma_U.
 *
 *   X, then sigma_U: T, [M], c, s_m, s_a, [s_z]
 */
int paea_zyhw_user_prove(const EC_GROUP *group, EVP_MD *md,
                         const EC_POINT *pw_credential, const BIGNUM *m,
                         EVP_PKEY *verify_key,
                         const EC_POINT *witness, const EC_POINT *acc,
                         const unsigned char *pw, size_t pw_len,
                         const unsigned char *msg1, size_t msg1_len,
                         unsigned char **out, size_t *out_len,
                         unsigned char **session_key, size_t *session_key_len)
{
    const unsigned char *cur = msg1, *sig = NULL;
    size_t rem = msg1_len, sig_len = 0;
    BIGNUM *x = NULL, *a = NULL, *r_m = NULL, *r_a = NULL;
    BIGNUM *z = NULL, *r_z = NULL, *c = NULL;
    BIGNUM *neg_r_m = NULL;
    BIGNUM *tmp = NULL, *s_m = NULL, *s_a = NULL, *s_z = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT *y_pt = NULL, *sig_pt = NULL, *hp = NULL;
    EC_POINT *t_pt = NULL, *r_pt = NULL, *m_pt = NULL, *n_pt = NULL;
    EC_POINT *x_pt = NULL, *kdh = NULL;
    unsigned char *sk = NULL;
    size_t sklen = 0;
    unsigned char *su_raw = NULL, *msg = NULL;
    size_t su_len = 0, msg_len, xlen;
    const BIGNUM *q;
    int revocation, ret = 0;

    *out = NULL;
    *out_len = 0;
    if (session_key != NULL)
        *session_key = NULL;
    if (session_key_len != NULL)
        *session_key_len = 0;

    if (group == NULL || md == NULL || pw_credential == NULL
        || m == NULL || verify_key == NULL
        || (q = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }
    revocation = acc != NULL;

    /* msg1: Y, sigma_S */
    y_pt = EC_POINT_new(group);
    if (y_pt == NULL)
        goto err;
    if (!paea_get_point(group, &cur, &rem, y_pt)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
        goto err;
    }
    if (!paea_get_bytes(&cur, &rem, &sig, &sig_len) || sig_len == 0 || rem != 0)
        goto err;

    /* step 2a: verify the server signature on Y */
    {
        size_t ylen = EC_POINT_point2oct(group, y_pt,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         NULL, 0, NULL);
        unsigned char *yenc;

        if (ylen == 0)
            goto err;
        yenc = OPENSSL_malloc(ylen);
        if (yenc == NULL)
            goto err;
        if (EC_POINT_point2oct(group, y_pt,
                               POINT_CONVERSION_UNCOMPRESSED,
                               yenc, ylen, NULL) == 0) {
            OPENSSL_free(yenc);
            goto err;
        }
        if (paea_sig_verify(verify_key, md, sig, sig_len, yenc, ylen) != 1) {
            OPENSSL_free(yenc);
            goto err;    /* REJECT */
        }
        OPENSSL_free(yenc);
    }

    /* recover sigma = sigma_pw - H_g(pw) */
    hp = EC_POINT_new(group);
    sig_pt = EC_POINT_new(group);
    x_pt = EC_POINT_new(group);
    t_pt = EC_POINT_new(group);
    r_pt = EC_POINT_new(group);
    c = BN_new();
    x = BN_new();
    a = BN_new();
    r_m = BN_new();
    r_a = BN_new();
    neg_r_m = BN_new();
    tmp = BN_new();
    s_m = BN_new();
    s_a = BN_new();
    bctx = BN_CTX_new();
    if (hp == NULL || sig_pt == NULL || x_pt == NULL || t_pt == NULL
        || r_pt == NULL || c == NULL || x == NULL || a == NULL
        || r_m == NULL || r_a == NULL || neg_r_m == NULL
        || tmp == NULL || s_m == NULL || s_a == NULL || bctx == NULL)
        goto err;

    if (pw == NULL)
        goto err;
    if (!paea_h_g(group, md, pw, pw_len, hp))
        goto err;
    /* sigma = sigma_pw - H_g(pw) */
    if (EC_POINT_invert(group, hp, bctx) != 1
        || EC_POINT_add(group, sig_pt, pw_credential, hp, bctx) != 1)
        goto err;
    if (EC_POINT_is_at_infinity(group, sig_pt) == 1)
        goto err;          /* wrong password or broken credential */

    if (!paea_rand_in_zq_star(q, x)
        || EC_POINT_mul(group, x_pt, x, NULL, NULL, bctx) != 1)
        goto err;
    if (!paea_rand_in_zq_star(q, a)
        || EC_POINT_mul(group, t_pt, NULL, sig_pt, a, bctx) != 1)
        goto err;                                        /* T = a*sigma */
    if (!paea_rand_in_zq_star(q, r_m)
        || !paea_rand_in_zq_star(q, r_a)
        || BN_sub(neg_r_m, q, r_m) != 1        /* -r_m = q - r_m */
        || EC_POINTs_mul(group, r_pt, r_a, 1,
                         (const EC_POINT *[]){ t_pt },
                         (const BIGNUM *[]){ neg_r_m },
                         bctx) != 1)
        goto err;                                        /* R = r_a*g - r_m*T */

    if (revocation) {
        if (witness == NULL)
            goto err_notinit;
        m_pt = EC_POINT_new(group);
        n_pt = EC_POINT_new(group);
        z = BN_new();
        r_z = BN_new();
        s_z = BN_new();
        if (m_pt == NULL || n_pt == NULL || z == NULL || r_z == NULL
            || s_z == NULL)
            goto err;
        if (!paea_rand_in_zq_star(q, z)
            || EC_POINT_mul(group, m_pt, NULL, witness, z,
                            bctx) != 1)
            goto err;                                        /* M = z*W */
        if (!paea_rand_in_zq_star(q, r_z)
            || EC_POINTs_mul(group, n_pt, NULL, 2,
                             (const EC_POINT *[]){ acc, m_pt },
                             (const BIGNUM *[]){ r_z, neg_r_m },
                             bctx) != 1)
            goto err;                                        /* N = r_z*B_n - r_m*M */
    }

    /* challenge */
    if (!paea_zyhw_challenge(group, md, revocation, t_pt, r_pt, m_pt, n_pt,
                             x_pt, y_pt,
                             sig, sig_len, c))
        goto err;

    /* responses, all reduced mod q (the standard's "mod q" applies to the
     * result, c itself is not reduced) */
    if (BN_mul(tmp, c, m, bctx) != 1
        || BN_mod_add(s_m, r_m, tmp, q, bctx) != 1)
        goto err;
    if (BN_mul(tmp, c, a, bctx) != 1
        || BN_mod_add(s_a, r_a, tmp, q, bctx) != 1)
        goto err;
    if (revocation
        && (BN_mul(tmp, c, z, bctx) != 1
            || BN_mod_add(s_z, r_z, tmp, q, bctx) != 1))
        goto err;

    /* sigma_U: T, [M], c, s_m, s_a, [s_z] */
    if (!zyhw_sigma_u(group, md, revocation, t_pt, m_pt, c, s_m, s_a, s_z,
                      &su_raw, &su_len))
        goto err;

    /* msg2 = X || sigma_U */
    xlen = paea_point_len(group);
    if (xlen == 0)
        goto err;
    msg_len = xlen + su_len;
    msg = OPENSSL_malloc(msg_len);
    if (msg == NULL || paea_put_point(group, msg, x_pt) != xlen)
        goto err;
    memcpy(msg + xlen, su_raw, su_len);
    *out = msg;
    *out_len = msg_len;
    msg = NULL;

    /* optional session key */
    kdh = EC_POINT_new(group);
    if (kdh == NULL
        || EC_POINT_mul(group, kdh, NULL, y_pt, x, bctx) != 1)
        goto err;                                        /* x*Y */
    if (!paea_zyhw_session_key(group, md, y_pt, x_pt, sig, sig_len,
                               su_raw, su_len, kdh, &sk, &sklen))
        goto err;

    if (session_key != NULL && session_key_len != NULL) {
        *session_key = sk;
        *session_key_len = sklen;
        sk = NULL;
    }
    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
 done:
    OPENSSL_free(msg);
    OPENSSL_free(su_raw);
    BN_clear_free(x);
    BN_clear_free(a);
    BN_clear_free(r_m);
    BN_clear_free(r_a);
    BN_clear_free(z);
    BN_clear_free(r_z);
    BN_clear_free(c);
    BN_clear_free(neg_r_m);
    BN_clear_free(tmp);
    BN_clear_free(s_m);
    BN_clear_free(s_a);
    BN_clear_free(s_z);
    BN_CTX_free(bctx);
    EC_POINT_free(y_pt);
    EC_POINT_free(sig_pt);
    EC_POINT_free(hp);
    EC_POINT_free(t_pt);
    EC_POINT_free(r_pt);
    EC_POINT_free(m_pt);
    EC_POINT_free(n_pt);
    EC_POINT_free(x_pt);
    EC_POINT_free(kdh);
    OPENSSL_clear_free(sk, sklen);
    return ret;
}

/*
 * Pass 3 (server): verify sigma_U.  Returns 1 (ACCEPT) or 0 (REJECT).
 * On ACCEPT the optional session key is returned through session_key when
 * both session_key and session_key_len are non-NULL.
 */
int paea_zyhw_server_verify(const EC_GROUP *group, EVP_MD *md,
                            const BIGNUM *r,
                            const BIGNUM *y, const EC_POINT *y_pt,
                            const unsigned char *sigma_s, size_t sigma_s_len,
                            const EC_POINT *acc,
                            const unsigned char *msg2, size_t msg2_len,
                            unsigned char **session_key,
                            size_t *session_key_len)
{
    const unsigned char *cur = msg2, *su = NULL;
    size_t rem = msg2_len, su_len = 0;
    BIGNUM *c = NULL, *c_chk = NULL;
    BIGNUM *s_m = NULL, *s_a = NULL, *s_z = NULL;
    BIGNUM *neg_c = NULL, *neg_sm = NULL;
    const EC_POINT *pts[3];
    const BIGNUM *scalar_s[3];
    EC_POINT *x_pt = NULL, *t_pt = NULL, *r_pt = NULL;
    EC_POINT *m_pt = NULL, *v_pt = NULL, *p_pt = NULL, *n_pt = NULL;
    EC_POINT *kdh = NULL;
    BN_CTX *bctx = NULL;
    unsigned char *sk = NULL;
    size_t sklen = 0;
    const BIGNUM *q;
    size_t qlen, clen;
    int mdsize, revocation, reason = PAEA_R_BAD_MESSAGE, ret = 0;

    if (session_key != NULL)
        *session_key = NULL;
    if (session_key_len != NULL)
        *session_key_len = 0;

    if (group == NULL || md == NULL || r == NULL || y == NULL
        || y_pt == NULL || sigma_s == NULL || sigma_s_len == 0
        || (q = EC_GROUP_get0_order(group)) == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }
    revocation = acc != NULL;
    qlen = (size_t)BN_num_bytes(q);
    mdsize = EVP_MD_get_size(md);
    if (qlen == 0 || mdsize <= 0)
        goto err;
    clen = (size_t)mdsize;

    x_pt = EC_POINT_new(group);
    t_pt = EC_POINT_new(group);
    r_pt = EC_POINT_new(group);
    v_pt = EC_POINT_new(group);
    c = BN_new();
    c_chk = BN_new();
    s_m = BN_new();
    s_a = BN_new();
    neg_c = BN_new();
    neg_sm = BN_new();
    bctx = BN_CTX_new();
    if (x_pt == NULL || t_pt == NULL || r_pt == NULL || v_pt == NULL
        || c == NULL || c_chk == NULL || s_m == NULL || s_a == NULL
        || neg_c == NULL || neg_sm == NULL || bctx == NULL)
        goto err;

    /* msg2: X, then sigma_U. sigma_U is hashed as sent. */
    if (!paea_get_point(group, &cur, &rem, x_pt))
        goto err;
    su = cur;
    su_len = rem;
    if (!paea_get_point(group, &cur, &rem, t_pt))
        goto err;
    if (revocation) {
        m_pt = EC_POINT_new(group);
        if (m_pt == NULL || !paea_get_point(group, &cur, &rem, m_pt))
            goto err;
    }
    if (!paea_get_bn(&cur, &rem, clen, c)
        || !paea_get_bn(&cur, &rem, qlen, s_m)
        || !paea_get_bn(&cur, &rem, qlen, s_a))
        goto err;
    if (revocation) {
        s_z = BN_new();
        if (s_z == NULL || !paea_get_bn(&cur, &rem, qlen, s_z))
            goto err;
    }
    if (rem != 0)
        goto err;

    /* 7.3.4 / 7.3.5: T != 1, and with revocation M != 1. */
    if (EC_POINT_is_at_infinity(group, t_pt) == 1)
        goto err;                    /* T != 1 */
    if (revocation
        && EC_POINT_is_at_infinity(group, m_pt) == 1)
        goto err;                    /* M != 1 */

    /*
     * s_m, s_a, s_z are in Z_q.  c is compared in full and is only
     * reduced for the exponent -c.
     */
    if (BN_nnmod(s_m, s_m, q, bctx) != 1
        || BN_nnmod(s_a, s_a, q, bctx) != 1
        || (revocation && BN_nnmod(s_z, s_z, q, bctx) != 1)
        || BN_mod_sub(neg_sm, q, s_m, q, bctx) != 1
        || BN_mod_sub(neg_c, q, c, q, bctx) != 1)
        goto err;
    /* V = r*T, then R' = s_a*g - s_m*T - c*V */
    if (EC_POINT_mul(group, v_pt, NULL, t_pt, r, bctx) != 1)
        goto err;
    pts[0] = t_pt;     scalar_s[0] = neg_sm;
    pts[1] = v_pt;     scalar_s[1] = neg_c;
    if (EC_POINTs_mul(group, r_pt, s_a, 2, &pts[0], &scalar_s[0],
                      bctx) != 1)
        goto err;

    if (revocation) {
        /* P = r*M, then N' = s_z*B_n - s_m*M - c*P */
        p_pt = EC_POINT_new(group);
        n_pt = EC_POINT_new(group);
        if (p_pt == NULL || n_pt == NULL)
            goto err;
        if (EC_POINT_mul(group, p_pt, NULL, m_pt, r, bctx) != 1)
            goto err;
        pts[0] = acc;   scalar_s[0] = s_z;
        pts[1] = m_pt;       scalar_s[1] = neg_sm;
        pts[2] = p_pt;       scalar_s[2] = neg_c;
        if (EC_POINTs_mul(group, n_pt, NULL, 3, &pts[0], &scalar_s[0],
                          bctx) != 1)
            goto err;
    }
    if (!paea_zyhw_challenge(group, md, revocation, t_pt, r_pt, m_pt, n_pt,
                             x_pt, y_pt, sigma_s, sigma_s_len, c_chk)) {
        reason = 0;                         /* already raised */
        goto err;
    }

    if (BN_cmp(c, c_chk) != 0)
        goto err;                    /* REJECT */

    /* optional session key: y*X.  sigma_U is the suffix of msg2. */
    kdh = EC_POINT_new(group);
    if (kdh == NULL
        || EC_POINT_mul(group, kdh, NULL, x_pt, y, bctx) != 1)
        goto err;
    if (!paea_zyhw_session_key(group, md, y_pt, x_pt,
                               sigma_s, sigma_s_len,
                               su, su_len, kdh, &sk, &sklen)) {
        reason = 0;                         /* already raised */
        goto err;
    }
    if (session_key != NULL && session_key_len != NULL) {
        *session_key = sk;
        *session_key_len = sklen;
        sk = NULL;
    }
    ret = 1;
    goto done;

 err:
 done:
    BN_clear_free(c);
    BN_free(c_chk);
    BN_clear_free(s_m);
    BN_clear_free(s_a);
    BN_clear_free(s_z);
    BN_clear_free(neg_c);
    BN_clear_free(neg_sm);
    BN_CTX_free(bctx);
    EC_POINT_free(x_pt);
    EC_POINT_free(t_pt);
    EC_POINT_free(r_pt);
    EC_POINT_free(m_pt);
    EC_POINT_free(v_pt);
    EC_POINT_free(p_pt);
    EC_POINT_free(n_pt);
    EC_POINT_free(kdh);
    OPENSSL_clear_free(sk, sklen);
    if (ret == 0 && reason != 0)
        ERR_raise(ERR_LIB_PAEA, reason);
    return ret;
}
