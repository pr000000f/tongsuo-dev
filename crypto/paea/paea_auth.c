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
 *   server: V = r*T, P = chi*M
 *           R' = s_a*g - s_m*T - c*V
 *           [N' = s_z*B_n - s_m*M - c*P]
 *           c' = BS2IP(H_lamda(g || T || [M ||] R' || [N' ||] X || Y || sig))accept iff c' = c
 *
 * The session key is
 *   SK = H_lamda(Y || sigma_S || X || sigma_U || x*Y)      ( == y*X )
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"

/*
 * Fiat-Shamir challenge: c = BS2IP(H_lamda(...)).  The exact hash input
 * order follows the standard text; M and N are only hashed in the
 * revocation enabled variant.  Note the standard explicitly writes
 * compression-bytes for the group elements (GE2OSP) and the raw
 * signature bytes for sigma_S (see implementation notes, issue #4).
 */
static int paea_zyhw_challenge(EVP_PAEA_CTX *ctx,
                               const EC_POINT *t_pt, const EC_POINT *r_pt,
                               const EC_POINT *m_pt, const EC_POINT *n_pt,
                               const EC_POINT *x_pt, const EC_POINT *y_pt,
                               const unsigned char *sig, size_t sig_len,
                               BIGNUM *c)
{
    int rc = 0;
    EVP_MD_CTX *hash = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char *buf = NULL;
    size_t buf_len;
    unsigned int mdlen = 0;

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /*
     * All points lie in one group, their uncompressed encodings share
     * one length: probe it once, then reuse a single scratch buffer
     * for every element.
     */
    buf_len = EC_POINT_point2oct(ctx->group, ctx->gpt,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 NULL, 0, NULL);
    if (buf_len == 0) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EC_LIB);
        goto done;
    }
    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL)
        goto done;

    if (!EVP_DigestInit(hash, ctx->md)) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /*
     * c = BS2IP(H_lamda(GE2OSP(g) || GE2OSP(T) || [GE2OSP(M) ||
     *           GE2OSP(R) || [GE2OSP(N) ||] GE2OSP(X) || GE2OSP(Y) ||
     *           sigma_S)); the element order is fixed by the standard
     * text (7.3.4 step 2 and 7.3.5).  m_pt and n_pt are hashed in the
     * revocation enabled variant only, sigma_S is the raw signature
     * bytes (implementation notes, issue #4).
     */
    if (EC_POINT_point2oct(ctx->group, ctx->gpt, POINT_CONVERSION_UNCOMPRESSED,
                           buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || EC_POINT_point2oct(ctx->group, t_pt, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || (m_pt != NULL
                && (EC_POINT_point2oct(ctx->group, m_pt,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       buf, buf_len, NULL) == 0
                    || !EVP_DigestUpdate(hash, buf, buf_len)))
            || EC_POINT_point2oct(ctx->group, r_pt, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || (n_pt != NULL
                && (EC_POINT_point2oct(ctx->group, n_pt,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       buf, buf_len, NULL) == 0
                    || !EVP_DigestUpdate(hash, buf, buf_len)))
            || EC_POINT_point2oct(ctx->group, x_pt, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || EC_POINT_point2oct(ctx->group, y_pt, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || !EVP_DigestUpdate(hash, sig, sig_len)
            || !EVP_DigestFinal(hash, md, &mdlen)
            || BN_bin2bn(md, (int)mdlen, c) == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_cleanse(md, sizeof(md));
    OPENSSL_free(buf);
    EVP_MD_CTX_free(hash);
    return rc;
}

/*
 * Session key (7.3.4 optional output):
 *   SK = H_lamda(GE2OSP(Y) || GE2OSP(sigma_S) || GE2OSP(X)
 *                || GE2OSP(sigma_U) || GE2OSP(<the DH term>))
 * "GE2OSP(sigma_U)" is interpreted as the canonical TL encoding of the
 * message part sigma_U (see implementation notes, issue #5).  The DH
 * term is x*Y on the user side and y*X on the server side, both bound to
 * the transcript through the challenge.
 */
static int paea_zyhw_session_key(EVP_PAEA_CTX *ctx,
                                 const EC_POINT *y_pt, const EC_POINT *x_pt,
                                 const unsigned char *sig, size_t sig_len,
                                 const unsigned char *su, size_t su_len,
                                 const EC_POINT *dh,
                                 unsigned char **out, size_t *out_len)
{
    int rc = 0;
    EVP_MD_CTX *hash = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
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

    buf_len = EC_POINT_point2oct(ctx->group, y_pt,
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 NULL, 0, NULL);
    if (buf_len == 0) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EC_LIB);
        goto done;
    }
    buf = OPENSSL_zalloc(buf_len);
    if (buf == NULL)
        goto done;

    if (!EVP_DigestInit(hash, ctx->md)) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_EVP_LIB);
        goto done;
    }

    /*
     * SK = H_lamda(GE2OSP(Y) || sigma_S || GE2OSP(X) || sigma_U ||
     *              GE2OSP(<the DH term>)); sigma_U is hashed as its
     * canonical TL encoding (implementation notes, issue #5), the DH
     * term is x*Y on the user side and y*X on the server side.
     */
    if (EC_POINT_point2oct(ctx->group, y_pt, POINT_CONVERSION_UNCOMPRESSED,
                           buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || !EVP_DigestUpdate(hash, sig, sig_len)
            || EC_POINT_point2oct(ctx->group, x_pt,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || !EVP_DigestUpdate(hash, su, su_len)
            || EC_POINT_point2oct(ctx->group, dh,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  buf, buf_len, NULL) == 0
            || !EVP_DigestUpdate(hash, buf, buf_len)
            || !EVP_DigestFinal(hash, md, &mdlen)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
        goto done;
    }

    sk = OPENSSL_memdup(md, mdlen);
    if (sk == NULL)
        goto done;
    *out = sk;
    *out_len = mdlen;
    rc = 1;

 done:
    OPENSSL_cleanse(md, sizeof(md));
    OPENSSL_free(buf);
    EVP_MD_CTX_free(hash);
    return rc;
}

/*
 * Pass 1 (server): a fresh Y with a server signature over it.
 *
 *   u8 version? none -- message, not blob:
 *   TL(Y) TL(sigma_S)
 */
int paea_zyhw_server_auth_init(EVP_PAEA_CTX *ctx, PAEA_BUF *msg)
{
    EVP_MD_CTX *mctx = NULL;
    BIGNUM *y = NULL;
    EC_POINT *y_pt = NULL;
    unsigned char *yenc = NULL, *sig = NULL;
    size_t yenc_len = 0, sig_len = 0;
    int ret = 0;

    if (!ctx->params_ready || !ctx->server_secret
            || ctx->sig_key == NULL || ctx->r == NULL)
        goto err_notinit;

    if (ctx->srv_pend) {
        /* one pending authentication per context: the previous one is
         * aborted when a new one is started (implementation choice) */
        paea_ctx_clear_session(ctx);
    }

    y = BN_new();
    y_pt = EC_POINT_new(ctx->group);
    if (y == NULL || y_pt == NULL)
        goto err;
    if (!paea_rand_in_zq_star(ctx, y))
        goto err;
    if (!paea_generator_mul(ctx, y, y_pt))
        goto err;

    /* sigma_S = Sign_sk(GE2OSP(Y)) over the canonical point encoding */
    yenc_len = EC_POINT_point2oct(ctx->group, y_pt,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  NULL, 0, NULL);
    if (yenc_len == 0)
        goto err;
    yenc = OPENSSL_malloc(yenc_len);
    if (yenc == NULL
            || EC_POINT_point2oct(ctx->group, y_pt,
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  yenc, yenc_len, NULL) == 0)
        goto err;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
            || !paea_sig_sign(ctx, mctx, yenc, yenc_len, &sig, &sig_len))
        goto err;

    if (!paea_buf_point(ctx, msg, y_pt)
            || !paea_buf_u32(msg, (uint32_t)sig_len)
            || !paea_buf_raw(msg, sig, sig_len))
        goto err;

    /* remember the session */
    paea_ctx_clear_session(ctx);
    ctx->sess_y = y;
    ctx->sess_y_pt = y_pt;
    ctx->sess_sig = sig;
    ctx->sess_sig_len = sig_len;
    ctx->srv_pend = 1;
    return 1;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    BN_clear_free(y);
    EC_POINT_free(y_pt);
    OPENSSL_free(yenc);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mctx);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return 0;
}

/*
 * Pass 2 (user): recover sigma, blind it, prove knowledge of (m, a) [and
 * the revocation witness (m, z)] in sigma_U.
 *
 *   TL(X) TL(T) [TL(M)] TL(c) TL(s_m) TL(s_a) [TL(s_z)]
 */
int paea_zyhw_user_prove(EVP_PAEA_CTX *ctx, const unsigned char *pw,
                         size_t pw_len, const unsigned char *msg1,
                         size_t msg1_len, PAEA_BUF *msg2)
{
    PAEA_RDR r = { msg1, msg1_len, 0 };
    PAEA_BUF su;
    size_t unused, tllen;
    const unsigned char *sig = NULL;
    BIGNUM *x = NULL, *a = NULL, *r_m = NULL, *r_a = NULL;
    BIGNUM *z = NULL, *r_z = NULL, *c = NULL;
    BIGNUM *neg_r_m = NULL;
    BIGNUM *tmp = NULL, *s_m = NULL, *s_a = NULL, *s_z = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT *y_pt = NULL, *sig_pt = NULL, *hp = NULL;
    EC_POINT *t_pt = NULL, *r_pt = NULL, *m_pt = NULL, *n_pt = NULL;
    EC_POINT *x_pt = NULL, *kdh = NULL;
    unsigned char *sk = NULL;
    size_t sk_len = 0;
    unsigned char *su_raw = NULL;
    size_t su_len = 0;
    int ret = 0;

    paea_buf_init(&su);

    if (!ctx->params_ready || ctx->group == NULL
            || ctx->sigma_pw == NULL || ctx->m == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }

    /* msg1: TL(Y) TL(sigma_S) */
    y_pt = EC_POINT_new(ctx->group);
    if (y_pt == NULL || !paea_rdr_take_point(ctx->group, &r, y_pt, &unused))
        goto err;
    if (!paea_rdr_take_tl(&r, &tllen, &sig))
        goto err;
    if (sig == NULL || tllen == 0 || r.remaining != 0)
        goto err;
    if (!paea_point_valid_pub(ctx, y_pt))
        goto err;

    /* step 2a: verify the server signature on Y */
    {
        size_t ylen = EC_POINT_point2oct(ctx->group, y_pt,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         NULL, 0, NULL);
        unsigned char *yenc;

        if (ylen == 0)
            goto err;
        yenc = OPENSSL_malloc(ylen);
        if (yenc == NULL)
            goto err;
        if (EC_POINT_point2oct(ctx->group, y_pt,
                               POINT_CONVERSION_UNCOMPRESSED,
                               yenc, ylen, NULL) == 0) {
            OPENSSL_free(yenc);
            goto err;
        }
        if (paea_sig_verify(ctx, sig, tllen, yenc, ylen) != 1) {
            OPENSSL_free(yenc);
            goto err;    /* REJECT */
        }
        OPENSSL_free(yenc);
    }

    /* recover sigma = sigma_pw - H_g(pw) */
    hp = EC_POINT_new(ctx->group);
    sig_pt = EC_POINT_new(ctx->group);
    x_pt = EC_POINT_new(ctx->group);
    t_pt = EC_POINT_new(ctx->group);
    r_pt = EC_POINT_new(ctx->group);
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
    if (!paea_h_g(ctx, pw, pw_len, hp))
        goto err;
    if (!paea_point_sub(ctx, ctx->sigma_pw, hp, sig_pt))
        goto err;
    if (EC_POINT_is_at_infinity(ctx->group, sig_pt) == 1)
        goto err;          /* wrong password or broken credential */

    if (!paea_rand_in_zq_star(ctx, x)
            || !paea_generator_mul(ctx, x, x_pt))
        goto err;
    if (!paea_rand_in_zq_star(ctx, a)
            || !paea_scalar_mul(ctx, a, sig_pt, t_pt))    /* T = a*sigma */
        goto err;
    if (!paea_rand_in_zq_star(ctx, r_m)
            || !paea_rand_in_zq_star(ctx, r_a)
            || BN_sub(neg_r_m, ctx->q, r_m) != 1   /* -r_m as q - r_m */
            || !paea_muls(ctx, r_pt, r_a, 1,
                          (const EC_POINT *[]){ t_pt },
                          (const BIGNUM *[]){ neg_r_m })) /* R = r_a*g - r_m*T */
        goto err;

    if (ctx->revocation) {
        if (ctx->witness == NULL || ctx->acc == NULL)
            goto err_notinit;
        m_pt = EC_POINT_new(ctx->group);
        n_pt = EC_POINT_new(ctx->group);
        z = BN_new();
        r_z = BN_new();
        s_z = BN_new();
        if (m_pt == NULL || n_pt == NULL || z == NULL || r_z == NULL
                || s_z == NULL)
            goto err;
        if (!paea_rand_in_zq_star(ctx, z)
                || !paea_scalar_mul(ctx, z, ctx->witness, m_pt)) /* M = z*W */
            goto err;
        if (!paea_rand_in_zq_star(ctx, r_z)
                || !paea_muls(ctx, n_pt, NULL, 2,
                              (const EC_POINT *[]){ ctx->acc, m_pt },
                              (const BIGNUM *[]){ r_z, neg_r_m }))
            goto err;                                        /* N = r_z*B_n - r_m*M */
    }

    /* challenge */
    if (!paea_zyhw_challenge(ctx, t_pt, r_pt, m_pt, n_pt, x_pt, y_pt,
                             sig, tllen, c))
        goto err;

    /* responses, all reduced mod q (the standard's "mod q" applies to the
     * result, c itself is not reduced) */
    if (BN_mul(tmp, c, ctx->m, bctx) != 1
            || BN_mod_add(s_m, r_m, tmp, ctx->q, bctx) != 1)
        goto err;
    if (BN_mul(tmp, c, a, bctx) != 1
            || BN_mod_add(s_a, r_a, tmp, ctx->q, bctx) != 1)
        goto err;
    if (ctx->revocation
            && (BN_mul(tmp, c, z, bctx) != 1
                || BN_mod_add(s_z, r_z, tmp, ctx->q, bctx) != 1))
        goto err;

    /* sigma_U: TL(T) [TL(M)] TL(c) TL(s_m) TL(s_a) [TL(s_z)] */
    if (!paea_buf_point(ctx, &su, t_pt))
        goto err;
    if (ctx->revocation && !paea_buf_point(ctx, &su, m_pt))
        goto err;
    if (!paea_buf_int(ctx, &su, c)
            || !paea_buf_int(ctx, &su, s_m)
            || !paea_buf_int(ctx, &su, s_a))
        goto err;
    if (ctx->revocation && !paea_buf_int(ctx, &su, s_z))
        goto err;

    su_raw = paea_buf_release(&su, &su_len);
    if (su_raw == NULL)
        goto err;

    /* msg2 = TL(X) sigma_U */
    if (!paea_buf_point(ctx, msg2, x_pt)
            || !paea_buf_raw(msg2, su_raw, su_len))
        goto err;

    /* optional session key */
    kdh = EC_POINT_new(ctx->group);
    if (kdh == NULL)
        goto err;
    if (!paea_scalar_mul(ctx, x, y_pt, kdh))           /* x*Y */
        goto err;
    if (!paea_zyhw_session_key(ctx, y_pt, x_pt, sig, tllen,
                               su_raw, su_len, kdh, &sk, &sk_len))
        goto err;

    paea_ctx_clear_session(ctx);
    ctx->sk = sk;
    ctx->sk_len = sk_len;
    ctx->accepted = 1;
    sk = NULL;
    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    /* the standard stops the protocol with REJECT; use the dedicated
     * reason when nothing more specific has been raised already */
 done:
    paea_buf_cleanup(&su);
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
    OPENSSL_clear_free(sk, sk_len);
    return ret;
}

/*
 * Pass 3 (server): verify sigma_U.  Returns 1 (ACCEPT) or 0 (REJECT),
 * the (optional) session key is available through get_session_key().
 */
int paea_zyhw_server_verify(EVP_PAEA_CTX *ctx, const unsigned char *msg2,
                            size_t msg2_len)
{
    PAEA_RDR r = { msg2, msg2_len, 0 };
    PAEA_BUF su;
    size_t unused;
    BIGNUM *c = NULL, *c_chk = NULL;
    BIGNUM *s_m = NULL, *s_a = NULL, *s_z = NULL;
    BIGNUM *neg_c = NULL, *neg_sm = NULL;
    const EC_POINT *pts[3];
    const BIGNUM *scalar_s[3];
    EC_POINT *x_pt = NULL, *t_pt = NULL, *r_pt = NULL;
    EC_POINT *m_pt = NULL, *v_pt = NULL, *p_pt = NULL, *n_pt = NULL;
    EC_POINT *kdh = NULL;
    unsigned char *su_raw = NULL;
    size_t su_len = 0;
    unsigned char *sk = NULL;
    size_t sk_len = 0;
    int ret = 0;

    paea_buf_init(&su);

    if (!ctx->srv_pend || ctx->r == NULL || ctx->sess_y == NULL
            || ctx->sess_y_pt == NULL
            || ctx->sess_sig == NULL || ctx->sess_sig_len == 0) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }

    x_pt = EC_POINT_new(ctx->group);
    t_pt = EC_POINT_new(ctx->group);
    r_pt = EC_POINT_new(ctx->group);
    v_pt = EC_POINT_new(ctx->group);
    c = BN_new();
    c_chk = BN_new();
    s_m = BN_new();
    s_a = BN_new();
    neg_c = BN_new();
    neg_sm = BN_new();
    if (x_pt == NULL || t_pt == NULL || r_pt == NULL || v_pt == NULL
            || c == NULL || c_chk == NULL || s_m == NULL || s_a == NULL
            || neg_c == NULL || neg_sm == NULL)
        goto err;

    /* msg2: TL(X) TL(T) [TL(M)] TL(c) TL(s_m) TL(s_a) [TL(s_z)] */
    if (!paea_rdr_take_point(ctx->group, &r, x_pt, &unused)
            || !paea_rdr_take_point(ctx->group, &r, t_pt, &unused))
        goto err;
    if (ctx->revocation) {
        m_pt = EC_POINT_new(ctx->group);
        if (m_pt == NULL || !paea_rdr_take_point(ctx->group, &r, m_pt, &unused))
            goto err;
    }
    if (!paea_rdr_take_int(&r, c, &unused)
            || !paea_rdr_take_int(&r, s_m, &unused)
            || !paea_rdr_take_int(&r, s_a, &unused))
        goto err;
    if (ctx->revocation) {
        s_z = BN_new();
        if (s_z == NULL || !paea_rdr_take_int(&r, s_z, &unused))
            goto err;
    }
    if (r.remaining != 0 || c == NULL)
        goto err;

    /* public point validation; the standard additionally requires
    /* public point validation; the standard requires T != 1 and, with
     * revocation, M != 1 ("1" being the group identity, i.e. the point
     * at infinity in the EC instantiation, 7.3.4 step 3 / 7.3.5) */
    if (!paea_point_valid_pub(ctx, x_pt)
            || !paea_point_valid_pub(ctx, t_pt)
            || (ctx->revocation && !paea_point_valid_pub(ctx, m_pt)))
        goto err;
    if (EC_POINT_is_at_infinity(ctx->group, t_pt) == 1)
        goto err;                    /* T != 1 */
    if (ctx->revocation
            && EC_POINT_is_at_infinity(ctx->group, m_pt) == 1)
        goto err;                    /* M != 1 */

    /* additive inverses mod q; BN_sub may go negative when c >= q, the
     * scalars are reduced mod q inside paea_muls() anyway */
    if (BN_sub(neg_c, ctx->q, c) != 1
            || BN_sub(neg_sm, ctx->q, s_m) != 1)
        goto err;
    /* V = r*T, then R' = s_a*g - s_m*T - c*V */
    if (!paea_scalar_mul(ctx, ctx->r, t_pt, v_pt))
        goto err;
    pts[0] = t_pt;     scalar_s[0] = neg_sm;
    pts[1] = v_pt;     scalar_s[1] = neg_c;
    if (!paea_muls(ctx, r_pt, s_a, 2, &pts[0], &scalar_s[0]))
        goto err;

    if (ctx->revocation) {
        /* P = chi*M, then N' = s_z*B_n - s_m*M - c*P */
        p_pt = EC_POINT_new(ctx->group);
        n_pt = EC_POINT_new(ctx->group);
        if (p_pt == NULL || n_pt == NULL
                || ctx->acc == NULL || ctx->acckey == NULL)
            goto err;
        if (!paea_scalar_mul(ctx, ctx->acckey, m_pt, p_pt))
            goto err;
        pts[0] = ctx->acc;   scalar_s[0] = s_z;
        pts[1] = m_pt;       scalar_s[1] = neg_sm;
        pts[2] = p_pt;       scalar_s[2] = neg_c;
        if (!paea_muls(ctx, n_pt, NULL, 3, &pts[0], &scalar_s[0]))
            goto err;
        if (!paea_zyhw_challenge(ctx, t_pt, r_pt, m_pt, n_pt,
                                 x_pt, ctx->sess_y_pt,
                                 ctx->sess_sig, ctx->sess_sig_len,
                                 c_chk))
            goto err;
    } else {
        if (!paea_zyhw_challenge(ctx, t_pt, r_pt, NULL, NULL,
                                 x_pt, ctx->sess_y_pt,
                                 ctx->sess_sig, ctx->sess_sig_len,
                                 c_chk))
            goto err;
    }

    if (BN_cmp(c, c_chk) != 0)
        goto err;                    /* REJECT */

    /* Recompose the sigma_U part the user has sent; the TL encoding is
     * canonical so the reconstructed bytes equal the original ones. */
    if (!paea_buf_point(ctx, &su, t_pt))
        goto err;
    if (ctx->revocation && !paea_buf_point(ctx, &su, m_pt))
        goto err;
    if (!paea_buf_int(ctx, &su, c)
            || !paea_buf_int(ctx, &su, s_m)
            || !paea_buf_int(ctx, &su, s_a))
        goto err;
    if (ctx->revocation && !paea_buf_int(ctx, &su, s_z))
        goto err;
    su_raw = paea_buf_release(&su, &su_len);
    if (su_raw == NULL)
        goto err;

    /* optional session key: y*X */
    kdh = EC_POINT_new(ctx->group);
    if (kdh == NULL)
        goto err;
    if (!paea_scalar_mul(ctx, ctx->sess_y, x_pt, kdh))
        goto err;
    if (!paea_zyhw_session_key(ctx, ctx->sess_y_pt, x_pt,
                               ctx->sess_sig, ctx->sess_sig_len,
                               su_raw, su_len, kdh, &sk, &sk_len))
        goto err;

    paea_ctx_clear_session(ctx);     /* also clears srv_pend */
    OPENSSL_free(su_raw);
    su_raw = NULL;
    ctx->sk = sk;
    ctx->sk_len = sk_len;
    ctx->accepted = 1;
    sk = NULL;
    ret = 1;
    goto done;

 err:
 done:
    paea_buf_cleanup(&su);
    OPENSSL_free(su_raw);
    BN_clear_free(c);
    BN_free(c_chk);
    BN_clear_free(s_m);
    BN_clear_free(s_a);
    BN_clear_free(s_z);
    BN_clear_free(neg_c);
    BN_clear_free(neg_sm);
    EC_POINT_free(x_pt);
    EC_POINT_free(t_pt);
    EC_POINT_free(r_pt);
    EC_POINT_free(m_pt);
    EC_POINT_free(v_pt);
    EC_POINT_free(p_pt);
    EC_POINT_free(n_pt);
    EC_POINT_free(kdh);
    OPENSSL_clear_free(sk, sk_len);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return ret;
}

/*
 * Public API wrappers with the EVP style buffer convention: *out is an
 * in/out size, out == NULL returns the required size.
 */
static int paea_export_buf(PAEA_BUF *b, unsigned char *out, size_t *out_len)
{
    unsigned char *data;
    size_t len;
    int ret = 0;

    data = paea_buf_release(b, &len);
    if (data == NULL) {
        *out_len = 0;
        return 0;
    }
    if (out == NULL) {
        *out_len = len;
        ret = 1;
    } else if (*out_len < len) {
        *out_len = len;
        ret = 0;
    } else {
        memcpy(out, data, len);
        *out_len = len;
        ret = 1;
    }
    OPENSSL_free(data);
    return ret;
}

int EVP_PAEA_server_auth_init(EVP_PAEA_CTX *ctx, unsigned char *out,
                              size_t *out_len)
{
    PAEA_BUF msg;
    int ret;

    if (ctx == NULL || out_len == NULL)
        return 0;
    if (ctx->mechanism == NID_undef) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
    if (ctx->mechanism != NID_zyhw_mechanism) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
    paea_buf_init(&msg);
    if (!paea_zyhw_server_auth_init(ctx, &msg)) {
        paea_buf_cleanup(&msg);
        return 0;
    }
    ret = paea_export_buf(&msg, out, out_len);
    paea_buf_cleanup(&msg);
    return ret;
}

int EVP_PAEA_user_auth_prove(EVP_PAEA_CTX *ctx, const unsigned char *pw,
                             size_t pw_len, const unsigned char *msg1,
                             size_t msg1_len, unsigned char *out,
                             size_t *out_len)
{
    PAEA_BUF msg;
    int ret;

    if (ctx == NULL || out_len == NULL || msg1 == NULL)
        return 0;
    if (ctx->mechanism != NID_zyhw_mechanism) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
    paea_buf_init(&msg);
    if (!paea_zyhw_user_prove(ctx, pw, pw_len, msg1, msg1_len, &msg)) {
        paea_buf_cleanup(&msg);
        return 0;
    }
    ret = paea_export_buf(&msg, out, out_len);
    paea_buf_cleanup(&msg);
    return ret;
}

int EVP_PAEA_server_auth_verify(EVP_PAEA_CTX *ctx, const unsigned char *msg2,
                                size_t msg2_len)
{
    if (ctx == NULL || msg2 == NULL || msg2_len == 0)
        return 0;
    if (ctx->mechanism != NID_zyhw_mechanism) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
    return paea_zyhw_server_verify(ctx, msg2, msg2_len);
}

int EVP_PAEA_CTX_get_session_key(EVP_PAEA_CTX *ctx, unsigned char *out,
                                  size_t *out_len)
{
    if (ctx == NULL || out_len == NULL)
        return 0;
    if (!ctx->accepted || ctx->sk == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NO_SESSION_KEY);
        return 0;
    }
    if (out == NULL) {
        *out_len = ctx->sk_len;
        return 1;
    }
    if (*out_len < ctx->sk_len) {
        *out_len = ctx->sk_len;
        return 0;
    }
    memcpy(out, ctx->sk, ctx->sk_len);
    *out_len = ctx->sk_len;
    return 1;
}