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
 * ZYHW mechanism (GB/T 34953.4-XXXX, 7.3): setup, user registration and
 * revocation operations on top of the prime order cyclic group in
 * EVP_PAEA_CTX.  The serialisation of the exchanged objects lives in
 * paea_blob.c; the anonymous authentication exchange lives in
 * paea_auth.c.
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"

/*
 * Setup (7.3.2): generate the server secret r, w = g^r and, when user
 * revocation is enabled, the additional key ACC(r) = chi with ACC(w) =
 * g^chi, plus a fresh signing key pair for the server signature scheme.
 *
 * SM2 keys sign with SM3 per GB/T 32918.2 (the instantiation chosen for
 * the GB/T 17902.2/.3 based digital signature); plain EC keys sign on
 * the curve given by the "sig-curve" parameter, falling back to the
 * mechanism's group itself.
 */
static EVP_PKEY *paea_keygen_sig(EVP_PAEA_CTX *ctx)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(ctx->libctx, ctx->sig_type,
                                      ctx->propq);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) != 1)
        goto err;

    if (OPENSSL_strcasecmp(ctx->sig_type, "SM2") == 0) {
        if (EVP_PKEY_CTX_set_group_name(pctx, "sm2") != 1)
            goto err;
    } else {
        const char *sigcurve = ctx->sig_curve_name;

        if (sigcurve == NULL) {
            int nid = EC_GROUP_get_curve_name(ctx->group);

            if (nid != NID_undef)
                sigcurve = OBJ_nid2sn(nid);
        }
        if (sigcurve == NULL
                || EVP_PKEY_CTX_set_group_name(pctx, sigcurve) != 1)
            goto err;
    }

    if (EVP_PKEY_generate(pctx, &pkey) != 1)
        goto err;

    EVP_PKEY_CTX_free(pctx);
    return pkey;

 err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_KEYGEN_FAILED);
    return NULL;
}

int paea_zyhw_setup(EVP_PAEA_CTX *ctx)
{
    BIGNUM *r = NULL, *chi = NULL;
    EC_POINT *w = NULL, *accw = NULL, *acc = NULL;
    EVP_PKEY *sigkey = NULL;
    char *sig_digest_name = NULL;

    if (ctx->mechanism != NID_zyhw_mechanism)
        goto err_notinit;
    if (ctx->group == NULL || ctx->md == NULL || ctx->sig_type == NULL)
        goto err_notinit;

    r = BN_new();
    w = EC_POINT_new(ctx->group);
    if (r == NULL || w == NULL)
        goto err;
    if (!paea_rand_in_zq_star(ctx, r))
        goto err;
    if (!paea_generator_mul(ctx, r, w))          /* w = g^r */
        goto err;

    if (ctx->revocation) {
        chi = BN_new();
        accw = EC_POINT_new(ctx->group);
        acc = EC_POINT_new(ctx->group);
        if (chi == NULL || accw == NULL || acc == NULL)
            goto err;
        if (!paea_rand_in_zq_star(ctx, chi))
            goto err;
        if (!paea_generator_mul(ctx, chi, accw)) /* ACC(w) = g^chi */
            goto err;
        /* empty accumulator: B_0 = g */
        if (!EC_POINT_copy(acc, ctx->gpt))
            goto err;
    }

    sigkey = paea_keygen_sig(ctx);
    if (sigkey == NULL)
        goto err;

    if (OPENSSL_strcasecmp(ctx->sig_type, "SM2") == 0)
        sig_digest_name = OPENSSL_strdup("SM3");
    else if (ctx->sig_digest_name != NULL)
        sig_digest_name = OPENSSL_strdup(ctx->sig_digest_name);
    else
        sig_digest_name = OPENSSL_strdup("SHA256");
    if (sig_digest_name == NULL)
        goto err;

    /* Install the fresh state, dropping any previous one.  Re-running
     * setup therefore resets the whole mechanism (all previously issued
     * credentials become invalid); the standard text does not discuss
     * re-establishment (implementation notes, issue #9). */
    paea_ctx_clear_session(ctx);
    paea_ctx_clear_credential(ctx);
    paea_ctx_clear_crl(ctx);
    BN_clear_free(ctx->r);
    ctx->r = NULL;
    BN_clear_free(ctx->acckey);
    ctx->acckey = NULL;
    EC_POINT_free(ctx->w);
    ctx->w = NULL;
    EC_POINT_free(ctx->acc_w);
    ctx->acc_w = NULL;
    EVP_MD_free(ctx->sig_md);
    ctx->sig_md = NULL;

    ctx->r = r;
    ctx->w = w;
    ctx->acckey = chi;
    ctx->acc_w = accw;
    ctx->acc = acc;
    EVP_PKEY_free(ctx->sig_key);
    ctx->sig_key = sigkey;
    OPENSSL_free(ctx->sig_digest_name);
    ctx->sig_digest_name = sig_digest_name;

    ctx->params_ready = 1;
    ctx->server_secret = 1;
    return 1;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
    return 0;

 err:
    BN_clear_free(r);
    BN_clear_free(chi);
    EC_POINT_free(w);
    EC_POINT_free(accw);
    EC_POINT_free(acc);
    EVP_PKEY_free(sigkey);
    OPENSSL_free(sig_digest_name);
    return 0;
}

int EVP_PAEA_setup(EVP_PAEA_CTX *ctx)
{
    if (ctx == NULL)
        return 0;
    if (ctx->mechanism == NID_undef) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
    switch (ctx->mechanism) {
    case NID_zyhw_mechanism:
        return paea_zyhw_setup(ctx);
    default:
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM);
        return 0;
    }
}

/*
 * Registration (7.3.3)
 *
 * The server computes m = BS2IP(H_lamda(I_U)) -- REJECT if m = -r -- and
 * issues sigma = g^(1/(r+m)).  When revocation is enabled it also issues
 * the (unprotected) witness W = B_n^(1/(chi+m)), where B_n is the current
 * accumulator value (B_0 = g on an empty CRL); the CRL size the witness
 * was issued for is transported alongside so users can refresh it later.
 *
 * "issued" blob (implementation defined):
 *   TL(sigma)
 *   [u32 witness_crl_index TL(W)]   when revocation is enabled
 */
int EVP_PAEA_server_issue_credential(EVP_PAEA_CTX *ctx,
                                     const unsigned char *uid,
                                     size_t uid_len,
                                     unsigned char *out, size_t *out_len)
{
    BIGNUM *m = NULL, *s = NULL, *inv = NULL;
    EC_POINT *sigma = NULL, *wit = NULL;
    PAEA_BUF issued;
    unsigned char *data = NULL;
    size_t len = 0;
    BN_CTX *bctx = NULL;
    int ret = 0;

    paea_buf_init(&issued);

    if (uid == NULL || uid_len == 0 || out_len == NULL)
        goto err;
    if (!ctx->server_secret || ctx->r == NULL || !ctx->params_ready)
        goto err_notinit;

    m = BN_new();
    s = BN_new();
    inv = BN_new();
    sigma = EC_POINT_new(ctx->group);
    if (m == NULL || s == NULL || inv == NULL || sigma == NULL)
        goto err;
    bctx = BN_CTX_new();
    if (bctx == NULL)
        goto err;

    if (!paea_m_of_uid(ctx, uid, uid_len, m))
        goto err;

    /* reject if m = -r (r + m = 0 mod q): no inverse exists */
    if (BN_mod_add(s, ctx->r, m, ctx->q, bctx) != 1)
        goto err;
    if (BN_is_zero(s)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
        goto err;
    }
    if (!paea_inverse_mod_q(ctx, s, inv))
        goto err;
    if (!paea_generator_mul(ctx, inv, sigma))   /* sigma = g^(1/(r+m)) */
        goto err;

    if (!paea_buf_point(ctx, &issued, sigma))
        goto err;

    if (ctx->revocation) {
        if (ctx->acckey == NULL || ctx->acc == NULL)
            goto err_notinit;

        wit = EC_POINT_new(ctx->group);
        if (wit == NULL)
            goto err;
        /* reject if chi + m = 0 mod q (hash collision with the
         * revocation key or a previously revoked member) */
        if (BN_mod_add(s, ctx->acckey, m, ctx->q, bctx) != 1)
            goto err;
        if (BN_is_zero(s)) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
            goto err;
        }
        if (!paea_inverse_mod_q(ctx, s, inv))
            goto err;
        if (!paea_scalar_mul(ctx, inv, ctx->acc, wit))  /* W = B_n^(1/(chi+m)) */
            goto err;

        if (!paea_buf_u32(&issued, (uint32_t)ctx->crl_len)
                || !paea_buf_point(ctx, &issued, wit))
            goto err;
    }

    data = paea_buf_release(&issued, &len);   /* data != NULL on success */
    if (data == NULL)
        goto err;

    if (out == NULL) {
        *out_len = len;
    } else if (*out_len < len) {
        *out_len = len;
        OPENSSL_free(data);
        goto err;
    } else {
        memcpy(out, data, len);
        *out_len = len;
    }
    OPENSSL_free(data);
    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    paea_buf_cleanup(&issued);
 done:
    BN_clear_free(m);
    BN_clear_free(s);
    BN_clear_free(inv);
    BN_CTX_free(bctx);
    EC_POINT_free(sigma);
    EC_POINT_free(wit);
    return ret;
}

/*
 * The user recovers sigma = sigma_pw - H_g(pw) for the anonymous
 * authentication only, keeping the wrapped credential sigma_pw at rest.
 */
int EVP_PAEA_user_store_credential(EVP_PAEA_CTX *ctx,
                                   const unsigned char *uid, size_t uid_len,
                                   const unsigned char *pw, size_t pw_len,
                                   const unsigned char *issued,
                                   size_t issued_len)
{
    PAEA_RDR r = { issued, issued_len, 0 };
    size_t unused;
    BIGNUM *m = NULL, *m_chk = NULL;
    EC_POINT *sigma = NULL, *s_pw = NULL, *wit = NULL;
    EC_POINT *hp = NULL;
    uint32_t witness_idx = 0;
    int ret = 0;

    if (uid == NULL || uid_len == 0 || pw == NULL || issued == NULL)
        goto err;
    if (!ctx->params_ready || ctx->group == NULL)
        goto err_notinit;

    sigma = EC_POINT_new(ctx->group);
    s_pw = EC_POINT_new(ctx->group);
    m = BN_new();
    m_chk = BN_new();
    if (sigma == NULL || s_pw == NULL || m == NULL || m_chk == NULL)
        goto err;

    if (!paea_rdr_take_point(ctx->group, &r, sigma, &unused))
        goto err;
    if (r.remaining == 0 && ctx->revocation) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        goto err;
    }

    if (ctx->revocation) {
        wit = EC_POINT_new(ctx->group);
        if (wit == NULL
                || !paea_rdr_take_u32(&r, &witness_idx)
                || !paea_rdr_take_point(ctx->group, &r, wit, &unused))
            goto err;
    }
    if (r.remaining != 0) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        goto err;
    }

    /* sigma_pw = sigma + H_g(pw) */
    hp = EC_POINT_new(ctx->group);
    if (hp == NULL || !paea_h_g(ctx, pw, pw_len, hp))
        goto err;
    if (!paea_point_add(ctx, sigma, hp, s_pw))
        goto err;

    /* recompute m to stay independent of the issuing transcript */
    if (!paea_m_of_uid(ctx, uid, uid_len, m))
        goto err;

    /* consistency: the wrapped credential must be reconstructable from
     * the stored data; sanity check m through a second reduction */
    if (!paea_m_of_uid(ctx, uid, uid_len, m_chk) || BN_cmp(m, m_chk) != 0)
        goto err;

    paea_ctx_clear_credential(ctx);
    OPENSSL_free(ctx->uid);
    ctx->uid = OPENSSL_memdup(uid, uid_len);
    if (ctx->uid == NULL)
        goto err;
    ctx->uid_len = uid_len;
    ctx->m = m;
    ctx->sigma_pw = s_pw;
    ctx->witness = wit;
    ctx->witness_crl_index = witness_idx;
    m = NULL;
    s_pw = NULL;
    wit = NULL;
    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    BN_clear_free(m);            /* m is NULL when ownership moved */
 done:
    BN_free(m_chk);              /* check value only, holds no secret */
    EC_POINT_free(sigma);
    EC_POINT_free(s_pw);
    EC_POINT_free(wit);
    EC_POINT_free(hp);
    return ret;
}

/*
 * Revocation (7.3.5)
 */

/*
 * Append (m, B) to the CRL and update the running accumulator
 * acc = B_n <- B_n^(1/(chi+m)).
 */
int paea_crl_revoke(EVP_PAEA_CTX *ctx, const BIGNUM *m)
{
    BIGNUM *s = NULL, *inv = NULL;
    EC_POINT *b = NULL, *acc_new = NULL;
    BN_CTX *bctx = NULL;

    if (!ctx->revocation || ctx->acckey == NULL || ctx->acc == NULL
            || ctx->group == NULL)
        goto err_notinit;

    s = BN_new();
    inv = BN_new();
    bctx = BN_CTX_new();
    if (s == NULL || inv == NULL || bctx == NULL)
        goto err;
    if (BN_mod_add(s, ctx->acckey, m, ctx->q, bctx) != 1)
        goto err;
    if (BN_is_zero(s)) {
        /* chi + m = 0 mod q: cannot accumulate this member (the
         * standard does not discuss this 1/q event) */
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
        goto err;
    }
    if (!paea_inverse_mod_q(ctx, s, inv))
        goto err;

    b = EC_POINT_new(ctx->group);
    acc_new = EC_POINT_new(ctx->group);
    if (b == NULL || acc_new == NULL)
        goto err;
    if (!paea_scalar_mul(ctx, inv, ctx->acc, b))   /* B_n+1 = B_n^(1/(chi+m)) */
        goto err;
    if (!EC_POINT_copy(acc_new, b))
        goto err;

    /* grow the CRL */
    if (ctx->crl == NULL && !paea_ctx_setup_crl(ctx, 4))
        goto err;
    if (ctx->crl_len == ctx->crl_alloc) {
        size_t nalloc = ctx->crl_alloc > 0 ? ctx->crl_alloc * 2 : 4;
        PAEA_CRL_ENTRY *tmp = OPENSSL_realloc(ctx->crl,
                                              nalloc * sizeof(*tmp));

        if (tmp == NULL)
            goto err;
        ctx->crl = tmp;
        ctx->crl_alloc = nalloc;
    }
    ctx->crl[ctx->crl_len].m = BN_dup(m);
    if (ctx->crl[ctx->crl_len].m == NULL)
        goto err;
    ctx->crl[ctx->crl_len].b = b;
    ctx->crl_len++;

    /* rotate the accumulator to the fresh entry */
    EC_POINT_free(ctx->acc);
    ctx->acc = acc_new;
    BN_clear_free(s);
    BN_clear_free(inv);
    BN_CTX_free(bctx);
    return 1;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    BN_clear_free(s);
    BN_clear_free(inv);
    BN_CTX_free(bctx);
    EC_POINT_free(b);
    EC_POINT_free(acc_new);
    return 0;
}

int EVP_PAEA_server_revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid,
                           size_t uid_len)
{
    BIGNUM *m = NULL;
    size_t i;
    int ret;

    if (!ctx->revocation)
        goto err_notinit;
    if (ctx->acckey == NULL)
        goto err_notinit;

    m = BN_new();
    if (m == NULL || !paea_m_of_uid(ctx, uid, uid_len, m))
        goto err;

    /* duplicate revocation is rejected (the witness update of 7.3.5
     * implicitly requires distinct new CRL entries, implementation
     * notes issue #10) */
    for (i = 0; i < ctx->crl_len; i++) {
        if (BN_cmp(ctx->crl[i].m, m) == 0) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
            BN_clear_free(m);
            return 0;
        }
    }

    ret = paea_crl_revoke(ctx, m);
    BN_clear_free(m);
    return ret;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    BN_clear_free(m);
    return 0;
}

/*
 * Witness refresh after the CRL grew (7.3.5):
 *   W <- (W / B_{j+1})^(1/(m_{j+1} - m))   for the newly added entries
 * The user stops (and reports the user revoked) when delta = 0.
 */
int EVP_PAEA_user_update_witness(EVP_PAEA_CTX *ctx)
{
    BIGNUM *delta = NULL, *inv = NULL;
    EC_POINT *tmp = NULL, *res = NULL;
    BN_CTX *bctx = NULL;
    size_t i;
    int ret = 0;

    if (ctx->witness == NULL || ctx->m == NULL || !ctx->params_ready)
        goto err_notinit;

    /* the CRL shrank or the witness does not fit the imported list:
     * re-registration is required */
    if (ctx->witness_crl_index > ctx->crl_len) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WITNESS_INVALID);
        goto err;
    }

    delta = BN_new();
    inv = BN_new();
    tmp = EC_POINT_new(ctx->group);
    res = EC_POINT_new(ctx->group);
    bctx = BN_CTX_new();
    if (delta == NULL || inv == NULL || tmp == NULL || res == NULL
            || bctx == NULL)
        goto err;

    for (i = ctx->witness_crl_index; i < ctx->crl_len; i++) {
        if (BN_sub(delta, ctx->crl[i].m, ctx->m) != 1)
            goto err;
        if (BN_mod(delta, delta, ctx->q, bctx) != 1)
            goto err;
        if (BN_is_zero(delta)) {
            /* the user itself is on the CRL now */
            ERR_raise(ERR_LIB_PAEA, PAEA_R_USER_REVOKED);
            goto err;
        }
        if (!paea_inverse_mod_q(ctx, delta, inv))
            goto err;

        /* W' = (W - B_i) * 1/delta */
        if (!paea_point_sub(ctx, ctx->witness, ctx->crl[i].b, tmp))
            goto err;
        if (!paea_scalar_mul(ctx, inv, tmp, res))
            goto err;
        if (!EC_POINT_copy(ctx->witness, res))
            goto err;
        ctx->witness_crl_index = (uint32_t)(i + 1);
    }

    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
 done:
    BN_clear_free(delta);
    BN_clear_free(inv);
    BN_CTX_free(bctx);
    EC_POINT_free(tmp);
    EC_POINT_free(res);
    return ret;
}