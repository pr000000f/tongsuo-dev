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
 * revocation.  Callers hold the group, r, w and the CRL.  Serialisation
 * lives in
 * paea_blob.c; the anonymous authentication exchange lives in
 * paea_auth.c.
 */

#include <openssl/byteorder.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"

/*
 * Setup (7.3.2): generate the server secret r, w = g^r and a fresh
 * signing key pair.  Revocation (7.3.5) reuses this same r; the public
 * parameter it calls w is the w already published here.  An empty CRL
 * has accumulator B_0 = g.
 *
 * SM2 keys sign with SM3 per GB/T 32918.2 (the instantiation chosen for
 * the GB/T 17902.2/.3 based digital signature); plain EC keys sign on
 * the curve given by the "sig-curve" parameter, falling back to the
 * mechanism's group itself.
 */
static EVP_PKEY *paea_keygen_sig(OSSL_LIB_CTX *libctx, const char *propq,
                                 const char *sig_type, const char *sig_curve,
                                 const EC_GROUP *group)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(libctx, sig_type, propq);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) != 1)
        goto err;

    if (OPENSSL_strcasecmp(sig_type, "SM2") == 0) {
        if (EVP_PKEY_CTX_set_group_name(pctx, "sm2") != 1)
            goto err;
    } else {
        const char *curve = sig_curve;

        if (curve == NULL) {
            int nid = EC_GROUP_get_curve_name(group);

            if (nid != NID_undef)
                curve = OBJ_nid2sn(nid);
        }
        if (curve == NULL || EVP_PKEY_CTX_set_group_name(pctx, curve) != 1)
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

int paea_zyhw_setup(const EC_GROUP *group, const char *sig_type,
                    const char *sig_digest_name, const char *sig_curve_name,
                    OSSL_LIB_CTX *libctx, const char *propq, int revocation,
                    BIGNUM **r_out, EC_POINT **w_out, EC_POINT **acc_out,
                    EVP_PKEY **sig_key_out, char **sig_digest_out)
{
    const BIGNUM *q;
    const EC_POINT *g;
    BIGNUM *r = NULL;
    EC_POINT *w = NULL, *acc = NULL;
    EVP_PKEY *sigkey = NULL;
    char *digest_out = NULL;

    *r_out = NULL;
    *w_out = NULL;
    *acc_out = NULL;
    *sig_key_out = NULL;
    *sig_digest_out = NULL;

    ossl_err_load_PAEA_strings();
    if (group == NULL || sig_type == NULL
        || (q = EC_GROUP_get0_order(group)) == NULL
        || (g = EC_GROUP_get0_generator(group)) == NULL)
        goto err_notinit;

    r = BN_new();
    w = EC_POINT_new(group);
    if (r == NULL || w == NULL)
        goto err;
    if (!paea_rand_in_zq_star(q, r))
        goto err;
    if (EC_POINT_mul(group, w, r, NULL, NULL, NULL) != 1) /* w = r*g */
        goto err;

    if (revocation) {
        acc = EC_POINT_new(group);
        if (acc == NULL)
            goto err;
        /* empty accumulator: B_0 = g (empty product is 1) */
        if (!EC_POINT_copy(acc, g))
            goto err;
    }

    sigkey = paea_keygen_sig(libctx, propq, sig_type, sig_curve_name, group);
    if (sigkey == NULL)
        goto err;

    if (OPENSSL_strcasecmp(sig_type, "SM2") == 0)
        digest_out = OPENSSL_strdup("SM3");
    else if (sig_digest_name != NULL)
        digest_out = OPENSSL_strdup(sig_digest_name);
    else
        digest_out = OPENSSL_strdup("SHA256");
    if (digest_out == NULL)
        goto err;

    *r_out = r;
    *w_out = w;
    *acc_out = acc;
    *sig_key_out = sigkey;
    *sig_digest_out = digest_out;
    return 1;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
    return 0;

 err:
    BN_clear_free(r);
    EC_POINT_free(w);
    EC_POINT_free(acc);
    EVP_PKEY_free(sigkey);
    OPENSSL_free(digest_out);
    return 0;
}

/*
 * Registration (7.3.3)
 *
 * m = BS2IP(H_lamda(I_U)).  Reject m = -r.  sigma = g^(1/(r+m)).
 * With revocation, also W = B_n^(1/(r+m)); acc == NULL means revocation
 * is off.  crl_len is the CRL size the witness was issued against.
 *
 * issued blob: sigma, and with revocation the witness index and W.
 */
int paea_zyhw_issue_credential(const EC_GROUP *group, const EVP_MD *md,
                               const BIGNUM *r, const EC_POINT *acc,
                               size_t crl_len,
                               const unsigned char *uid, size_t uid_len,
                               unsigned char **out, size_t *out_len)
{
    const BIGNUM *q;
    BIGNUM *m = NULL, *s = NULL, *inv = NULL;
    EC_POINT *sigma = NULL, *wit = NULL;
    unsigned char *data = NULL;
    size_t len = 0, off, ptlen;
    BN_CTX *bctx = NULL;
    int ret = 0;

    *out = NULL;
    *out_len = 0;
    q = EC_GROUP_get0_order(group);
    if (q == NULL || r == NULL)
        goto err_notinit;

    m = BN_new();
    s = BN_new();
    inv = BN_new();
    sigma = EC_POINT_new(group);
    bctx = BN_CTX_new();
    if (m == NULL || s == NULL || inv == NULL || sigma == NULL || bctx == NULL)
        goto err;

    if (!paea_m_of_uid(md, group, uid, uid_len, m))
        goto err;

    /* reject if m = -r (r + m = 0 mod q): no inverse exists */
    if (BN_mod_add(s, r, m, q, bctx) != 1)
        goto err;
    if (BN_is_zero(s)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
        goto err;
    }
    if (BN_mod_inverse(inv, s, q, bctx) == NULL)
        goto err;
    if (EC_POINT_mul(group, sigma, inv, NULL, NULL, bctx) != 1)
        goto err;                               /* sigma = (1/(r+m))*g */

    ptlen = paea_point_len(group);
    if (ptlen == 0)
        goto err;
    len = ptlen;

    if (acc != NULL) {
        wit = EC_POINT_new(group);
        if (wit == NULL)
            goto err;
        /* W = B_n^(1/(r+m)); the m = -r check above is this inverse */
        if (EC_POINT_mul(group, wit, NULL, acc, inv, bctx) != 1)
            goto err;
        len += 4 + ptlen;
    }

    data = OPENSSL_malloc(len);
    if (data == NULL)
        goto err;
    off = paea_put_point(group, data, sigma);
    if (off == 0)
        goto err;
    if (wit != NULL) {
        OPENSSL_store_u32_be(data + off, (uint32_t)crl_len);
        off += 4;
        if (paea_put_point(group, data + off, wit) == 0)
            goto err;
    }

    *out = data;
    *out_len = len;
    data = NULL;
    ret = 1;
    goto done;

 err_notinit:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
 err:
    OPENSSL_clear_free(data, len);
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
 * sigma_pw = sigma + H_g(pw).  The issued blob is parsed here; the
 * wrapped point (and the witness, when revocation is on) is what the
 * user keeps.
 */
int paea_zyhw_wrap_credential(const EC_GROUP *group, const EVP_MD *md,
                              const unsigned char *uid, size_t uid_len,
                              const unsigned char *pw, size_t pw_len,
                              const unsigned char *issued, size_t issued_len,
                              int revocation,
                              BIGNUM **m_out, EC_POINT **sigma_pw,
                              EC_POINT **witness, uint32_t *witness_idx)
{
    const unsigned char *cur = issued;
    size_t rem = issued_len;
    uint32_t idx = 0;
    BIGNUM *m = NULL;
    EC_POINT *sigma = NULL, *s_pw = NULL, *wit = NULL, *hp = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    *m_out = NULL;
    *sigma_pw = NULL;
    *witness = NULL;
    *witness_idx = 0;

    sigma = EC_POINT_new(group);
    s_pw = EC_POINT_new(group);
    m = BN_new();
    bctx = BN_CTX_new();
    if (sigma == NULL || s_pw == NULL || m == NULL || bctx == NULL)
        goto err;

    if (!paea_get_point(group, &cur, &rem, sigma)) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
        goto err;
    }
    if (rem == 0 && revocation) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        goto err;
    }

    if (revocation) {
        wit = EC_POINT_new(group);
        if (wit == NULL || rem < 4)
            goto err;
        cur = OPENSSL_load_u32_be(&idx, cur);
        rem -= 4;
        if (!paea_get_point(group, &cur, &rem, wit)) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
            goto err;
        }
    }
    if (rem != 0) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        goto err;
    }

    /* sigma_pw = sigma + H_g(pw) */
    hp = EC_POINT_new(group);
    if (hp == NULL || !paea_h_g(group, md, pw, pw_len, hp))
        goto err;
    if (EC_POINT_add(group, s_pw, sigma, hp, bctx) != 1)
        goto err;
    if (!paea_m_of_uid(md, group, uid, uid_len, m))
        goto err;

    *m_out = m;
    *sigma_pw = s_pw;
    *witness = wit;
    *witness_idx = idx;
    m = NULL;
    s_pw = NULL;
    wit = NULL;
    ret = 1;
    goto done;

 err:
    BN_clear_free(m);
 done:
    BN_CTX_free(bctx);
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
 * acc = B_n <- B_n^(1/(r+m)).
 */
int paea_crl_revoke(const EC_GROUP *group, const BIGNUM *r, EC_POINT **acc,
                    PAEA_CRL_ENTRY **crl, size_t *crl_len, size_t *crl_alloc,
                    const BIGNUM *m)
{
    const BIGNUM *q;
    BIGNUM *s = NULL, *inv = NULL;
    EC_POINT *b = NULL, *acc_new = NULL;
    BN_CTX *bctx = NULL;

    size_t i;

    if (group == NULL || r == NULL || acc == NULL || *acc == NULL
        || crl == NULL || crl_len == NULL || crl_alloc == NULL
        || (q = EC_GROUP_get0_order(group)) == NULL)
        goto err_notinit;

    /* A second revocation of the same m makes the witness update of
     * 7.3.5 divide by zero (implementation notes, issue #10). */
    if (*crl != NULL) {
        for (i = 0; i < *crl_len; i++) {
            if (BN_cmp((*crl)[i].m, m) == 0) {
                ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
                return 0;
            }
        }
    }

    s = BN_new();
    inv = BN_new();
    bctx = BN_CTX_new();
    if (s == NULL || inv == NULL || bctx == NULL)
        goto err;
    if (BN_mod_add(s, r, m, q, bctx) != 1)
        goto err;
    if (BN_is_zero(s)) {
        /* r + m = 0 mod q: the inverse in B_i does not exist */
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
        goto err;
    }
    if (BN_mod_inverse(inv, s, q, bctx) == NULL)
        goto err;

    b = EC_POINT_new(group);
    acc_new = EC_POINT_new(group);
    if (b == NULL || acc_new == NULL)
        goto err;
    if (EC_POINT_mul(group, b, NULL, *acc, inv, bctx) != 1)
        goto err;                                  /* B <- B^(1/(r+m)) */
    if (!EC_POINT_copy(acc_new, b))
        goto err;

    if (*crl == NULL) {
        *crl = OPENSSL_zalloc(4 * sizeof(**crl));
        if (*crl == NULL)
            goto err;
        *crl_alloc = 4;
        *crl_len = 0;
    }
    if (*crl_len == *crl_alloc) {
        size_t nalloc = *crl_alloc > 0 ? *crl_alloc * 2 : 4;
        PAEA_CRL_ENTRY *tmp = OPENSSL_realloc(*crl, nalloc * sizeof(*tmp));

        if (tmp == NULL)
            goto err;
        *crl = tmp;
        *crl_alloc = nalloc;
    }
    (*crl)[*crl_len].m = BN_dup(m);
    if ((*crl)[*crl_len].m == NULL)
        goto err;
    (*crl)[*crl_len].b = b;
    (*crl_len)++;

    EC_POINT_free(*acc);
    *acc = acc_new;
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


/*
 * Witness refresh after the CRL grew (7.3.5):
 *   W <- (W - B_{j+1}) * 1/(m_{j+1} - m)   for each newly added entry.
 * delta = 0 means this user is now on the CRL.
 */
int paea_zyhw_update_witness(const EC_GROUP *group, const BIGNUM *m,
                             EC_POINT *witness, uint32_t *witness_idx,
                             const PAEA_CRL_ENTRY *crl, size_t crl_len)
{
    const BIGNUM *q = EC_GROUP_get0_order(group);
    BIGNUM *delta = NULL, *inv = NULL;
    EC_POINT *tmp = NULL, *res = NULL;
    BN_CTX *bctx = NULL;
    size_t i;
    int ret = 0;

    if (q == NULL || witness == NULL || m == NULL)
        goto err_notinit;
    if (*witness_idx > crl_len) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WITNESS_INVALID);
        goto err;
    }

    delta = BN_new();
    inv = BN_new();
    tmp = EC_POINT_new(group);
    res = EC_POINT_new(group);
    bctx = BN_CTX_new();
    if (delta == NULL || inv == NULL || tmp == NULL || res == NULL
        || bctx == NULL)
        goto err;

    for (i = *witness_idx; i < crl_len; i++) {
        if (BN_mod_sub(delta, crl[i].m, m, q, bctx) != 1)
            goto err;
        if (BN_is_zero(delta)) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_USER_REVOKED);
            goto err;
        }
        if (BN_mod_inverse(inv, delta, q, bctx) == NULL)
            goto err;

        /* W' = (W - B_i) * 1/(m_i - m) */
        if (EC_POINT_copy(tmp, crl[i].b) != 1
            || EC_POINT_invert(group, tmp, bctx) != 1
            || EC_POINT_add(group, res, witness, tmp, bctx) != 1
            || EC_POINT_mul(group, tmp, NULL, res, inv, bctx) != 1
            || EC_POINT_copy(witness, tmp) != 1)
            goto err;
        *witness_idx = (uint32_t)(i + 1);
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
