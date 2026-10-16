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
 * Serialisation of the ZYHW protocol objects.  None of these formats is
 * fixed by the standard text (it only specifies abstract tuples), they
 * are the implementation defined on the wire / at rest representations:
 *
 *   "params"     the trusted copy of the public system parameters
 *   "servkey"    the server secret key material (never publish!)
 *   "crl"        the credential revocation list
 *   "credential" the user's password wrapped credential
 *
 * All variable size fields use the TL encoding of paea_local.h.  The
 * group travels as a DER encoded ECPKParameters structure, so users are
 * not restricted to the named curves locally known to libcrypto.
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>
#include <openssl/x509.h>

#include "paea_local.h"

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static int paea_buf_tlname(PAEA_BUF *b, const char *name)
{
    size_t len = name != NULL ? strlen(name) : 0;

    if (!paea_buf_u32(b, (uint32_t)len))
        return 0;
    if (len == 0)
        return 1;
    return paea_buf_raw(b, name, len);
}

static int paea_buf_tlder(PAEA_BUF *b, const unsigned char *der, size_t derlen)
{
    if (derlen == 0 || der == NULL)
        return 0;
    if (!paea_buf_u32(b, (uint32_t)derlen))
        return 0;
    return paea_buf_raw(b, der, derlen);
}

/* take a TL encoded UTF8-ish name, no embedded NUL bytes allowed */
static char *paea_take_tlname(PAEA_RDR *r)
{
    size_t len;
    const unsigned char *p;
    char *s;

    if (!paea_rdr_take_tl(r, &len, &p))
        return NULL;
    s = OPENSSL_strndup((const char *)p, len);
    if (s == NULL)
        return NULL;
    if (strlen(s) != len) {        /* embedded NUL, or trailing NUL */
        OPENSSL_free(s);
        return NULL;
    }
    return s;
}

static void paea_free_crl_arr(PAEA_CRL_ENTRY *arr, size_t n)
{
    size_t i;

    if (arr == NULL)
        return;
    for (i = 0; i < n; i++) {
        BN_clear_free(arr[i].m);
        EC_POINT_free(arr[i].b);
    }
    OPENSSL_free(arr);
}

/* ------------------------------------------------------------------ */
/* CRL                                                                 */
/*                                                                     */
/*   u8 version                                                        */
/*   u32 n                                                             */
/*   n * { TL(m_i) TL(B_i) }                                           */
/* ------------------------------------------------------------------ */

static int paea_parse_crl_content(const EC_GROUP *group, PAEA_RDR *r,
                                  PAEA_CRL_ENTRY **out_arr, size_t *out_n)
{
    uint8_t ver;
    uint32_t n;
    PAEA_CRL_ENTRY *arr = NULL;
    size_t i;

    *out_arr = NULL;
    *out_n = 0;

    if (!paea_rdr_take_u8(r, &ver) || ver != PAEA_BLOB_VERSION)
        goto err;
    if (!paea_rdr_take_u32(r, &n) || n > PAEA_MAX_CRL_ENTRIES)
        goto err;
    if (n > 0) {
        arr = OPENSSL_zalloc(n * sizeof(*arr));
        if (arr == NULL)
            goto err;
        for (i = 0; i < n; i++) {
            size_t unused;

            arr[i].m = BN_new();
            arr[i].b = EC_POINT_new(group);
            if (arr[i].m == NULL || arr[i].b == NULL)
                goto err;
            if (!paea_rdr_take_int(r, arr[i].m, &unused)
                    || !paea_rdr_take_point(group, r, arr[i].b, &unused))
                goto err;
            if (BN_is_zero(arr[i].m))
                goto err;
        }
    }
    *out_arr = arr;
    *out_n = n;
    return 1;

 err:
    paea_free_crl_arr(arr, n);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;
}

/*
 * Replace the context CRL with a freshly decoded array and refresh the
 * view of the current accumulator B_n: the last CRL entry, or the
 * generator for an empty list.  The standard does not define the empty
 * product; we take it to be 1 (B_0 = g), which keeps the witness
 * algebra of 7.3.5 consistent (see implementation notes).
 *
 * Ownership: on entry the array and all its entries are given away;
 * on any return path (success or failure) this function has consumed
 * them, so callers must never touch arr afterwards.
 */
static int paea_install_crl(EVP_PAEA_CTX *ctx, PAEA_CRL_ENTRY *arr,
                            size_t n)
{
    EC_POINT *acc = NULL;

    paea_ctx_clear_crl(ctx);
    if (!paea_ctx_setup_crl(ctx, (int)(n > 0 ? n : 4)))
        goto err_unmoved;
    if (n > 0) {
        memcpy(ctx->crl, arr, n * sizeof(*arr));
        ctx->crl_len = n;
        acc = EC_POINT_new(ctx->group);
        if (acc == NULL || !EC_POINT_copy(acc, arr[n - 1].b))
            goto err_moved;
    } else {
        acc = EC_POINT_new(ctx->group);
        if (acc == NULL || !EC_POINT_copy(acc, ctx->gpt))
            goto err_moved;
    }
    OPENSSL_free(arr);
    ctx->acc = acc;
    return 1;

 err_unmoved:
    /* nothing was moved into the context, release the given entries */
    paea_free_crl_arr(arr, n);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;

 err_moved:
    /* the entries now live in ctx->crl; clear them out by hand since
     * crl_len is reset here, then drop the array shells */
    {
        size_t i;

        for (i = 0; i < n; i++) {
            BN_clear_free(ctx->crl[i].m);
            EC_POINT_free(ctx->crl[i].b);
        }
    }
    OPENSSL_free(ctx->crl);
    ctx->crl = NULL;
    ctx->crl_len = 0;
    ctx->crl_alloc = 0;
    OPENSSL_free(arr);            /* bare shell, entries differ */
    EC_POINT_free(acc);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;
}

int paea_encode_crl_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *b)
{
    size_t i;

    if (!paea_buf_u8(b, PAEA_BLOB_VERSION))
        return 0;
    if (!paea_buf_u32(b, (uint32_t)ctx->crl_len))
        return 0;
    for (i = 0; i < ctx->crl_len; i++) {
        if (!paea_buf_int(ctx, b, ctx->crl[i].m))
            return 0;
        if (!paea_buf_point(ctx, b, ctx->crl[i].b))
            return 0;
    }
    return 1;
}

int paea_decode_crl_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                         size_t blob_len)
{
    PAEA_RDR r = { blob, blob_len, 0 };
    PAEA_CRL_ENTRY *arr = NULL;
    size_t n = 0;

    if (ctx->group == NULL)
        goto err;
    if (!paea_parse_crl_content(ctx->group, &r, &arr, &n))
        goto err;
    if (r.remaining != 0)
        goto err;
    return paea_install_crl(ctx, arr, n);

 err:
    paea_free_crl_arr(arr, n);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;
}

/* ------------------------------------------------------------------ */
/* "params" blob                                                       */
/*                                                                     */
/*   u8  version                                                       */
/*   TL(ECPKParameters DER)                                            */
/*   TL(digest name)                                                   */
/*   TL(sig_type)                                                      */
/*   TL(sig digest name)                                               */
/*   u8  revocation enabled                                            */
/*   TL(w point)                                                       */
/*   [TL(ACC(w) point)]                                                */
/*   [CRL blob]                                                        */
/*   TL(sig public key SPKI DER)                                       */
/* ------------------------------------------------------------------ */

int paea_encode_params_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *b)
{
    BIO *mem = NULL;
    unsigned char *der = NULL;
    long derlen;
    unsigned char *memdata;
    int ret = 0;

    if (!ctx->params_ready)
        goto end;
    if (ctx->group == NULL || ctx->digest_name == NULL
            || ctx->sig_type == NULL || ctx->sig_digest_name == NULL
            || ctx->w == NULL || ctx->sig_key == NULL)
        goto end;
    if (ctx->revocation && ctx->acc_w == NULL)
        goto end;

    if (!paea_buf_u8(b, PAEA_BLOB_VERSION))
        goto end;

    derlen = i2d_ECPKParameters(ctx->group, &der);
    if (derlen <= 0)
        goto end;
    if (!paea_buf_tlder(b, der, (size_t)derlen))
        goto end;

    if (!paea_buf_tlname(b, ctx->digest_name)
            || !paea_buf_tlname(b, ctx->sig_type)
            || !paea_buf_tlname(b, ctx->sig_digest_name)
            || !paea_buf_u8(b, ctx->revocation != 0)
            || !paea_buf_point(ctx, b, ctx->w))
        goto end;

    if (ctx->revocation
            && (!paea_buf_point(ctx, b, ctx->acc_w)
                || !paea_encode_crl_blob(ctx, b)))
        goto end;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL || i2d_PUBKEY_bio(mem, ctx->sig_key) != 1)
        goto end;
    derlen = BIO_get_mem_data(mem, &memdata);
    if (derlen <= 0 || !paea_buf_tlder(b, memdata, (size_t)derlen))
        goto end;

    ret = 1;

 end:
    OPENSSL_free(der);
    BIO_free(mem);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_PARAMS_BLOB);
    return ret;
}

int paea_decode_params_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                            size_t blob_len)
{
    PAEA_RDR r = { blob, blob_len, 0 };
    uint8_t ver, rev;
    size_t len, unused;
    const unsigned char *p, *tmp;
    EC_GROUP *group = NULL;
    char *digest_name = NULL, *sig_type = NULL, *sig_digest_name = NULL;
    EC_POINT *w = NULL, *accw = NULL;
    PAEA_CRL_ENTRY *crl_arr = NULL;
    size_t crl_n = 0;
    EVP_PKEY *pk = NULL;
    BIO *mem = NULL;
    int ret = 0;

    if (!paea_rdr_take_u8(&r, &ver) || ver != PAEA_BLOB_VERSION)
        goto err;
    if (!paea_rdr_take_tl(&r, &len, &p))
        goto err;
    tmp = p;
    group = d2i_ECPKParameters(NULL, &tmp, (long)len);
    if (group == NULL)
        goto err;

    digest_name = paea_take_tlname(&r);
    if (digest_name == NULL)
        goto err;
    sig_type = paea_take_tlname(&r);
    if (sig_type == NULL)
        goto err;
    if (OPENSSL_strcasecmp(sig_type, "SM2") != 0
            && OPENSSL_strcasecmp(sig_type, "EC") != 0
            && OPENSSL_strcasecmp(sig_type, "ECDSA") != 0) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_SIGNATURE_SCHEME);
        goto err;
    }
    sig_digest_name = paea_take_tlname(&r);
    if (sig_digest_name == NULL)
        goto err;

    if (!paea_rdr_take_u8(&r, &rev))
        goto err;

    w = EC_POINT_new(group);
    if (w == NULL || !paea_rdr_take_point(group, &r, w, &unused))
        goto err;

    if (rev) {
        accw = EC_POINT_new(group);
        if (accw == NULL || !paea_rdr_take_point(group, &r, accw, &unused))
            goto err;
        if (!paea_parse_crl_content(group, &r, &crl_arr, &crl_n))
            goto err;
    }

    /* SPKI public key of the server signature scheme */
    if (!paea_rdr_take_tl(&r, &len, &p))
        goto err;
    mem = BIO_new_mem_buf(p, (int)len);
    if (mem == NULL)
        goto err;
    pk = d2i_PUBKEY_ex_bio(mem, NULL, ctx->libctx, ctx->propq);
    BIO_free(mem);
    mem = NULL;
    if (pk == NULL)
        goto err;

    if (r.remaining != 0)
        goto err;

    /* Everything parsed: install atomically.  paea_ctx_install_group()
     * drops every intermediate state of the previous group.  Users are
     * expected to import "params" before the "credential"; the server
     * is expected to import "servkey" right after. */
    if (!paea_ctx_install_group(ctx, group))
        goto err;
    group = NULL;                 /* ownership moved into the context */

    if (!paea_ctx_set_md_by_name(ctx, digest_name))
        goto err;

    OPENSSL_free(ctx->sig_type);
    ctx->sig_type = sig_type;
    sig_type = NULL;
    OPENSSL_free(ctx->sig_digest_name);
    ctx->sig_digest_name = sig_digest_name;
    sig_digest_name = NULL;
    ctx->revocation = rev != 0;

    ctx->w = w;
    w = NULL;
    ctx->acc_w = accw;
    accw = NULL;

    EVP_PKEY_free(ctx->sig_key);
    ctx->sig_key = pk;
    pk = NULL;

    if (ctx->revocation && !paea_install_crl(ctx, crl_arr, crl_n))
        goto err;
    crl_arr = NULL;               /* consumed by install_crl (or freed) */

    ctx->params_ready = 1;
    ctx->server_secret = 0;
    ret = 1;

 err:
    EC_GROUP_free(group);
    OPENSSL_free(digest_name);
    OPENSSL_free(sig_type);
    OPENSSL_free(sig_digest_name);
    EC_POINT_free(w);
    EC_POINT_free(accw);
    if (ret == 0)
        paea_free_crl_arr(crl_arr, crl_n);
    EVP_PKEY_free(pk);
    BIO_free(mem);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_PARAMS_BLOB);
    return ret;
}

/* ------------------------------------------------------------------ */
/* "servkey" blob                                                      */
/*                                                                     */
/*   u8  version                                                       */
/*   TL(r)                                                             */
/*   u8  revocation enabled                                            */
/*   [TL(chi)]                                                         */
/*   TL(PKCS#8 privateKeyInfo DER)                                     */
/* ------------------------------------------------------------------ */

int paea_encode_servkey_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *b)
{
    BIO *mem = NULL;
    unsigned char *memdata;
    long derlen;
    int ret = 0;

    if (!ctx->server_secret || ctx->r == NULL)
        goto end;
    if (ctx->revocation && ctx->acckey == NULL)
        goto end;
    if (ctx->sig_key == NULL)
        goto end;

    if (!paea_buf_u8(b, PAEA_BLOB_VERSION)
            || !paea_buf_int(ctx, b, ctx->r)
            || !paea_buf_u8(b, ctx->revocation != 0))
        goto end;
    if (ctx->revocation && !paea_buf_int(ctx, b, ctx->acckey))
        goto end;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL || i2d_PKCS8PrivateKeyInfo_bio(mem, ctx->sig_key) != 1)
        goto end;
    derlen = BIO_get_mem_data(mem, &memdata);
    if (derlen <= 0 || !paea_buf_tlder(b, memdata, (size_t)derlen))
        goto end;
    ret = 1;

 end:
    BIO_free(mem);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_SERVKEY_BLOB);
    return ret;
}

int paea_decode_servkey_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                             size_t blob_len)
{
    PAEA_RDR r = { blob, blob_len, 0 };
    uint8_t ver, rev;
    size_t unused;
    BIGNUM *r_bn = NULL, *chi_bn = NULL;
    EVP_PKEY *sk = NULL;
    BIO *mem = NULL;
    size_t len;
    const unsigned char *p;
    EC_POINT *chk = NULL;
    int ret = 0;

    if (ctx->group == NULL || !ctx->params_ready)
        goto err;

    r_bn = BN_new();
    if (r_bn == NULL)
        goto err;
    if (!paea_rdr_take_u8(&r, &ver) || ver != PAEA_BLOB_VERSION)
        goto err;
    if (!paea_rdr_take_int(&r, r_bn, &unused))
        goto err;
    if (BN_is_zero(r_bn) || BN_is_negative(r_bn)
            || BN_ucmp(r_bn, ctx->q) >= 0)
        goto err;
    if (!paea_rdr_take_u8(&r, &rev))
        goto err;

    if (rev) {
        chi_bn = BN_new();
        if (chi_bn == NULL || !paea_rdr_take_int(&r, chi_bn, &unused))
            goto err;
        if (BN_is_zero(chi_bn) || BN_is_negative(chi_bn)
                || BN_ucmp(chi_bn, ctx->q) >= 0)
            goto err;
    }
    if (rev != (ctx->revocation != 0))
        goto err;   /* revocation setting mismatch with params */

    if (!paea_rdr_take_tl(&r, &len, &p))
        goto err;
    mem = BIO_new_mem_buf(p, (int)len);
    if (mem == NULL)
        goto err;
    sk = d2i_PrivateKey_ex_bio(mem, NULL, ctx->libctx, ctx->propq);
    BIO_free(mem);
    mem = NULL;
    if (sk == NULL)
        goto err;

    if (r.remaining != 0)
        goto err;

    /* cross check with the imported public parameters: r must match w
     * and, with revocation, chi must match ACC(w) */
    chk = EC_POINT_new(ctx->group);
    if (chk == NULL
            || !paea_generator_mul(ctx, r_bn, chk)
            || EC_POINT_cmp(ctx->group, chk, ctx->w, NULL) != 0)
        goto err;
    if (rev) {
        if (!paea_generator_mul(ctx, chi_bn, chk)
                || EC_POINT_cmp(ctx->group, chk, ctx->acc_w, NULL) != 0)
            goto err;
    }

    /* install */
    BN_clear_free(ctx->r);
    ctx->r = r_bn;
    r_bn = NULL;
    BN_clear_free(ctx->acckey);
    ctx->acckey = chi_bn;
    chi_bn = NULL;
    EVP_PKEY_free(ctx->sig_key);
    ctx->sig_key = sk;
    sk = NULL;
    EVP_MD_free(ctx->sig_md);     /* re-bound on next use */
    ctx->sig_md = NULL;
    ctx->server_secret = 1;
    ret = 1;

 err:
    BN_clear_free(r_bn);
    BN_clear_free(chi_bn);
    EVP_PKEY_free(sk);
    BIO_free(mem);
    EC_POINT_free(chk);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_SERVKEY_BLOB);
    return ret;
}

/* ------------------------------------------------------------------ */
/* "credential" blob (user side, password wrapped credential)          */
/*                                                                     */
/*   u8  version                                                       */
/*   TL(uid)                                                           */
/*   TL(m)                                                             */
/*   TL(sigma_pw point)                                                */
/*   u8 has witness                                                    */
/*   [u32 witness_crl_index TL(W point)]                               */
/* ------------------------------------------------------------------ */

int paea_encode_credential_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *b)
{
    if (ctx->uid == NULL || ctx->m == NULL || ctx->sigma_pw == NULL)
        return 0;

    if (!paea_buf_u8(b, PAEA_BLOB_VERSION)
            || !paea_buf_u32(b, (uint32_t)ctx->uid_len)
            || !paea_buf_raw(b, ctx->uid, ctx->uid_len)
            || !paea_buf_int(ctx, b, ctx->m)
            || !paea_buf_point(ctx, b, ctx->sigma_pw))
        return 0;

    if (!paea_buf_u8(b, ctx->witness != NULL))
        return 0;
    if (ctx->witness != NULL) {
        if (!paea_buf_u32(b, ctx->witness_crl_index))
            return 0;
        if (!paea_buf_point(ctx, b, ctx->witness))
            return 0;
    }
    return 1;
}

int paea_decode_credential_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                                size_t blob_len)
{
    PAEA_RDR r = { blob, blob_len, 0 };
    uint8_t ver, has_witness;
    size_t len, unused;
    const unsigned char *p;
    unsigned char *uid = NULL;
    BIGNUM *m = NULL;
    EC_POINT *sigma_pw = NULL, *witness = NULL;
    uint32_t witness_idx = 0;
    int ret = 0;

    if (ctx->group == NULL)
        goto err;

    m = BN_new();
    sigma_pw = EC_POINT_new(ctx->group);
    if (m == NULL || sigma_pw == NULL)
        goto err;

    if (!paea_rdr_take_u8(&r, &ver) || ver != PAEA_BLOB_VERSION)
        goto err;
    if (!paea_rdr_take_tl(&r, &len, &p))
        goto err;
    if (len == 0 || len > 512)
        goto err;
    uid = OPENSSL_memdup(p, len);
    if (uid == NULL)
        goto err;
    if (!paea_rdr_take_int(&r, m, &unused))
        goto err;
    if (BN_is_zero(m) || BN_is_negative(m) || BN_ucmp(m, ctx->q) >= 0)
        goto err;
    if (!paea_rdr_take_point(ctx->group, &r, sigma_pw, &unused))
        goto err;
    if (EC_POINT_is_at_infinity(ctx->group, sigma_pw) == 1)
        goto err;

    if (!paea_rdr_take_u8(&r, &has_witness))
        goto err;
    if (has_witness != 0) {
        witness = EC_POINT_new(ctx->group);
        if (witness == NULL)
            goto err;
        if (!paea_rdr_take_u32(&r, &witness_idx)
                || !paea_rdr_take_point(ctx->group, &r, witness, &unused))
            goto err;
        if (EC_POINT_is_at_infinity(ctx->group, witness) == 1)
            goto err;
    }
    if (r.remaining != 0)
        goto err;

    /* install */
    paea_ctx_clear_credential(ctx);
    ctx->uid = uid;
    ctx->uid_len = len;
    ctx->m = m;
    ctx->sigma_pw = sigma_pw;
    ctx->witness = witness;
    ctx->witness_crl_index = witness_idx;
    ret = 1;

 err:
    if (ret == 0) {
        OPENSSL_free(uid);
        BN_free(m);
        EC_POINT_free(sigma_pw);
        EC_POINT_free(witness);
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CREDENTIAL_BLOB);
    }
    return ret;
}