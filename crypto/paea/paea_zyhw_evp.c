/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "internal/deprecated.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include "paea_evp_local.h"

typedef struct {
    EC_GROUP *group;
    EVP_MD *md, *sig_md;
    EVP_PKEY *sig_key;
    BIGNUM *r, *m, *y;
    EC_POINT *w, *acc, *credential, *witness, *y_pt;
    PAEA_CRL_ENTRY *crl;
    size_t crl_len, crl_alloc;
    uint32_t index;
    unsigned char *sigma;
    size_t sigma_len;
} ZH;

static void reset(EVP_PAEA_CTX *ctx)
{
    ZH *z = ctx->data;

    BN_clear_free(z->y); z->y = NULL;
    EC_POINT_free(z->y_pt); z->y_pt = NULL;
    OPENSSL_free(z->sigma); z->sigma = NULL; z->sigma_len = 0;
}

static void cleanup(EVP_PAEA_CTX *ctx)
{
    ZH *z = ctx->data;

    if (z == NULL)
        return;
    reset(ctx);
    EC_GROUP_free(z->group); EVP_MD_free(z->md); EVP_MD_free(z->sig_md);
    EVP_PKEY_free(z->sig_key); BN_clear_free(z->r); BN_clear_free(z->m);
    EC_POINT_free(z->w); EC_POINT_free(z->acc);
    EC_POINT_clear_free(z->credential); EC_POINT_clear_free(z->witness);
    paea_crl_entries_free(z->crl, z->crl_len);
    OPENSSL_clear_free(z, sizeof(*z)); ctx->data = NULL;
}

static int setup(EVP_PAEA_CTX *ctx)
{
    ZH *z = OPENSSL_zalloc(sizeof(*z));
    int nid;
    char *sig_name = NULL;
    int rc;

    if (z == NULL)
        return 0;
    ctx->data = z;
    nid = EC_curve_nist2nid(ctx->group);
    if (nid == NID_undef)
        nid = OBJ_txt2nid(ctx->group);
    z->group = EC_GROUP_new_by_curve_name_ex(ctx->libctx, ctx->propq, nid);
    z->md = EVP_MD_fetch(ctx->libctx, ctx->digest, ctx->propq);
    if (z->group == NULL || z->md == NULL
        || !paea_check_digest(z->group, z->md))
        return 0;
    rc = paea_zyhw_setup(z->group, nid == NID_sm2 ? "SM2" : "EC",
                         ctx->digest, NULL, ctx->libctx, ctx->propq,
                         ctx->revocation, &z->r, &z->w, &z->acc,
                         &z->sig_key, &sig_name);
    if (rc)
        z->sig_md = EVP_MD_fetch(ctx->libctx, sig_name, ctx->propq);
    OPENSSL_free(sig_name);
    return rc && z->sig_md != NULL;
}

static int export_public(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len)
{
    const ZH *z = ctx->data;
    PAEA_BUF b = {0};
    unsigned char *der = NULL, *crl = NULL, header[6] = {'Z','Y','H','W',1,0};
    size_t crllen = 0;
    int n, rc = 0;

    header[5] = ctx->revocation;
    if (!ossl_paea_put(&b, header, sizeof(header))
        || (n = i2d_ECPKParameters(z->group, &der)) <= 0
        || !ossl_paea_put(&b, der, n))
        goto done;
    OPENSSL_free(der); der = NULL;
    if (!ossl_paea_put(&b, EVP_MD_get0_name(z->md), strlen(EVP_MD_get0_name(z->md)))
        || !ossl_paea_put(&b, EVP_MD_get0_name(z->sig_md), strlen(EVP_MD_get0_name(z->sig_md)))
        || (n = i2d_PUBKEY(z->sig_key, &der)) <= 0
        || !ossl_paea_put(&b, der, n)
        || !ossl_paea_put_point(&b, z->group, z->w))
        goto done;
    if (ctx->revocation
        && (!ossl_paea_put_point(&b, z->group, z->acc)
            || !paea_encode_crl_blob(z->group, z->crl, z->crl_len, &crl, &crllen)
            || !ossl_paea_put(&b, crl, crllen)))
        goto done;
    *out = b.buf; *len = b.len; b.buf = NULL; rc = 1;
 done:
    OPENSSL_free(der); OPENSSL_free(crl); OPENSSL_free(b.buf);
    return rc;
}

static EVP_MD *read_md(EVP_PAEA_CTX *ctx, PAEA_READER *r)
{
    const unsigned char *p;
    size_t n;
    char name[80];

    if (!ossl_paea_get(r, &p, &n) || n == 0 || n >= sizeof(name)
        || memchr(p, 0, n) != NULL)
        return NULL;
    memcpy(name, p, n); name[n] = 0;
    return EVP_MD_fetch(ctx->libctx, name, ctx->propq);
}

static int import_public(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len)
{
    ZH *z = OPENSSL_zalloc(sizeof(*z));
    PAEA_READER r = {in, len};
    const unsigned char *p, *end;
    size_t n;

    if (z == NULL)
        return 0;
    ctx->data = z;
    if (!ossl_paea_get(&r, &p, &n) || n != 6 || memcmp(p, "ZYHW\1", 5)
        || p[5] > 1)
        goto err;
    ctx->revocation = p[5];
    if (!ossl_paea_get(&r, &p, &n))
        goto err;
    end = p + n;
    z->group = d2i_ECPKParameters(NULL, &p, (long)n);
    if (z->group == NULL || p != end || !paea_check_group(z->group)
        || (z->md = read_md(ctx, &r)) == NULL
        || (z->sig_md = read_md(ctx, &r)) == NULL
        || !ossl_paea_get(&r, &p, &n))
        goto err;
    end = p + n;
    z->sig_key = d2i_PUBKEY_ex(NULL, &p, (long)n, ctx->libctx, ctx->propq);
    z->w = EC_POINT_new(z->group);
    if (z->sig_key == NULL || p != end || z->w == NULL
        || !ossl_paea_read_point(&r, z->group, z->w))
        goto err;
    if (!paea_check_digest(z->group, z->md)
        || !paea_check_digest(z->group, z->sig_md)
        || (EVP_PKEY_is_a(z->sig_key, "SM2")
            && (!EVP_MD_is_a(z->md, "SM3") || !EVP_MD_is_a(z->sig_md, "SM3"))))
        goto err;
    if (ctx->revocation) {
        z->acc = EC_POINT_new(z->group);
        if (z->acc == NULL || !ossl_paea_read_point(&r, z->group, z->acc)
            || !ossl_paea_get(&r, &p, &n)
            || !paea_decode_crl_blob(z->group, p, n, &z->crl, &z->crl_len)
            || EC_POINT_cmp(z->group, z->acc, z->crl_len == 0
                            ? EC_GROUP_get0_generator(z->group)
                            : z->crl[z->crl_len - 1].b, NULL) != 0)
            goto err;
        z->crl_alloc = z->crl_len;
    }
    if (r.len == 0)
        return 1;
 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return 0;
}

static int issue(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                 unsigned char **out, size_t *len)
{
    ZH *z = ctx->data;

    return paea_zyhw_issue_credential(z->group, z->md, z->r, z->acc, z->crl_len,
                                     uid, uidlen, out, len);
}

static int store_credential(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                 const unsigned char *pw, size_t pwlen, const unsigned char *in, size_t len)
{
    ZH *z = ctx->data;
    BIGNUM *m = NULL;
    EC_POINT *cred = NULL, *wit = NULL;
    uint32_t idx;

    if (!paea_zyhw_wrap_credential(z->group, z->md, uid, uidlen, pw, pwlen,
                                   in, len, ctx->revocation, &m, &cred, &wit, &idx))
        return 0;
    if (ctx->revocation && idx > z->crl_len) {
        BN_clear_free(m); EC_POINT_clear_free(cred); EC_POINT_clear_free(wit);
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        return 0;
    }
    BN_clear_free(z->m); EC_POINT_clear_free(z->credential); EC_POINT_clear_free(z->witness);
    z->m = m; z->credential = cred; z->witness = wit; z->index = idx;
    return 1;
}

static int revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen)
{
    ZH *z = ctx->data;
    BIGNUM *m = BN_new();
    int rc = m != NULL && paea_m_of_uid(z->md, z->group, uid, uidlen, m)
        && paea_crl_revoke(z->group, z->r, &z->acc, &z->crl,
                           &z->crl_len, &z->crl_alloc, m);

    BN_free(m);
    return rc;
}

static int refresh(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *source)
{
    ZH *z = ctx->data, *s = source->data;
    EC_POINT *wit = NULL, *acc = NULL;
    PAEA_CRL_ENTRY *crl = NULL;
    unsigned char *blob = NULL;
    size_t crllen = 0, bloblen = 0, i;
    uint32_t index = z->index;
    int rc = 0;

    if (z->credential == NULL || z->crl_len > s->crl_len
        || EC_GROUP_cmp(z->group, s->group, NULL)
        || EC_POINT_cmp(z->group, z->w, s->w, NULL)
        || EVP_PKEY_eq(z->sig_key, s->sig_key) != 1
        || EVP_MD_get_type(z->md) != EVP_MD_get_type(s->md)
        || EVP_MD_get_type(z->sig_md) != EVP_MD_get_type(s->sig_md))
        goto done;
    for (i = 0; i < z->crl_len; i++)
        if (BN_cmp(z->crl[i].m, s->crl[i].m)
            || EC_POINT_cmp(z->group, z->crl[i].b, s->crl[i].b, NULL))
            goto done;
    if (!paea_encode_crl_blob(z->group, s->crl, s->crl_len, &blob, &bloblen)
        || !paea_decode_crl_blob(z->group, blob, bloblen, &crl, &crllen))
        goto done;
    wit = EC_POINT_dup(z->witness, z->group);
    acc = EC_POINT_dup(s->acc, z->group);
    if (wit == NULL || acc == NULL
        || !paea_zyhw_update_witness(z->group, z->m, wit, &index, s->crl, s->crl_len))
        goto done;
    EC_POINT_free(z->witness); z->witness = wit; wit = NULL;
    EC_POINT_free(z->acc); z->acc = acc; acc = NULL; z->index = index;
    paea_crl_entries_free(z->crl, z->crl_len);
    z->crl = crl; crl = NULL; z->crl_len = z->crl_alloc = crllen;
    rc = 1;
 done:
    EC_POINT_free(wit); EC_POINT_free(acc);
    OPENSSL_free(blob); paea_crl_entries_free(crl, crllen);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WITNESS_INVALID);
    return rc;
}

static int init(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                unsigned char **out, size_t *len)
{
    ZH *z = ctx->data;

    if (!ctx->server)
        return 0;
    if (!paea_zyhw_server_auth_init(z->group, z->sig_key, z->sig_md,
                                    out, len, &z->y, &z->y_pt, &z->sigma, &z->sigma_len))
        return 0;
    ctx->stage = 1;
    return 1;
}

static int step(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                const unsigned char *in, size_t inlen, unsigned char **out, size_t *len)
{
    ZH *z = ctx->data;
    unsigned char *key = NULL;
    size_t keylen = 0;
    int rc = 0;

    if (ctx->server && ctx->stage == 1)
        rc = paea_zyhw_server_verify(z->group, z->md, z->r, z->y, z->y_pt,
                                      z->sigma, z->sigma_len, z->acc, in, inlen,
                                      &key, &keylen);
    else if (!ctx->server && ctx->stage == 0 && z->credential != NULL)
        rc = paea_zyhw_user_prove(z->group, z->md, z->credential, z->m, z->sig_key,
                                  z->witness, z->acc, pw, pwlen, in, inlen,
                                  out, len, &key, &keylen);
    if (!rc) {
        OPENSSL_clear_free(key, keylen);
        return 0;
    }
    return ossl_paea_key(ctx, key, keylen);
}

static int export_credential(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len)
{
    ZH *z = ctx->data;
    PAEA_BUF b = {0};
    unsigned char hdr[4] = {'Z','C',1,0}, idx[4];
    int rc = 0;

    hdr[3] = ctx->revocation;
    if (z->credential == NULL || !ossl_paea_put(&b, hdr, 4)
        || !ossl_paea_put_bn(&b, z->m, BN_num_bytes(EC_GROUP_get0_order(z->group)))
        || !ossl_paea_put_point(&b, z->group, z->credential))
        goto done;
    idx[0] = z->index >> 24; idx[1] = z->index >> 16; idx[2] = z->index >> 8; idx[3] = z->index;
    if (ctx->revocation && (!ossl_paea_put_point(&b, z->group, z->witness)
                            || !ossl_paea_put(&b, idx, 4)))
        goto done;
    *out = b.buf; *len = b.len; b.buf = NULL; rc = 1;
 done:
    OPENSSL_clear_free(b.buf, b.cap);
    return rc;
}

static int import_credential(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len)
{
    ZH *z = ctx->data;
    PAEA_READER r = {in, len};
    const unsigned char *p;
    size_t n;
    BIGNUM *m = BN_new();
    EC_POINT *cred = EC_POINT_new(z->group), *wit = NULL;
    uint32_t idx = 0;
    int rc = 0;

    if (m == NULL || cred == NULL || !ossl_paea_get(&r, &p, &n)
        || n != 4 || memcmp(p, "ZC\1", 3) || p[3] != ctx->revocation
        || !ossl_paea_read_bn(&r, m, BN_num_bytes(EC_GROUP_get0_order(z->group)))
        || BN_cmp(m, EC_GROUP_get0_order(z->group)) >= 0
        || !ossl_paea_read_point(&r, z->group, cred))
        goto done;
    if (ctx->revocation) {
        wit = EC_POINT_new(z->group);
        if (wit == NULL || !ossl_paea_read_point(&r, z->group, wit)
            || !ossl_paea_get(&r, &p, &n) || n != 4)
            goto done;
        idx = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
        if (idx > z->crl_len)
            goto done;
    }
    if (r.len != 0)
        goto done;
    BN_clear_free(z->m); EC_POINT_clear_free(z->credential); EC_POINT_free(z->witness);
    z->m = m; m = NULL; z->credential = cred; cred = NULL;
    z->witness = wit; wit = NULL; z->index = idx; rc = 1;
 done:
    BN_clear_free(m); EC_POINT_free(cred); EC_POINT_free(wit);
    if (!rc) ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return rc;
}

const PAEA_METHOD ossl_paea_zyhw_method = {
    "ZYHW", cleanup, setup, export_public, import_public, issue, store_credential,
    revoke, refresh, init, step, reset, export_credential, import_credential
};
