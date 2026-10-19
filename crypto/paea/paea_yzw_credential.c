/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

int ossl_yzw_export_credential(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    PAEA_BUF b = {0};
    unsigned char hdr[4] = {'Y','C',1,0}, idx[4];
    int rc = 0;

    hdr[3] = ctx->revocation;
    if (z->credential == NULL || !ossl_paea_put(&b, hdr, 4)
        || !ossl_paea_put_point(&b, z->group, z->credential)
        || !ossl_paea_put(&b, z->encrypted_m, 64) || !ossl_paea_put(&b, z->iv, 16)
        || !ossl_paea_put_bn(&b, z->k, 32) || !ossl_paea_put(&b, z->encrypted_s, 768))
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

int ossl_yzw_import_credential(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len)
{
    YZW *z = ctx->data;
    PAEA_READER r = {in, len};
    const unsigned char *p, *m, *iv, *ct;
    size_t n;
    BIGNUM *k = BN_new();
    EC_POINT *cred = EC_POINT_new(z->group), *wit = NULL;
    uint32_t idx = 0;
    int rc = 0;

    if (k == NULL || cred == NULL || !ossl_paea_get(&r, &p, &n)
        || n != 4 || memcmp(p, "YC\1", 3) || p[3] != ctx->revocation
        || !ossl_paea_read_point(&r, z->group, cred)
        || !ossl_paea_get(&r, &m, &n) || n != 64
        || !ossl_paea_get(&r, &iv, &n) || n != 16
        || !ossl_yzw_read_scalar(&r, z, k, 1)
        || !ossl_paea_get(&r, &ct, &n) || n != 768)
        goto done;
    if (ctx->revocation) {
        wit = EC_POINT_new(z->group);
        if (wit == NULL || !ossl_paea_read_point(&r, z->group, wit)
            || !ossl_paea_get(&r, &p, &n) || n != 4)
            goto done;
        idx = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
        if (idx > z->nevents)
            goto done;
    }
    if (r.len != 0)
        goto done;
    BN_clear_free(z->k); EC_POINT_clear_free(z->credential); EC_POINT_free(z->witness);
    z->k = k; k = NULL; z->credential = cred; cred = NULL;
    z->witness = wit; wit = NULL; z->index = idx;
    memcpy(z->encrypted_m, m, 64); memcpy(z->iv, iv, 16); memcpy(z->encrypted_s, ct, 768);
    rc = 1;
 done:
    BN_free(k); EC_POINT_free(cred); EC_POINT_free(wit);
    if (!rc) ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return rc;
}
