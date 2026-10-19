/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include <openssl/err.h>
#include "paea_evp_local.h"

int ossl_paea_put(PAEA_BUF *b, const void *p, size_t len)
{
    unsigned char *q;
    size_t n;

    if (len > PAEA_MAX_BLOB_LEN - 4 || b->len > PAEA_MAX_BLOB_LEN - len - 4)
        return 0;
    n = b->len + 4 + len;
    if (n > b->cap) {
        q = OPENSSL_realloc(b->buf, n);
        if (q == NULL)
            return 0;
        b->buf = q;
        b->cap = n;
    }
    q = b->buf + b->len;
    q[0] = (unsigned char)(len >> 24); q[1] = (unsigned char)(len >> 16);
    q[2] = (unsigned char)(len >> 8); q[3] = (unsigned char)len;
    if (len != 0)
        memcpy(q + 4, p, len);
    b->len = n;
    return 1;
}

int ossl_paea_get(PAEA_READER *r, const unsigned char **p, size_t *len)
{
    return paea_get_bytes(&r->p, &r->len, p, len);
}

int ossl_paea_put_point(PAEA_BUF *b, const EC_GROUP *g, const EC_POINT *p)
{
    /* Implementation capacity: 1 + 2 * ceil(521 / 8), through P-521. */
    unsigned char buf[133];
    size_t n = EC_POINT_point2oct(g, p, POINT_CONVERSION_UNCOMPRESSED,
                                 buf, sizeof(buf), NULL);

    return n > 1 && ossl_paea_put(b, buf, n);
}

int ossl_paea_read_point(PAEA_READER *r, const EC_GROUP *g, EC_POINT *p)
{
    const unsigned char *in;
    size_t len;
    EC_POINT *check = NULL;
    int rc = 0;

    if (!ossl_paea_get(r, &in, &len) || len != paea_point_len(g)
        || in[0] != 4 || !EC_POINT_oct2point(g, p, in, len, NULL)
        || EC_POINT_is_at_infinity(g, p))
        goto done;
    check = EC_POINT_new(g);
    if (check != NULL
        && EC_POINT_mul(g, check, NULL, p, EC_GROUP_get0_order(g), NULL)
        && EC_POINT_is_at_infinity(g, check))
        rc = 1;
 done:
    EC_POINT_free(check);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
    return rc;
}

int ossl_paea_put_bn(PAEA_BUF *b, const BIGNUM *n, size_t width)
{
    unsigned char buf[384];
    int rc;

    rc = width <= sizeof(buf) && !BN_is_negative(n)
        && BN_bn2binpad(n, buf, (int)width) == (int)width
        && ossl_paea_put(b, buf, width);
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

int ossl_paea_read_bn(PAEA_READER *r, BIGNUM *n, size_t width)
{
    const unsigned char *p;
    size_t len;

    return ossl_paea_get(r, &p, &len) && len == width
        && BN_bin2bn(p, (int)len, n) != NULL;
}

int ossl_paea_key(EVP_PAEA_CTX *ctx, unsigned char *key, size_t len)
{
    int rc = 0;

    if (len != 0 && len <= sizeof(ctx->key)) {
        memcpy(ctx->key, key, len);
        ctx->keylen = len;
        ctx->stage = 2;
        rc = 1;
    }
    OPENSSL_clear_free(key, len);
    return rc;
}
