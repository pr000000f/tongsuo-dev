/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

int ossl_yzw_read_scalar(PAEA_READER *r, YZW *z, BIGNUM *n, int nonzero)
{
    return ossl_paea_read_bn(r, n, 32)
        && BN_cmp(n, EC_GROUP_get0_order(z->group)) < 0
        && (!nonzero || !BN_is_zero(n));
}

int ossl_yzw_put_gt(PAEA_BUF *b, const PAIRING_GT *a)
{
    unsigned char buf[384];

    return PAIRING_GT_to_bytes(a, buf) && ossl_paea_put(b, buf, sizeof(buf));
}

int ossl_yzw_read_gt(PAEA_READER *r, PAIRING_GT *a)
{
    const unsigned char *p;
    size_t n;

    return ossl_paea_get(r, &p, &n) && PAIRING_GT_from_bytes(a, p, n);
}

int ossl_yzw_put_g2(PAEA_BUF *b, const PAIRING_G2 *a)
{
    unsigned char buf[129];

    return PAIRING_G2_to_bytes(a, buf) && ossl_paea_put(b, buf, sizeof(buf));
}

int ossl_yzw_read_g2(PAEA_READER *r, PAIRING_G2 *a)
{
    const unsigned char *p;
    size_t n;

    return ossl_paea_get(r, &p, &n) && PAIRING_G2_from_bytes(a, p, n);
}

int ossl_yzw_export(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    PAEA_BUF b = {0};
    unsigned char hdr[5] = {'Y','Z','W',1,0}, count[4], op;
    size_t i;
    int rc = 0;

    hdr[4] = ctx->revocation;
    if (!ossl_paea_put(&b, hdr, sizeof(hdr)))
        goto done;
    for (i = 0; i < YZ_BASES; i++)
        if (!ossl_paea_put_point(&b, z->group, z->base[i]))
            goto done;
    if (!ossl_yzw_put_g2(&b, z->h) || !ossl_yzw_put_g2(&b, z->w)
        || !ossl_yzw_put_g2(&b, z->wa) || !ossl_paea_put_bn(&b, z->he->pub, 384)
        || !ossl_paea_put_point(&b, z->group, z->acc))
        goto done;
    count[0] = z->nevents >> 24; count[1] = z->nevents >> 16;
    count[2] = z->nevents >> 8; count[3] = z->nevents;
    if (!ossl_paea_put(&b, count, 4))
        goto done;
    for (i = 0; i < z->nevents; i++) {
        op = z->events[i].add;
        if (!ossl_paea_put(&b, &op, 1) || !ossl_paea_put_bn(&b, z->events[i].k, 32)
            || !ossl_paea_put_point(&b, z->group, z->events[i].acc))
            goto done;
    }
    *out = b.buf; *len = b.len; b.buf = NULL; rc = 1;
 done:
    OPENSSL_free(b.buf);
    return rc;
}

int ossl_yzw_import(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len)
{
    YZW *z = ossl_yzw_new(ctx);
    PAEA_READER r = {in, len};
    const unsigned char *p;
    size_t n, count, i;

    if (z == NULL || !ossl_paea_get(&r, &p, &n) || n != 5
        || memcmp(p, "YZW\1", 4) || p[4] > 1)
        goto err;
    ctx->revocation = p[4];
    for (i = 0; i < YZ_BASES; i++)
        if (!ossl_paea_read_point(&r, z->group, z->base[i]))
            goto err;
    if (!ossl_yzw_read_g2(&r, z->h) || !ossl_yzw_read_g2(&r, z->w)
        || !ossl_yzw_read_g2(&r, z->wa) || !ossl_paea_get(&r, &p, &n) || n != 384
        || !ossl_paea_he_set_public(z->he, p)
        || !ossl_paea_read_point(&r, z->group, z->acc)
        || !ossl_paea_get(&r, &p, &n) || n != 4)
        goto err;
    count = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
    if (count > YZ_MAX_EVENTS || (!ctx->revocation && count != 0))
        goto err;
    if (count != 0 && (z->events = OPENSSL_zalloc(count * sizeof(*z->events))) == NULL)
        goto err;
    for (i = 0; i < count; i++) {
        YZ_EVENT *ev = &z->events[i];

        z->nevents++;
        ev->k = BN_new(); ev->acc = EC_POINT_new(z->group);
        if (ev->k == NULL || ev->acc == NULL || !ossl_paea_get(&r, &p, &n)
            || n != 1 || p[0] > 1)
            goto err;
        ev->add = p[0];
        if (!ossl_yzw_read_scalar(&r, z, ev->k, 1)
            || !ossl_paea_read_point(&r, z->group, ev->acc))
            goto err;
    }
    if (r.len != 0 || EC_POINT_cmp(z->group, z->acc,
            count ? z->events[count-1].acc : z->base[YZ_ACC_BASE], NULL) != 0
        || !ossl_yzw_cache(z))
        goto err;
    return 1;
 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return 0;
}
