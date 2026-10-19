/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License"). See LICENSE.txt.
 */
#include <openssl/pairing.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "sm9_local.h"

struct pairing_g2_st { OSSL_SM9_Z256_TWIST_POINT p; };
struct pairing_gt_st { ossl_sm9_z256_fp12_t a; };

static int scalar(ossl_sm9_z256_t out, const BIGNUM *k)
{
    unsigned char buf[32];

    if (BN_is_negative(k) || BN_bn2binpad(k, buf, sizeof(buf)) != sizeof(buf))
        goto err;
    ossl_sm9_z256_from_bytes(out, buf);
    OPENSSL_cleanse(buf, sizeof(buf));
    if (ossl_sm9_z256_cmp(out, ossl_sm9_z256_order()) < 0)
        return 1;
 err:
    OPENSSL_cleanse(buf, sizeof(buf));
    OPENSSL_cleanse(out, sizeof(ossl_sm9_z256_t));
    ERR_raise(ERR_LIB_EC, ERR_R_PASSED_INVALID_ARGUMENT);
    return 0;
}

EC_GROUP *PAIRING_GROUP_new_sm9(void)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p, *a, *b, *n, *x, *y;
    EC_GROUP *group = NULL;
    EC_POINT *g = NULL;
    int rc = 0;

    if (ctx == NULL)
        return NULL;
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx); a = BN_CTX_get(ctx); b = BN_CTX_get(ctx);
    n = BN_CTX_get(ctx); x = BN_CTX_get(ctx); y = BN_CTX_get(ctx);
    if (y == NULL
        || !BN_hex2bn(&p, "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D")
        || !BN_hex2bn(&n, "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25")
        || !BN_hex2bn(&x, "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD")
        || !BN_hex2bn(&y, "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616")
        || !BN_set_word(b, 5))
        goto done;
    group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    if (group == NULL || (g = EC_POINT_new(group)) == NULL
        || !EC_POINT_set_affine_coordinates(group, g, x, y, ctx)
        || !EC_GROUP_set_generator(group, g, n, BN_value_one()))
        goto done;
    rc = 1;
 done:
    EC_POINT_free(g);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (!rc) {
        EC_GROUP_free(group);
        group = NULL;
    }
    return group;
}

PAIRING_G2 *PAIRING_G2_new(void)
{
    PAIRING_G2 *p = OPENSSL_zalloc(sizeof(*p));

    if (p != NULL)
        ossl_sm9_z256_twist_point_set_infinity(&p->p);
    return p;
}

void PAIRING_G2_free(PAIRING_G2 *p)
{
    OPENSSL_clear_free(p, sizeof(*p));
}

int PAIRING_G2_generator(PAIRING_G2 *p)
{
    p->p = *ossl_sm9_z256_twist_generator();
    return 1;
}

int PAIRING_G2_mul(PAIRING_G2 *r, const PAIRING_G2 *p, const BIGNUM *k)
{
    ossl_sm9_z256_t t;

    if (!scalar(t, k))
        return 0;
    ossl_sm9_z256_twist_point_mul(&r->p, t, &p->p);
    OPENSSL_cleanse(t, sizeof(t));
    return 1;
}

int PAIRING_G2_to_bytes(const PAIRING_G2 *p, unsigned char out[129])
{
    if (ossl_sm9_z256_twist_point_is_at_infinity(&p->p)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        return 0;
    }
    return ossl_sm9_z256_twist_point_to_uncompressed_octets(&p->p, out) == 1;
}

int PAIRING_G2_from_bytes(PAIRING_G2 *p, const unsigned char *in, size_t len)
{
    OSSL_SM9_Z256_TWIST_POINT t, check;

    if (len != 129
        || ossl_sm9_z256_twist_point_from_uncompressed_octets(&t, in) != 1
        || ossl_sm9_z256_twist_point_is_at_infinity(&t))
        goto err;
    ossl_sm9_z256_twist_point_mul(&check, ossl_sm9_z256_order(), &t);
    if (!ossl_sm9_z256_twist_point_is_at_infinity(&check))
        goto err;
    p->p = t;
    return 1;
 err:
    ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
    return 0;
}

PAIRING_GT *PAIRING_GT_new(void)
{
    PAIRING_GT *r = OPENSSL_zalloc(sizeof(*r));

    if (r != NULL)
        ossl_sm9_z256_fp12_set_one(r->a);
    return r;
}

void PAIRING_GT_free(PAIRING_GT *a)
{
    OPENSSL_clear_free(a, sizeof(*a));
}

int PAIRING_apply(PAIRING_GT *r, const EC_POINT *p, const PAIRING_G2 *q)
{
    EC_GROUP *group = PAIRING_GROUP_new_sm9();
    OSSL_SM9_Z256_POINT t;
    unsigned char buf[65];
    int rc = 0;

    if (group == NULL)
        return 0;
    if (EC_POINT_is_at_infinity(group, p)
        || ossl_sm9_z256_twist_point_is_at_infinity(&q->p)) {
        ossl_sm9_z256_fp12_set_one(r->a);
        rc = 1;
        goto done;
    }
    if (EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED,
                          buf, sizeof(buf), NULL) != sizeof(buf)
        || ossl_sm9_z256_point_from_uncompressed_octets(&t, buf) != 1)
        goto done;
    ossl_sm9_z256_pairing(r->a, &q->p, &t);
    rc = 1;
 done:
    EC_GROUP_free(group);
    return rc;
}

int PAIRING_GT_mul(PAIRING_GT *r, const PAIRING_GT *a, const PAIRING_GT *b)
{
    ossl_sm9_z256_fp12_mul(r->a, a->a, b->a);
    return 1;
}

int PAIRING_GT_inv(PAIRING_GT *r, const PAIRING_GT *a)
{
    ossl_sm9_z256_fp12_inv(r->a, a->a);
    return 1;
}

int PAIRING_GT_pow(PAIRING_GT *r, const PAIRING_GT *a, const BIGNUM *k)
{
    ossl_sm9_z256_t t;

    if (!scalar(t, k))
        return 0;
    ossl_sm9_z256_fp12_pow(r->a, a->a, t);
    OPENSSL_cleanse(t, sizeof(t));
    return 1;
}

int PAIRING_GT_cmp(const PAIRING_GT *a, const PAIRING_GT *b)
{
    return !ossl_sm9_z256_fp12_equ(a->a, b->a);
}

int PAIRING_GT_to_bytes(const PAIRING_GT *a, unsigned char out[384])
{
    ossl_sm9_z256_fp12_to_bytes(a->a, out);
    return 1;
}

int PAIRING_GT_from_bytes(PAIRING_GT *a, const unsigned char *in, size_t len)
{
    ossl_sm9_z256_fp12_t t, check, one;

    if (len != 384 || ossl_sm9_z256_fp12_from_bytes(t, in) != 1)
        goto err;
    ossl_sm9_z256_fp12_set_one(one);
    ossl_sm9_z256_fp12_pow(check, t, ossl_sm9_z256_order());
    if (!ossl_sm9_z256_fp12_equ(check, one))
        goto err;
    ossl_sm9_z256_fp12_copy(a->a, t);
    return 1;
 err:
    ERR_raise(ERR_LIB_EC, ERR_R_PASSED_INVALID_ARGUMENT);
    return 0;
}
