/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

/* The same equation constructs R1 from masks and checks it from responses.
 * 7.2.5's r_xi on e(g0,Wacc) is corrected to r_zeta: the verification
 * equation uses s_zeta and eta=zeta*k. See the implementation issue log. */
int ossl_yzw_equation(YZW *z, int rev, BIGNUM *const v[], PAIRING_GT *out)
{
    YZ_SESSION *s = z->session;
    BN_CTX *bn = BN_CTX_new();
    BIGNUM *neg;
    PAIRING_GT *t = PAIRING_GT_new(), *base = PAIRING_GT_new();
    int rc = 0;

    if (bn == NULL || t == NULL || base == NULL)
        goto done;
    BN_CTX_start(bn);
    neg = BN_CTX_get(bn);
    if (neg == NULL || !BN_mod_sub(neg, EC_GROUP_get0_order(z->group), v[YZ_K],
                                   EC_GROUP_get0_order(z->group), bn)
        || !PAIRING_apply(base, rev ? s->T1r : s->T1, z->h)
        || !PAIRING_GT_pow(out, base, neg))
        goto end;
    if (rev) {
        if (!PAIRING_GT_pow(t, z->cache[YZ_EG0WA], v[YZ_ZETA]) || !PAIRING_GT_mul(out, out, t)
            || !PAIRING_GT_pow(t, z->cache[YZ_EG0H], v[YZ_ETA]) || !PAIRING_GT_mul(out, out, t))
            goto end;
    } else {
        if (!PAIRING_GT_pow(t, z->cache[YZ_EA], v[YZ_M]) || !PAIRING_GT_mul(out, out, t)
            || !PAIRING_GT_pow(t, s->be, v[YZ_GAMMA]) || !PAIRING_GT_mul(out, out, t)
            || !PAIRING_GT_pow(t, z->cache[YZ_EG0W], v[YZ_ALPHA]) || !PAIRING_GT_mul(out, out, t)
            || !PAIRING_GT_pow(t, z->cache[YZ_EG0H], v[YZ_BETA]) || !PAIRING_GT_mul(out, out, t))
            goto end;
    }
    rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    BN_CTX_free(bn); PAIRING_GT_free(t); PAIRING_GT_free(base);
    return rc;
}

int ossl_yzw_linear(YZW *z, EC_POINT *out, const EC_POINT *a, const BIGNUM *x,
                     const EC_POINT *b, const BIGNUM *y)
{
    EC_POINT *t = EC_POINT_new(z->group);
    int rc = t != NULL && EC_POINT_mul(z->group, t, NULL, b, y, NULL)
        && EC_POINT_mul(z->group, out, NULL, a, x, NULL)
        && EC_POINT_add(z->group, out, out, t, NULL);

    EC_POINT_free(t);
    return rc;
}

int ossl_yzw_mac(EVP_PAEA_CTX *ctx, unsigned char out[32])
{
    YZW *z = ctx->data;
    YZ_SESSION *s = z->session;
    unsigned char buf[2048];
    size_t n = 0, len = 0;

    if (BN_bn2binpad(s->ns, buf, 32) != 32)
        return 0;
    n += 32;
#define POINT(p) do { if (paea_put_point(z->group, buf + n, (p)) != 65) return 0; n += 65; } while (0)
#define TARGET(t) do { if (!PAIRING_GT_to_bytes((t), buf + n)) return 0; n += 384; } while (0)
    POINT(s->Y); POINT(s->X); POINT(s->T1); POINT(s->T2); TARGET(s->R1); POINT(s->R2);
    /* Bind the additional revocation commitments to the authenticated challenge. */
    if (ctx->revocation) {
        POINT(s->T1r); POINT(s->T2r); TARGET(s->R1r); POINT(s->R2r);
    }
#undef POINT
#undef TARGET
    return EVP_Q_mac(ctx->libctx, "HMAC", ctx->propq, "SM3", NULL,
                     s->nu, sizeof(s->nu), buf, n, out, 32, &len) != NULL && len == 32;
}

int ossl_yzw_session_key(EVP_PAEA_CTX *ctx)
{
    YZW *z = ctx->data;
    YZ_SESSION *s = z->session;
    EC_POINT *dh = EC_POINT_new(z->group);
    unsigned char buf[64 + 32 + 3*65];
    unsigned int n;
    int rc = 0;

    memcpy(buf, s->nu, 64);
    if (dh == NULL || BN_bn2binpad(s->ns, buf + 64, 32) != 32
        || paea_put_point(z->group, buf + 96, s->X) != 65
        || paea_put_point(z->group, buf + 161, s->Y) != 65
        || !EC_POINT_mul(z->group, dh, NULL, ctx->server ? s->X : s->Y, s->ephemeral, NULL)
        || paea_put_point(z->group, buf + 226, dh) != 65
        || !EVP_Digest(buf, sizeof(buf), ctx->key, &n, z->md, NULL))
        goto done;
    ctx->keylen = n; ctx->stage = 2; rc = 1;
 done:
    OPENSSL_cleanse(buf, sizeof(buf)); EC_POINT_clear_free(dh);
    return rc;
}
