/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

/* 7.2.4 step 2. Decrypt integer r*s under the larger ElGamal modulus,
 * then reduce only for exponentiation in the order-q pairing group. */
static int challenge(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t inlen,
                       unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    YZ_SESSION *s = ossl_yzw_session_new(z);
    BN_CTX *bn = BN_CTX_secure_new();
    BIGNUM *secret, *nonce, *limit;
    PAEA_READER rd = {in, inlen};
    PAEA_BUF msg = {0};
    const unsigned char *enc_s, *enc_nu;
    size_t n;
    unsigned char mac[32];
    int rc = 0;

    if (s == NULL || bn == NULL)
        goto done;
    BN_CTX_start(bn);
    secret = BN_CTX_get(bn); nonce = BN_CTX_get(bn); limit = BN_CTX_get(bn);
    if (limit == NULL || !ossl_paea_get(&rd, &enc_s, &n) || n != 768
        || !ossl_paea_read_point(&rd, z->group, s->X)
        || !ossl_paea_get(&rd, &enc_nu, &n) || n != 768
        || !ossl_paea_read_point(&rd, z->group, s->T1)
        || !ossl_paea_read_point(&rd, z->group, s->T2)
        || !ossl_yzw_read_gt(&rd, s->R1) || !ossl_paea_read_point(&rd, z->group, s->R2))
        goto end;
    if (ctx->revocation
        && (!ossl_paea_read_point(&rd, z->group, s->T1r)
            || !ossl_paea_read_point(&rd, z->group, s->T2r)
            || !ossl_yzw_read_gt(&rd, s->R1r)
            || !ossl_paea_read_point(&rd, z->group, s->R2r)))
        goto end;
    if (rd.len != 0 || !ossl_paea_he_decrypt(z->he, enc_s, secret)
        || !BN_sqr(limit, EC_GROUP_get0_order(z->group), bn)
        || BN_cmp(secret, limit) >= 0 || BN_is_zero(secret)
        || !BN_nnmod(secret, secret, EC_GROUP_get0_order(z->group), bn)
        || BN_is_zero(secret) || !PAIRING_GT_pow(s->be, z->cache[YZ_EB], secret)
        || !ossl_paea_he_decrypt(z->he, enc_nu, nonce)
        || BN_bn2binpad(nonce, s->nu, sizeof(s->nu)) != sizeof(s->nu)
        || !paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), s->ephemeral)
        || !paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), s->ns)
        || !EC_POINT_mul(z->group, s->Y, NULL, z->base[YZ_G], s->ephemeral, bn)
        || !ossl_yzw_mac(ctx, mac) || !ossl_paea_put_bn(&msg, s->ns, 32)
        || !ossl_paea_put_point(&msg, z->group, s->Y) || !ossl_paea_put(&msg, mac, 32))
        goto end;
    *out = msg.buf; *len = msg.len; msg.buf = NULL; ctx->stage = 1; rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    BN_CTX_free(bn); OPENSSL_free(msg.buf); OPENSSL_cleanse(mac, sizeof(mac));
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return rc;
}

static int verify_equation(YZW *z, int rev)
{
    YZ_SESSION *s = z->session;
    EC_POINT *left = EC_POINT_new(z->group), *right = EC_POINT_new(z->group);
    PAIRING_GT *l = PAIRING_GT_new(), *r = PAIRING_GT_new(), *div = PAIRING_GT_new();
    int rc = 0;
    int alpha = rev ? YZ_ZETA : YZ_ALPHA, mu = rev ? YZ_XI : YZ_MU;

    if (left == NULL || right == NULL || l == NULL || r == NULL || div == NULL
        || !ossl_yzw_linear(z, left, rev ? s->R2r : s->R2, BN_value_one(),
                            rev ? s->T2r : s->T2, s->ns)
        || !ossl_yzw_linear(z, right, z->base[YZ_G1], s->v[alpha], z->base[YZ_G0], s->v[mu])
        || EC_POINT_cmp(z->group, left, right, NULL) != 0
        || !PAIRING_apply(l, rev ? s->T1r : s->T1, rev ? z->wa : z->w)
        || !PAIRING_apply(div, rev ? z->acc : z->base[YZ_D], z->h)
        || !PAIRING_GT_inv(div, div) || !PAIRING_GT_mul(l, l, div)
        || !PAIRING_GT_pow(l, l, s->ns)
        || !PAIRING_GT_mul(l, l, rev ? s->R1r : s->R1)
        || !ossl_yzw_equation(z, rev, s->v, r) || PAIRING_GT_cmp(l, r) != 0)
        goto done;
    rc = 1;
 done:
    EC_POINT_free(left); EC_POINT_free(right);
    PAIRING_GT_free(l); PAIRING_GT_free(r); PAIRING_GT_free(div);
    return rc;
}

/* 7.2.4 step 4 and, when enabled, the linked 7.2.5 proof using the
 * identical k response in both equations. */
static int verify(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t inlen)
{
    YZW *z = ctx->data;
    YZ_SESSION *s = z->session;
    PAEA_READER rd = {in, inlen};
    int i;

    if (s == NULL)
        return 0;
    for (i = 0; i < (ctx->revocation ? 9 : 6); i++)
        if (!ossl_yzw_read_scalar(&rd, z, s->v[i], 0))
            goto err;
    if (rd.len != 0 || !verify_equation(z, 0)
        || (ctx->revocation && !verify_equation(z, 1))
        || !ossl_yzw_session_key(ctx))
        goto err;
    return 1;
 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_VERIFY_FAILED);
    return 0;
}

int ossl_yzw_step(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                   const unsigned char *in, size_t inlen, unsigned char **out, size_t *len)
{
    if (ctx->server && ctx->stage == 0)
        return challenge(ctx, in, inlen, out, len);
    if (ctx->server && ctx->stage == 1)
        return verify(ctx, in, inlen);
    if (!ctx->server && ctx->stage == 1)
        return ossl_yzw_client_step(ctx, in, inlen, out, len);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
    return 0;
}
