/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

/* 7.2.4 step 1. The denominator in Be is (e(a,h)^m * e(d,h)). */
int ossl_yzw_init(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                   unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    YZ_SESSION *s;
    BN_CTX *bn = BN_CTX_secure_new();
    BIGNUM *r, *nu;
    const BIGNUM *q = EC_GROUP_get0_order(z->group);
    PAIRING_GT *a = PAIRING_GT_new(), *b = PAIRING_GT_new();
    PAEA_BUF msg = {0};
    unsigned char mprime[64], enc_r[768], enc_s[768], enc_nu[768];
    int i, rc = 0;

    if (ctx->server || z->credential == NULL || bn == NULL || a == NULL || b == NULL)
        goto done;
    s = ossl_yzw_session_new(z);
    if (s == NULL)
        goto done;
    BN_CTX_start(bn);
    r = BN_CTX_get(bn); nu = BN_CTX_get(bn);
    if (nu == NULL || !ossl_yzw_crypt(ctx, pw, pwlen, z->iv, z->encrypted_m, mprime)
        || BN_bin2bn(mprime, 64, s->v[YZ_M]) == NULL
        || !BN_nnmod(s->v[YZ_M], s->v[YZ_M], q, bn)
        || BN_copy(s->v[YZ_K], z->k) == NULL
        || !paea_rand_in_zq_star(q, r)
        || BN_mod_inverse(s->v[YZ_GAMMA], r, q, bn) == NULL
        || !paea_rand_in_zq_star(q, s->ephemeral)
        || !EC_POINT_mul(z->group, s->X, NULL, z->base[YZ_G], s->ephemeral, bn)
        || !RAND_priv_bytes_ex(ctx->libctx, s->nu, sizeof(s->nu), 0)
        || BN_bin2bn(s->nu, sizeof(s->nu), nu) == NULL
        || !ossl_paea_he_encrypt(z->he, nu, enc_nu)
        || !ossl_paea_he_encrypt(z->he, r, enc_r)
        || !ossl_paea_he_mul(z->he, enc_r, z->encrypted_s, enc_s))
        goto end;
    for (i = 0; i < (ctx->revocation ? 9 : 6); i++)
        if (!paea_rand_in_zq_star(q, s->mask[i]))
            goto end;
    if (!paea_rand_in_zq_star(q, s->v[YZ_ALPHA])
        || !paea_rand_in_zq_star(q, s->v[YZ_MU])
        || !BN_mod_mul(s->v[YZ_BETA], s->v[YZ_ALPHA], s->v[YZ_K], q, bn)
        || !ossl_yzw_linear(z, s->T1, z->credential, BN_value_one(), z->base[YZ_G0], s->v[YZ_ALPHA])
        || !ossl_yzw_linear(z, s->T2, z->base[YZ_G1], s->v[YZ_ALPHA], z->base[YZ_G0], s->v[YZ_MU])
        || !ossl_yzw_linear(z, s->R2, z->base[YZ_G1], s->mask[YZ_ALPHA], z->base[YZ_G0], s->mask[YZ_MU])
        || !PAIRING_apply(a, z->credential, z->w)
        || !PAIRING_apply(b, z->credential, z->h)
        || !PAIRING_GT_pow(b, b, z->k) || !PAIRING_GT_mul(a, a, b)
        || !PAIRING_GT_pow(b, z->cache[YZ_EA], s->v[YZ_M])
        || !PAIRING_GT_mul(b, b, z->cache[YZ_ED])
        || !PAIRING_GT_inv(b, b) || !PAIRING_GT_mul(a, a, b)
        || !PAIRING_GT_pow(s->be, a, r)
        || !ossl_yzw_equation(z, 0, s->mask, s->R1))
        goto end;
    if (ctx->revocation
        && (!paea_rand_in_zq_star(q, s->v[YZ_ZETA])
            || !paea_rand_in_zq_star(q, s->v[YZ_XI])
            || !BN_mod_mul(s->v[YZ_ETA], s->v[YZ_ZETA], s->v[YZ_K], q, bn)
            || !ossl_yzw_linear(z, s->T1r, z->witness, BN_value_one(), z->base[YZ_G0], s->v[YZ_ZETA])
            || !ossl_yzw_linear(z, s->T2r, z->base[YZ_G1], s->v[YZ_ZETA], z->base[YZ_G0], s->v[YZ_XI])
            || !ossl_yzw_linear(z, s->R2r, z->base[YZ_G1], s->mask[YZ_ZETA], z->base[YZ_G0], s->mask[YZ_XI])
            || !ossl_yzw_equation(z, 1, s->mask, s->R1r)))
        goto end;
    if (!ossl_paea_put(&msg, enc_s, 768) || !ossl_paea_put_point(&msg, z->group, s->X)
        || !ossl_paea_put(&msg, enc_nu, 768)
        || !ossl_paea_put_point(&msg, z->group, s->T1)
        || !ossl_paea_put_point(&msg, z->group, s->T2)
        || !ossl_yzw_put_gt(&msg, s->R1) || !ossl_paea_put_point(&msg, z->group, s->R2))
        goto end;
    if (ctx->revocation
        && (!ossl_paea_put_point(&msg, z->group, s->T1r)
            || !ossl_paea_put_point(&msg, z->group, s->T2r)
            || !ossl_yzw_put_gt(&msg, s->R1r)
            || !ossl_paea_put_point(&msg, z->group, s->R2r)))
        goto end;
    *out = msg.buf; *len = msg.len; msg.buf = NULL; ctx->stage = 1; rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    BN_CTX_free(bn); PAIRING_GT_free(a); PAIRING_GT_free(b); OPENSSL_free(msg.buf);
    OPENSSL_cleanse(mprime, sizeof(mprime)); OPENSSL_cleanse(enc_r, sizeof(enc_r));
    OPENSSL_cleanse(enc_s, sizeof(enc_s)); OPENSSL_cleanse(enc_nu, sizeof(enc_nu));
    return rc;
}

/* 7.2.4 step 3. Verify the server MAC before releasing any response. */
int ossl_yzw_client_step(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t inlen,
                          unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    YZ_SESSION *s = z->session;
    BN_CTX *bn = BN_CTX_secure_new();
    BIGNUM *response;
    PAEA_READER rd = {in, inlen};
    PAEA_BUF msg = {0};
    const unsigned char *mac;
    unsigned char expected[32];
    size_t n;
    int i, rc = 0;

    if (bn == NULL || s == NULL || !ossl_yzw_read_scalar(&rd, z, s->ns, 1)
        || !ossl_paea_read_point(&rd, z->group, s->Y)
        || !ossl_paea_get(&rd, &mac, &n) || n != 32 || rd.len != 0
        || !ossl_yzw_mac(ctx, expected) || CRYPTO_memcmp(mac, expected, 32))
        goto done;
    BN_CTX_start(bn);
    response = BN_CTX_get(bn);
    if (response == NULL)
        goto end;
    for (i = 0; i < (ctx->revocation ? 9 : 6); i++) {
        if (!BN_mod_mul(response, s->ns, s->v[i], EC_GROUP_get0_order(z->group), bn)
            || !BN_mod_add(response, response, s->mask[i], EC_GROUP_get0_order(z->group), bn)
            || !ossl_paea_put_bn(&msg, response, 32))
            goto end;
    }
    if (!ossl_yzw_session_key(ctx))
        goto end;
    *out = msg.buf; *len = msg.len; msg.buf = NULL; rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    BN_CTX_free(bn); OPENSSL_free(msg.buf); OPENSSL_cleanse(expected, sizeof(expected));
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_VERIFY_FAILED);
    return rc;
}
