/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

YZW *ossl_yzw_new(EVP_PAEA_CTX *ctx)
{
    YZW *z = OPENSSL_zalloc(sizeof(*z));
    int i;

    if (z == NULL)
        return NULL;
    ctx->data = z;
    z->group = PAIRING_GROUP_new_sm9();
    z->md = EVP_MD_fetch(ctx->libctx, "SM3", ctx->propq);
    z->he = ossl_paea_he_new();
    z->h = PAIRING_G2_new(); z->w = PAIRING_G2_new(); z->wa = PAIRING_G2_new();
    if (z->group == NULL || z->md == NULL || z->he == NULL
        || z->h == NULL || z->w == NULL || z->wa == NULL)
        return NULL;
    for (i = 0; i < YZ_BASES; i++)
        if ((z->base[i] = EC_POINT_new(z->group)) == NULL)
            return NULL;
    for (i = 0; i < YZ_CACHE; i++)
        if ((z->cache[i] = PAIRING_GT_new()) == NULL)
            return NULL;
    z->acc = EC_POINT_new(z->group);
    return z->acc != NULL ? z : NULL;
}

int ossl_yzw_cache(YZW *z)
{
    return PAIRING_apply(z->cache[YZ_EA], z->base[YZ_A], z->h)
        && PAIRING_apply(z->cache[YZ_ED], z->base[YZ_D], z->h)
        && PAIRING_apply(z->cache[YZ_EG0W], z->base[YZ_G0], z->w)
        && PAIRING_apply(z->cache[YZ_EG0H], z->base[YZ_G0], z->h)
        && PAIRING_apply(z->cache[YZ_EB], z->base[YZ_B], z->h)
        && PAIRING_apply(z->cache[YZ_EG0WA], z->base[YZ_G0], z->wa);
}

void ossl_yzw_reset(EVP_PAEA_CTX *ctx)
{
    YZW *z = ctx->data;
    YZ_SESSION *s = z->session;
    int i;

    if (s == NULL)
        return;
    for (i = 0; i < YZ_SECRETS; i++) {
        BN_clear_free(s->v[i]); BN_clear_free(s->mask[i]);
    }
    BN_clear_free(s->ephemeral); BN_clear_free(s->ns);
    EC_POINT_free(s->X); EC_POINT_free(s->Y);
    EC_POINT_free(s->T1); EC_POINT_free(s->T2); EC_POINT_free(s->R2);
    EC_POINT_free(s->T1r); EC_POINT_free(s->T2r); EC_POINT_free(s->R2r);
    PAIRING_GT_free(s->R1); PAIRING_GT_free(s->R1r); PAIRING_GT_free(s->be);
    OPENSSL_clear_free(s, sizeof(*s)); z->session = NULL;
}

void ossl_yzw_free(EVP_PAEA_CTX *ctx)
{
    YZW *z = ctx->data;
    size_t i;

    if (z == NULL)
        return;
    ossl_yzw_reset(ctx);
    for (i = 0; i < YZ_BASES; i++) EC_POINT_free(z->base[i]);
    for (i = 0; i < YZ_CACHE; i++) PAIRING_GT_free(z->cache[i]);
    for (i = 0; i < z->nusers; i++) BN_clear_free(z->users[i].k);
    for (i = 0; i < z->nevents; i++) {
        BN_free(z->events[i].k); EC_POINT_free(z->events[i].acc);
    }
    OPENSSL_free(z->users); OPENSSL_free(z->events);
    PAIRING_G2_free(z->h); PAIRING_G2_free(z->w); PAIRING_G2_free(z->wa);
    EC_POINT_free(z->acc); EC_POINT_clear_free(z->credential); EC_POINT_free(z->witness);
    BN_clear_free(z->k); BN_clear_free(z->x); BN_clear_free(z->chi);
    ossl_paea_he_free(z->he); EVP_MD_free(z->md); EC_GROUP_free(z->group);
    OPENSSL_clear_free(z, sizeof(*z)); ctx->data = NULL;
}

YZ_SESSION *ossl_yzw_session_new(YZW *z)
{
    YZ_SESSION *s = OPENSSL_zalloc(sizeof(*s));
    int i;

    if (s == NULL)
        return NULL;
    z->session = s;
    for (i = 0; i < YZ_SECRETS; i++) {
        s->v[i] = BN_secure_new(); s->mask[i] = BN_secure_new();
        if (s->v[i] == NULL || s->mask[i] == NULL)
            return NULL;
    }
    s->ephemeral = BN_secure_new(); s->ns = BN_new();
    s->X = EC_POINT_new(z->group); s->Y = EC_POINT_new(z->group);
    s->T1 = EC_POINT_new(z->group); s->T2 = EC_POINT_new(z->group);
    s->R2 = EC_POINT_new(z->group); s->T1r = EC_POINT_new(z->group);
    s->T2r = EC_POINT_new(z->group); s->R2r = EC_POINT_new(z->group);
    s->R1 = PAIRING_GT_new(); s->R1r = PAIRING_GT_new(); s->be = PAIRING_GT_new();
    if (s->ephemeral == NULL || s->ns == NULL || s->X == NULL || s->Y == NULL
        || s->T1 == NULL || s->T2 == NULL || s->R2 == NULL || s->T1r == NULL
        || s->T2r == NULL || s->R2r == NULL || s->R1 == NULL || s->R1r == NULL || s->be == NULL)
        return NULL;
    return s;
}

int ossl_yzw_setup(EVP_PAEA_CTX *ctx)
{
    YZW *z;
    BIGNUM *r = BN_secure_new();
    int i, rc = 0;

    if (OPENSSL_strcasecmp(ctx->group, "SM9-BN256") != 0
        || OPENSSL_strcasecmp(ctx->digest, "SM3") != 0) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_UNSUPPORTED);
        goto done;
    }
    z = ossl_yzw_new(ctx);
    if (z == NULL || r == NULL)
        goto done;
    z->x = BN_secure_new(); z->chi = BN_secure_new();
    if (z->x == NULL || z->chi == NULL)
        goto done;
    for (i = 0; i < YZ_BASES; i++) {
        if (!paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), r)
            || !EC_POINT_mul(z->group, z->base[i], r, NULL, NULL, NULL))
            goto done;
    }
    if (!paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), r)
        || !PAIRING_G2_generator(z->h) || !PAIRING_G2_mul(z->h, z->h, r)
        || !paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), z->x)
        || !paea_rand_in_zq_star(EC_GROUP_get0_order(z->group), z->chi)
        || !PAIRING_G2_mul(z->w, z->h, z->x)
        || !PAIRING_G2_mul(z->wa, z->h, z->chi)
        || !EC_POINT_copy(z->acc, z->base[YZ_ACC_BASE])
        || !ossl_paea_he_generate(z->he) || !ossl_yzw_cache(z))
        goto done;
    rc = 1;
 done:
    BN_clear_free(r);
    return rc;
}

int ossl_yzw_crypt(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                    const unsigned char iv[16], const unsigned char in[64], unsigned char out[64])
{
    YZW *z = ctx->data;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx->libctx, "SM4-CTR", ctx->propq);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char key[32];
    unsigned int keylen;
    int n, m, rc = 0;

    if (cipher == NULL || c == NULL || !EVP_Digest(pw, pwlen, key, &keylen, z->md, NULL)
        || !EVP_EncryptInit_ex2(c, cipher, key, iv, NULL)
        || !EVP_EncryptUpdate(c, out, &n, in, 64)
        || !EVP_EncryptFinal_ex(c, out + n, &m) || n + m != 64)
        goto done;
    rc = 1;
 done:
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(c); EVP_CIPHER_free(cipher);
    return rc;
}

const PAEA_METHOD ossl_paea_yzw_method = {
    "YZW", ossl_yzw_free, ossl_yzw_setup, ossl_yzw_export, ossl_yzw_import,
    ossl_yzw_issue, ossl_yzw_store, ossl_yzw_revoke, ossl_yzw_refresh,
    ossl_yzw_init, ossl_yzw_step, ossl_yzw_reset,
    ossl_yzw_export_credential, ossl_yzw_import_credential
};
