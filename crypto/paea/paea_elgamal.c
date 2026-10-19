/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include <openssl/err.h>
#include <openssl/paeaerr.h>
#include <openssl/crypto.h>
#include "paea_local.h"
#include "paea_elgamal.h"

PAEA_HE_KEY *ossl_paea_he_new(void)
{
    PAEA_HE_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    key->p = BN_get_rfc3526_prime_3072(NULL);
    key->order = key->p != NULL ? BN_dup(key->p) : NULL;
    key->pub = BN_new();
    if (key->p == NULL || key->order == NULL || key->pub == NULL
        || !BN_rshift1(key->order, key->order)) {
        ossl_paea_he_free(key);
        return NULL;
    }
    return key;
}

void ossl_paea_he_free(PAEA_HE_KEY *key)
{
    if (key == NULL)
        return;
    BN_free(key->p);
    BN_free(key->order);
    BN_free(key->pub);
    BN_clear_free(key->priv);
    OPENSSL_free(key);
}

int ossl_paea_he_generate(PAEA_HE_KEY *key)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *g;
    int rc = 0;

    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);
    g = BN_CTX_get(ctx);
    if (key->priv == NULL)
        key->priv = BN_secure_new();
    if (g == NULL || key->priv == NULL || !BN_set_word(g, 4)
        || !paea_rand_in_zq_star(key->order, key->priv)
        || !BN_mod_exp_mont_consttime(key->pub, g, key->priv, key->p, ctx, NULL))
        goto done;
    rc = 1;
 done:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}

/* c1 and public keys must be nonidentity members of the order-(P-1)/2
 * subgroup; c2 is a general nonzero field element, as required by the draft. */
static int check(const PAEA_HE_KEY *key, const BIGNUM *a, int subgroup,
                 BN_CTX *ctx)
{
    BIGNUM *t;
    int rc = 0;

    if (BN_is_zero(a) || BN_is_negative(a) || BN_cmp(a, key->p) >= 0)
        goto err;
    if (!subgroup)
        return 1;
    if (BN_is_one(a))
        goto err;
    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    if (t != NULL && BN_mod_exp(t, a, key->order, key->p, ctx)
        && BN_is_one(t))
        rc = 1;
    BN_CTX_end(ctx);
    if (rc)
        return 1;
 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return 0;
}

int ossl_paea_he_set_public(PAEA_HE_KEY *key, const unsigned char in[384])
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_bin2bn(in, 384, NULL);
    int rc = 0;

    if (ctx != NULL && p != NULL && check(key, p, 1, ctx)
        && BN_copy(key->pub, p) != NULL)
        rc = 1;
    BN_free(p);
    BN_CTX_free(ctx);
    return rc;
}

int ossl_paea_he_encrypt(const PAEA_HE_KEY *key, const BIGNUM *m,
                         unsigned char out[768])
{
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *r, *a, *b, *g;
    int rc = 0;

    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx); a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx); g = BN_CTX_get(ctx);
    if (g == NULL || !check(key, m, 0, ctx)
        || !paea_rand_in_zq_star(key->order, r) || !BN_set_word(g, 4)
        || !BN_mod_exp_mont_consttime(a, g, r, key->p, ctx, NULL)
        || !BN_mod_exp_mont_consttime(b, key->pub, r, key->p, ctx, NULL)
        || !BN_mod_mul(b, b, m, key->p, ctx)
        || BN_bn2binpad(a, out, 384) != 384
        || BN_bn2binpad(b, out + 384, 384) != 384)
        goto done;
    rc = 1;
 done:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}

int ossl_paea_he_decrypt(const PAEA_HE_KEY *key, const unsigned char in[768],
                         BIGNUM *m)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *a, *b, *t, *exp;
    int rc = 0;

    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx); b = BN_CTX_get(ctx);
    t = BN_CTX_get(ctx); exp = BN_CTX_get(ctx);
    if (exp == NULL || key->priv == NULL
        || BN_bin2bn(in, 384, a) == NULL
        || BN_bin2bn(in + 384, 384, b) == NULL
        || !check(key, a, 1, ctx) || !check(key, b, 0, ctx)
        || !BN_sub(exp, key->order, key->priv)
        || !BN_mod_exp_mont_consttime(t, a, exp, key->p, ctx, NULL)
        || !BN_mod_mul(m, b, t, key->p, ctx))
        goto done;
    rc = 1;
 done:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}

int ossl_paea_he_mul(const PAEA_HE_KEY *key, const unsigned char a[768],
                     const unsigned char b[768], unsigned char out[768])
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x, *y, *r;
    unsigned char buf[768];
    int i, rc = 0;

    if (ctx == NULL)
        return 0;
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx); y = BN_CTX_get(ctx); r = BN_CTX_get(ctx);
    if (r == NULL)
        goto done;
    for (i = 0; i < 2; i++) {
        if (BN_bin2bn(a + 384*i, 384, x) == NULL
            || BN_bin2bn(b + 384*i, 384, y) == NULL
            || !check(key, x, i == 0, ctx) || !check(key, y, i == 0, ctx)
            || !BN_mod_mul(r, x, y, key->p, ctx)
            || !check(key, r, i == 0, ctx)
            || BN_bn2binpad(r, buf + 384*i, 384) != 384)
            goto done;
    }
    memcpy(out, buf, sizeof(buf));
    rc = 1;
 done:
    OPENSSL_cleanse(buf, sizeof(buf));
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}
