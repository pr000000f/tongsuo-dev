/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

static int uid_hash(YZW *z, const unsigned char *uid, size_t len, unsigned char out[32])
{
    unsigned int n;

    return EVP_Digest(uid, len, out, &n, z->md, NULL) && n == 32;
}

/* Reserve and construct first; publish only after all allocations succeed. */
static int event(YZW *z, int add, const BIGNUM *k, const EC_POINT *acc)
{
    YZ_EVENT *events, e = {0};

    if (z->nevents == YZ_MAX_EVENTS)
        return 0;
    e.add = add; e.k = BN_dup(k); e.acc = EC_POINT_dup(acc, z->group);
    if (e.k == NULL || e.acc == NULL)
        goto err;
    events = OPENSSL_realloc(z->events, (z->nevents + 1) * sizeof(*events));
    if (events == NULL)
        goto err;
    z->events = events;
    z->events[z->nevents++] = e;
    return 1;
 err:
    BN_free(e.k); EC_POINT_free(e.acc);
    return 0;
}

int ossl_yzw_issue(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                    unsigned char **out, size_t *len)
{
    YZW *z = ctx->data;
    BN_CTX *bn = BN_CTX_secure_new();
    const BIGNUM *q = EC_GROUP_get0_order(z->group);
    BIGNUM *k, *s, *m, *den, *inv, *accden;
    EC_POINT *M = EC_POINT_new(z->group), *t = EC_POINT_new(z->group);
    EC_POINT *acc = EC_POINT_new(z->group);
    unsigned char mprime[64], digest[32], index[4];
    PAEA_BUF b = {0};
    YZ_USER user = {0}, *users;
    size_t i;
    int rc = 0;

    if (bn == NULL || M == NULL || t == NULL || acc == NULL)
        goto done;
    BN_CTX_start(bn);
    k = BN_CTX_get(bn); s = BN_CTX_get(bn); m = BN_CTX_get(bn);
    den = BN_CTX_get(bn); inv = BN_CTX_get(bn); accden = BN_CTX_get(bn);
    if (accden == NULL || !uid_hash(z, uid, uidlen, digest))
        goto end;
    for (i = 0; i < z->nusers; i++)
        if (CRYPTO_memcmp(digest, z->users[i].uid, 32) == 0)
            goto end;
    do {
        if (!paea_rand_in_zq_star(q, k) || !BN_mod_add(den, k, z->x, q, bn)
            || !BN_mod_add(accden, k, z->chi, q, bn))
            goto end;
        for (i = 0; i < z->nusers; i++)
            if (BN_cmp(k, z->users[i].k) == 0)
                break;
    } while (BN_is_zero(den) || BN_is_zero(accden) || i != z->nusers);
    if (!paea_rand_in_zq_star(q, s) || !RAND_priv_bytes_ex(ctx->libctx, mprime, 64, 0)
        || BN_bin2bn(mprime, 64, m) == NULL || !BN_nnmod(m, m, q, bn)
        || BN_mod_inverse(inv, den, q, bn) == NULL
        || !EC_POINT_mul(z->group, M, NULL, z->base[YZ_A], m, bn)
        || !EC_POINT_mul(z->group, t, NULL, z->base[YZ_B], s, bn)
        || !EC_POINT_add(z->group, M, M, t, bn)
        || !EC_POINT_add(z->group, M, M, z->base[YZ_D], bn)
        || !EC_POINT_mul(z->group, M, NULL, M, inv, bn)
        || !ossl_paea_put_point(&b, z->group, M)
        || !ossl_paea_put(&b, mprime, 64) || !ossl_paea_put_bn(&b, k, 32)
        || !ossl_paea_put_bn(&b, s, 32))
        goto end;
    if (ctx->revocation) {
        size_t idx = z->nevents + 1;

        index[0] = idx >> 24; index[1] = idx >> 16; index[2] = idx >> 8; index[3] = idx;
        if (!EC_POINT_mul(z->group, acc, NULL, z->acc, accden, bn)
            || !ossl_paea_put_point(&b, z->group, z->acc)
            || !ossl_paea_put(&b, index, 4))
            goto end;
        user.k = BN_dup(k);
        if (user.k == NULL)
            goto end;
        users = OPENSSL_realloc(z->users, (z->nusers + 1) * sizeof(*users));
        if (users == NULL)
            goto end;
        z->users = users;
        if (!event(z, 1, k, acc))
            goto end;
        memcpy(user.uid, digest, 32); user.active = 1;
        z->users[z->nusers++] = user; user.k = NULL;
        EC_POINT_free(z->acc); z->acc = acc; acc = NULL;
    }
    *out = b.buf; *len = b.len; b.buf = NULL; rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    OPENSSL_cleanse(mprime, sizeof(mprime));
    OPENSSL_clear_free(b.buf, b.cap); BN_clear_free(user.k);
    BN_CTX_free(bn); EC_POINT_free(M); EC_POINT_free(t); EC_POINT_free(acc);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
    return rc;
}

int ossl_yzw_store(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                    const unsigned char *pw, size_t pwlen, const unsigned char *in, size_t len)
{
    YZW *z = ctx->data;
    PAEA_READER r = {in, len};
    EC_POINT *M = EC_POINT_new(z->group), *wit = EC_POINT_new(z->group);
    BIGNUM *k = BN_new(), *s = BN_secure_new();
    const unsigned char *mp, *p;
    size_t n;
    uint32_t index = 0;
    unsigned char iv[16], encrypted[64], ct[768];
    int rc = 0;

    if (M == NULL || wit == NULL || k == NULL || s == NULL
        || !ossl_paea_read_point(&r, z->group, M)
        || !ossl_paea_get(&r, &mp, &n) || n != 64
        || !ossl_yzw_read_scalar(&r, z, k, 1) || !ossl_yzw_read_scalar(&r, z, s, 1))
        goto done;
    if (ctx->revocation) {
        if (!ossl_paea_read_point(&r, z->group, wit)
            || !ossl_paea_get(&r, &p, &n) || n != 4)
            goto done;
        index = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
        if (index > z->nevents)
            goto done;
    }
    if (r.len != 0 || !RAND_bytes_ex(ctx->libctx, iv, 16, 0)
        || !ossl_yzw_crypt(ctx, pw, pwlen, iv, mp, encrypted)
        || !ossl_paea_he_encrypt(z->he, s, ct))
        goto done;
    EC_POINT_clear_free(z->credential); EC_POINT_free(z->witness); BN_free(z->k);
    z->credential = M; M = NULL; z->witness = wit; wit = NULL; z->k = k; k = NULL;
    z->index = index;
    memcpy(z->encrypted_m, encrypted, 64); memcpy(z->iv, iv, 16); memcpy(z->encrypted_s, ct, 768);
    rc = 1;
 done:
    OPENSSL_cleanse(encrypted, sizeof(encrypted)); OPENSSL_cleanse(ct, sizeof(ct));
    EC_POINT_free(M); EC_POINT_free(wit); BN_free(k); BN_clear_free(s);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
    return rc;
}

int ossl_yzw_revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen)
{
    YZW *z = ctx->data;
    BN_CTX *bn = BN_CTX_secure_new();
    BIGNUM *t;
    EC_POINT *acc = EC_POINT_new(z->group);
    unsigned char hash[32];
    size_t i;
    int rc = 0;

    if (bn == NULL || acc == NULL || !uid_hash(z, uid, uidlen, hash))
        goto done;
    for (i = 0; i < z->nusers; i++)
        if (CRYPTO_memcmp(hash, z->users[i].uid, 32) == 0)
            break;
    if (i == z->nusers || !z->users[i].active)
        goto done;
    BN_CTX_start(bn);
    t = BN_CTX_get(bn);
    if (t != NULL && BN_mod_add(t, z->chi, z->users[i].k, EC_GROUP_get0_order(z->group), bn)
        && BN_mod_inverse(t, t, EC_GROUP_get0_order(z->group), bn) != NULL
        && EC_POINT_mul(z->group, acc, NULL, z->acc, t, bn)
        && event(z, 0, z->users[i].k, acc)) {
        EC_POINT_free(z->acc); z->acc = acc; acc = NULL;
        z->users[i].active = 0; rc = 1;
    }
    BN_CTX_end(bn);
 done:
    BN_CTX_free(bn); EC_POINT_free(acc);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_UID_REJECTED);
    return rc;
}
