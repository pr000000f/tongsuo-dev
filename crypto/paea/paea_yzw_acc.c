/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "paea_yzw_local.h"

static int same_parameters(YZW *z, YZW *s)
{
    unsigned char a[129], b[129];
    PAIRING_G2 *za[3] = {z->h, z->w, z->wa}, *sa[3] = {s->h, s->w, s->wa};
    int i;

    if (BN_cmp(z->he->pub, s->he->pub))
        return 0;
    for (i = 0; i < YZ_BASES; i++)
        if (EC_POINT_cmp(z->group, z->base[i], s->base[i], NULL))
            return 0;
    for (i = 0; i < 3; i++)
        if (!PAIRING_G2_to_bytes(za[i], a) || !PAIRING_G2_to_bytes(sa[i], b)
            || CRYPTO_memcmp(a, b, sizeof(a)))
            return 0;
    return 1;
}

/* Nguyen membership accumulator: add t: wit' = old_acc + (t-k)*wit;
 * remove t: wit' = (wit-new_acc)/(t-k). Updates are transactional. */
int ossl_yzw_refresh(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *source)
{
    YZW *z = ctx->data, *s = source->data;
    BN_CTX *bn = BN_CTX_new();
    BIGNUM *delta;
    EC_POINT *wit = NULL, *tmp = NULL, *acc = NULL;
    YZ_EVENT *events = NULL;
    const EC_POINT *before;
    size_t i;
    int rc = 0;

    if (bn == NULL || z->credential == NULL || z->index > s->nevents
        || z->nevents > s->nevents
        || !same_parameters(z, s))
        goto done;
    for (i = 0; i < z->nevents; i++)
        if (z->events[i].add != s->events[i].add
            || BN_cmp(z->events[i].k, s->events[i].k)
            || EC_POINT_cmp(z->group, z->events[i].acc, s->events[i].acc, bn))
            goto done;
    if (s->nevents != 0) {
        events = OPENSSL_zalloc(s->nevents * sizeof(*events));
        if (events == NULL)
            goto done;
        for (i = 0; i < s->nevents; i++) {
            events[i].add = s->events[i].add;
            events[i].k = BN_dup(s->events[i].k);
            events[i].acc = EC_POINT_dup(s->events[i].acc, z->group);
            if (events[i].k == NULL || events[i].acc == NULL)
                goto done;
        }
    }
    wit = EC_POINT_dup(z->witness, z->group);
    tmp = EC_POINT_new(z->group); acc = EC_POINT_dup(s->acc, z->group);
    if (wit == NULL || tmp == NULL || acc == NULL)
        goto done;
    BN_CTX_start(bn);
    delta = BN_CTX_get(bn);
    if (delta == NULL)
        goto end;
    for (i = z->index; i < s->nevents; i++) {
        YZ_EVENT *ev = &s->events[i];

        if (!BN_mod_sub(delta, ev->k, z->k, EC_GROUP_get0_order(z->group), bn))
            goto end;
        if (!ev->add && BN_is_zero(delta)) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_USER_REVOKED);
            goto end;
        }
        if (ev->add) {
            before = i == 0 ? s->base[YZ_ACC_BASE] : s->events[i-1].acc;
            if (!EC_POINT_mul(z->group, tmp, NULL, wit, delta, bn)
                || !EC_POINT_add(z->group, wit, tmp, before, bn))
                goto end;
        } else {
            if (!EC_POINT_copy(tmp, ev->acc) || !EC_POINT_invert(z->group, tmp, bn)
                || !EC_POINT_add(z->group, wit, wit, tmp, bn)
                || BN_mod_inverse(delta, delta, EC_GROUP_get0_order(z->group), bn) == NULL
                || !EC_POINT_mul(z->group, wit, NULL, wit, delta, bn))
                goto end;
        }
    }
    EC_POINT_free(z->witness); z->witness = wit; wit = NULL;
    EC_POINT_free(z->acc); z->acc = acc; acc = NULL;
    for (i = 0; i < z->nevents; i++) {
        BN_free(z->events[i].k); EC_POINT_free(z->events[i].acc);
    }
    OPENSSL_free(z->events); z->events = events; events = NULL;
    z->nevents = s->nevents;
    z->index = (uint32_t)s->nevents; rc = 1;
 end:
    BN_CTX_end(bn);
 done:
    if (events != NULL) {
        for (i = 0; i < s->nevents; i++) {
            BN_free(events[i].k); EC_POINT_free(events[i].acc);
        }
        OPENSSL_free(events);
    }
    BN_CTX_free(bn); EC_POINT_free(wit); EC_POINT_free(tmp); EC_POINT_free(acc);
    if (!rc)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_WITNESS_INVALID);
    return rc;
}
