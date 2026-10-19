/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include <openssl/paea.h>
#include <openssl/err.h>
#include "../paea/paea_evp_local.h"

static int state_error(void)
{
    ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
    return 0;
}

EVP_PAEA_CTX *EVP_PAEA_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *mechanism,
                                 const char *propq)
{
    EVP_PAEA_CTX *ctx;
    const PAEA_METHOD *meth = NULL;

    ossl_err_load_PAEA_strings();
    if (OPENSSL_strcasecmp(mechanism, "ZYHW") == 0)
        meth = &ossl_paea_zyhw_method;
#ifndef OPENSSL_NO_PAIRING
    else if (OPENSSL_strcasecmp(mechanism, "YZW") == 0)
        meth = &ossl_paea_yzw_method;
#endif
    if (meth == NULL) {
        ERR_raise(ERR_LIB_PAEA, ERR_R_UNSUPPORTED);
        return NULL;
    }
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->meth = meth;
    ctx->libctx = libctx;
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    OPENSSL_strlcpy(ctx->group, meth == &ossl_paea_zyhw_method ? "SM2" : "SM9-BN256",
                    sizeof(ctx->group));
    OPENSSL_strlcpy(ctx->digest, "SM3", sizeof(ctx->digest));
    return ctx;
}

void EVP_PAEA_CTX_free(EVP_PAEA_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->data != NULL)
        ctx->meth->free(ctx);
    OPENSSL_free(ctx->propq);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

const char *EVP_PAEA_CTX_get0_name(const EVP_PAEA_CTX *ctx)
{
    return ctx->meth->name;
}

int EVP_PAEA_CTX_set_params(EVP_PAEA_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    char group[80], digest[80], *g = group, *d = digest;
    int rev = ctx->revocation;

    if (ctx->data != NULL)
        return state_error();
    memcpy(group, ctx->group, sizeof(group));
    memcpy(digest, ctx->digest, sizeof(digest));
    if (((p = OSSL_PARAM_locate_const(params, "group")) != NULL
         && !OSSL_PARAM_get_utf8_string(p, &g, sizeof(group)))
        || ((p = OSSL_PARAM_locate_const(params, "digest")) != NULL
            && !OSSL_PARAM_get_utf8_string(p, &d, sizeof(digest)))
        || ((p = OSSL_PARAM_locate_const(params, "revocation")) != NULL
            && (!OSSL_PARAM_get_int(p, &rev) || (rev != 0 && rev != 1))))
        return 0;
    memcpy(ctx->group, group, sizeof(group));
    memcpy(ctx->digest, digest, sizeof(digest));
    ctx->revocation = rev;
    return 1;
}

int EVP_PAEA_setup(EVP_PAEA_CTX *ctx)
{
    if (ctx->data != NULL)
        return state_error();
    if (!ctx->meth->setup(ctx)) {
        ctx->meth->free(ctx);
        return 0;
    }
    ctx->server = 1;
    return 1;
}

int EVP_PAEA_export_public(const EVP_PAEA_CTX *ctx,
                           unsigned char **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    if (ctx->data == NULL)
        return state_error();
    return ctx->meth->export_public(ctx, out, outlen);
}

int EVP_PAEA_import_public(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len)
{
    int revocation = ctx->revocation;

    if (ctx->data != NULL || len > PAEA_MAX_BLOB_LEN)
        return state_error();
    if (!ctx->meth->import_public(ctx, in, len)) {
        ctx->meth->free(ctx);
        ctx->revocation = revocation;
        return 0;
    }
    return 1;
}

EVP_PAEA_CTX *EVP_PAEA_CTX_dup_public(const EVP_PAEA_CTX *src)
{
    EVP_PAEA_CTX *ctx = EVP_PAEA_CTX_new_ex(src->libctx, src->meth->name, src->propq);
    unsigned char *buf = NULL;
    size_t len = 0;

    if (ctx == NULL || !EVP_PAEA_export_public(src, &buf, &len)
        || !EVP_PAEA_import_public(ctx, buf, len)) {
        EVP_PAEA_CTX_free(ctx);
        ctx = NULL;
    }
    OPENSSL_free(buf);
    return ctx;
}

int EVP_PAEA_issue_credential(EVP_PAEA_CTX *ctx,
                              const unsigned char *uid, size_t uidlen,
                              unsigned char **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    if (ctx->data == NULL || !ctx->server || ctx->stage != 0 || uidlen > 512)
        return state_error();
    return ctx->meth->issue(ctx, uid, uidlen, out, outlen);
}

int EVP_PAEA_store_credential(EVP_PAEA_CTX *ctx,
                              const unsigned char *uid, size_t uidlen,
                              const unsigned char *pw, size_t pwlen,
                              const unsigned char *in, size_t inlen)
{
    if (ctx->data == NULL || ctx->server || ctx->stage != 0
        || uidlen > 512 || inlen > PAEA_MAX_BLOB_LEN)
        return state_error();
    return ctx->meth->store(ctx, uid, uidlen, pw, pwlen, in, inlen);
}

int EVP_PAEA_revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen)
{
    if (ctx->data == NULL || !ctx->server || !ctx->revocation
        || ctx->stage != 0 || uidlen > 512)
        return state_error();
    return ctx->meth->revoke(ctx, uid, uidlen);
}

int EVP_PAEA_refresh(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *src)
{
    if (ctx->data == NULL || src->data == NULL || ctx->server
        || ctx->stage != 0 || ctx->meth != src->meth || !ctx->revocation
        || !src->revocation)
        return state_error();
    return ctx->meth->refresh(ctx, src);
}

int EVP_PAEA_auth_init(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                       unsigned char **out, size_t *outlen)
{
    int rc;

    *out = NULL; *outlen = 0;
    if (ctx->data == NULL || ctx->stage != 0)
        return state_error();
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    ctx->keylen = 0;
    rc = ctx->meth->init(ctx, pw, pwlen, out, outlen);
    if (!rc) {
        ctx->meth->reset(ctx);
        ctx->stage = -1;
    }
    return rc;
}

int EVP_PAEA_auth_step(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                       const unsigned char *in, size_t inlen,
                       unsigned char **out, size_t *outlen)
{
    int rc;

    *out = NULL; *outlen = 0;
    if (ctx->data == NULL || ctx->stage < 0 || ctx->stage == 2)
        return state_error();
    if (inlen > PAEA_MAX_BLOB_LEN) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        rc = 0;
    } else {
        rc = ctx->meth->step(ctx, pw, pwlen, in, inlen, out, outlen);
    }
    if (!rc || ctx->stage == 2)
        ctx->meth->reset(ctx);
    if (!rc) {
        OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
        ctx->keylen = 0;
        ctx->stage = -1;
    }
    return rc;
}

void EVP_PAEA_auth_reset(EVP_PAEA_CTX *ctx)
{
    if (ctx->data != NULL)
        ctx->meth->reset(ctx);
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    ctx->keylen = 0;
    ctx->stage = 0;
}

int EVP_PAEA_get_session_key(const EVP_PAEA_CTX *ctx,
                             unsigned char *out, size_t *len)
{
    if (ctx->stage != 2 || ctx->keylen == 0)
        return state_error();
    if (out == NULL) {
        *len = ctx->keylen;
        return 1;
    }
    if (*len < ctx->keylen) {
        *len = ctx->keylen;
        return 0;
    }
    memcpy(out, ctx->key, ctx->keylen);
    *len = ctx->keylen;
    return 1;
}

int EVP_PAEA_export_credential(const EVP_PAEA_CTX *ctx,
                               unsigned char **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    if (ctx->data == NULL || ctx->server)
        return state_error();
    return ctx->meth->export_credential(ctx, out, outlen);
}

int EVP_PAEA_import_credential(EVP_PAEA_CTX *ctx,
                               const unsigned char *in, size_t inlen)
{
    if (ctx->data == NULL || ctx->server || ctx->stage != 0 || inlen > PAEA_MAX_BLOB_LEN)
        return state_error();
    return ctx->meth->import_credential(ctx, in, inlen);
}
