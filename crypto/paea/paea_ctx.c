/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * EVP_PAEA_CTX lifecycle and OSSL_PARAM dispatch.  The PAEA mechanism is
 * selected by its NID; individual algorithms (the cyclic group, the
 * collisions resistant hash function H_lamda and the server signature
 * scheme) are configured through EVP fetchable names so any provider
 * supplied implementation can be selected.
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"
#include "crypto/paeaerr.h"

EVP_PAEA_CTX *EVP_PAEA_CTX_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PAEA_CTX *ctx;

    ossl_err_load_PAEA_strings();

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    /*
     * Note: like most EVP level contexts, the library context and the
     * property query string are not reference counted here; the caller
     * has to keep them alive for the lifetime of this context.
     */
    ctx->libctx = libctx;
    if (propq != NULL) {
        ctx->propq = OPENSSL_strdup(propq);
        if (ctx->propq == NULL) {
            OPENSSL_free(ctx);
            return NULL;
        }
    }
    ctx->mechanism = NID_undef;
    return ctx;
}

void EVP_PAEA_CTX_free(EVP_PAEA_CTX *ctx)
{
    if (ctx == NULL)
        return;

    paea_ctx_clear_group(ctx);          /* also clears session, crl,
                                           credential, keys, r, chi */
    EVP_MD_free(ctx->md);
    EVP_MD_free(ctx->sig_md);
    OPENSSL_free(ctx->digest_name);
    OPENSSL_free(ctx->sig_type);
    OPENSSL_free(ctx->sig_digest_name);
    OPENSSL_free(ctx->sig_curve_name);
    OPENSSL_free(ctx->propq);
    OPENSSL_free(ctx);
}

static int paea_param_is_utf8_string(const OSSL_PARAM *p)
{
    return p->data_type == OSSL_PARAM_UTF8_STRING
           || p->data_type == OSSL_PARAM_OCTET_STRING;
}

static int paea_set_utf8_string(const OSSL_PARAM *p, char **dst)
{
    const char *s = p->data;
    char *tmp;

    if (s == NULL)
        return 0;
    tmp = OPENSSL_strdup(s);
    if (tmp == NULL)
        return 0;
    OPENSSL_free(*dst);
    *dst = tmp;
    return 1;
}

int EVP_PAEA_CTX_set_params(EVP_PAEA_CTX *ctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    int nid;
    unsigned int uival;

    if (ctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_MECHANISM);
    if (p != NULL) {
        if (!OSSL_PARAM_get_int(p, &nid))
            return 0;
        if (nid != NID_zyhw_mechanism) {
            ERR_raise_data(ERR_LIB_PAEA, PAEA_R_WRONG_MECHANISM,
                           "only the ZYHW mechanism is supported");
            return 0;
        }
        ctx->mechanism = nid;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_GROUP);
    if (p != NULL) {
        char *name;
        int ok;

        if (p->data == NULL)
            return 0;
        /*
         * libcrypto humble helper: allow the curve to be given either as a
         * NULL terminated string or an octet string of the same.
         */
        name = OPENSSL_strndup(p->data, p->data_size);
        if (name == NULL)
            return 0;
        ok = paea_ctx_set_group_by_name(ctx, name);
        OPENSSL_free(name);
        if (ok != 1)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_DIGEST);
    if (p != NULL) {
        if (p->data == NULL)
            return 0;
        if (!paea_ctx_set_md_by_name(ctx, p->data))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_SIGNATURE);
    if (p != NULL) {
        if (!paea_param_is_utf8_string(p) || p->data == NULL)
            return 0;
        if (OPENSSL_strcasecmp(p->data, "SM2") != 0
                && OPENSSL_strcasecmp(p->data, "EC") != 0
                && OPENSSL_strcasecmp(p->data, "ECDSA") != 0) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_SIGNATURE_SCHEME);
            return 0;
        }
        if (!paea_set_utf8_string(p, &ctx->sig_type))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_SIG_DIGEST);
    if (p != NULL) {
        if (!paea_param_is_utf8_string(p) || p->data == NULL)
            return 0;
        if (!paea_set_utf8_string(p, &ctx->sig_digest_name))
            return 0;
        EVP_MD_free(ctx->sig_md);        /* re-fetched on next use */
        ctx->sig_md = NULL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_SIG_CURVE);
    if (p != NULL) {
        if (!paea_param_is_utf8_string(p) || p->data == NULL)
            return 0;
        if (!paea_set_utf8_string(p, &ctx->sig_curve_name))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_REVOCATION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &uival))
            return 0;
        ctx->revocation = uival != 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_PARAMS);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!paea_decode_params_blob(ctx, p->data, p->data_size))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_SERVKEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!paea_decode_servkey_blob(ctx, p->data, p->data_size))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_CRL);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!paea_decode_crl_blob(ctx, p->data, p->data_size))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PAEA_PARAM_CREDENTIAL);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!paea_decode_credential_blob(ctx, p->data, p->data_size))
            return 0;
    }

    return 1;
}

static int paea_get_blob_param(OSSL_PARAM *p, int (*encoder)(EVP_PAEA_CTX *,
                                                             PAEA_BUF *),
                               EVP_PAEA_CTX *ctx)
{
    PAEA_BUF b;
    int ret;

    if (p == NULL)
        return 1;
    if (p->data_type != OSSL_PARAM_OCTET_STRING && p->data_type != 0)
        return 0;

    paea_buf_init(&b);
    ret = encoder(ctx, &b);
    if (ret != 1) {
        paea_buf_cleanup(&b);
        return 0;
    }
    ret = OSSL_PARAM_set_octet_string(p,
                                      b.data == NULL
                                          ? (const unsigned char *)""
                                          : b.data,
                                      b.len);
    paea_buf_cleanup(&b);
    return ret;
}

int EVP_PAEA_CTX_get_params(EVP_PAEA_CTX *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    if (ctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PAEA_PARAM_PARAMS);
    if (p != NULL) {
        if (!ctx->params_ready) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
            return 0;
        }
        ok &= paea_get_blob_param(p, paea_encode_params_blob, ctx);
    }

    p = OSSL_PARAM_locate(params, OSSL_PAEA_PARAM_SERVKEY);
    if (p != NULL) {
        if (!ctx->server_secret) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
            return 0;
        }
        ok &= paea_get_blob_param(p, paea_encode_servkey_blob, ctx);
    }

    p = OSSL_PARAM_locate(params, OSSL_PAEA_PARAM_CRL);
    if (p != NULL) {
        if (ctx->group == NULL) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
            return 0;
        }
        ok &= paea_get_blob_param(p, paea_encode_crl_blob, ctx);
    }

    p = OSSL_PARAM_locate(params, OSSL_PAEA_PARAM_CREDENTIAL);
    if (p != NULL) {
        if (ctx->sigma_pw == NULL) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_NO_CREDENTIAL);
            return 0;
        }
        ok &= paea_get_blob_param(p, paea_encode_credential_blob, ctx);
    }

    p = OSSL_PARAM_locate(params, OSSL_PAEA_PARAM_SESSION_KEY);
    if (p != NULL) {
        if (!ctx->accepted || ctx->sk == NULL) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_NO_SESSION_KEY);
            return 0;
        }
        ok &= OSSL_PARAM_set_octet_string(p, ctx->sk, ctx->sk_len);
    }

    return ok;
}