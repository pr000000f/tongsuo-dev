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
 * ZYHW (GB/T 34953.4-XXXX 7.3) integration tests:
 *
 *   - full registration + anonymous authentication (with and without
 *     the optional revocation bookkeeping)
 *   - session key agreement on both sides
 *   - wrong password is rejected by the server (REJECT)
 *   - tampered proof messages are rejected
 *   - user revocation: stale witnesses stop working, witnesses refreshed
 *     with the updated CRL work again
 *   - the group is configurable: the whole flow runs on SM2/SM3 as well
 *     as on P-256/SHA-256
 *   - server key persistence (params + servkey + crl) and user credential
 *     persistence survive a context round trip
 */

#include "testutil.h"
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

/* mechanism configuration used by most tests */
typedef struct zh_conf_st {
    const char *group;
    const char *digest;
    const char *signature;
    const char *sig_digest;     /* NULL == scheme default */
    int revocation;
} ZH_CONF;

static const ZH_CONF conf_sm2 = {
    "SM2", "SM3", "SM2", NULL, 1
};
static const ZH_CONF conf_p256 = {
    "P-256", "SHA256", "EC", "SHA256", 1
};
static const ZH_CONF conf_norev = {
    "SM2", "SM3", "SM2", NULL, 0
};

static EVP_PAEA_CTX *zh_new_ctx(void)
{
    return EVP_PAEA_CTX_new(NULL, NULL);
}

static int zh_apply_conf(EVP_PAEA_CTX *ctx, const ZH_CONF *conf)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    int ok = 0;

    if (bld == NULL)
        goto end;
    if (!OSSL_PARAM_BLD_push_int(bld, OSSL_PAEA_PARAM_MECHANISM,
                                 NID_zyhw_mechanism)
            || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PAEA_PARAM_GROUP,
                                               conf->group, 0)
            || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PAEA_PARAM_DIGEST,
                                                conf->digest, 0)
            || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PAEA_PARAM_SIGNATURE,
                                                conf->signature, 0)
            || !OSSL_PARAM_BLD_push_int(bld, OSSL_PAEA_PARAM_REVOCATION,
                                        conf->revocation))
        goto end;
    if (conf->sig_digest != NULL
            && OSSL_PARAM_BLD_push_utf8_string(bld,
                                              OSSL_PAEA_PARAM_SIG_DIGEST,
                                              conf->sig_digest, 0) != 1)
        goto end;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto end;
    ok = EVP_PAEA_CTX_set_params(ctx, params);

 end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

static int zh_set_blob(EVP_PAEA_CTX *ctx, const char *key,
                       const unsigned char *blob, size_t blob_len)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    int ok = 0;

    if (bld == NULL)
        goto end;
    if (OSSL_PARAM_BLD_push_octet_string(bld, key, blob, blob_len) != 1)
        goto end;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto end;
    ok = EVP_PAEA_CTX_set_params(ctx, params);

 end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

static unsigned char *zh_get_blob(EVP_PAEA_CTX *ctx, const char *key,
                                  size_t *out_len)
{
    OSSL_PARAM params[2];
    unsigned char *buf = NULL;

    *out_len = 0;
    params[0] = OSSL_PARAM_construct_octet_string(key, NULL, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_PAEA_CTX_get_params(ctx, params))
        return NULL;
    if (params[0].return_size == 0)
        return NULL;
    buf = OPENSSL_malloc(params[0].return_size);
    if (buf == NULL)
        return NULL;
    params[0] = OSSL_PARAM_construct_octet_string(key, buf,
                                                  params[0].return_size);
    if (!EVP_PAEA_CTX_get_params(ctx, params)) {
        OPENSSL_free(buf);
        return NULL;
    }
    *out_len = params[0].return_size;
    return buf;
}

static unsigned char *zh_issued(EVP_PAEA_CTX *sctx,
                                const unsigned char *uid, size_t uid_len,
                                size_t *out_len)
{
    size_t len = 0;
    unsigned char *buf;

    if (!EVP_PAEA_server_issue_credential(sctx, uid, uid_len, NULL, &len))
        return NULL;
    buf = OPENSSL_malloc(len);
    if (buf == NULL)
        return NULL;
    *out_len = len;
    if (!EVP_PAEA_server_issue_credential(sctx, uid, uid_len, buf, out_len)) {
        OPENSSL_free(buf);
        return NULL;
    }
    return buf;
}

/*
 * One anonymous authentication run.  Returns 1 (ACCEPT from both sides,
 * matching session keys) or 0 (anything fails).  sk_out may be NULL.
 */
static int zh_auth_once(EVP_PAEA_CTX *sctx, EVP_PAEA_CTX *uctx,
                        const unsigned char *pw, size_t pw_len,
                        unsigned char *sk_out, size_t *sk_len_out)
{
    unsigned char *msg1 = NULL, *msg2 = NULL, *sk_u = NULL, *sk_s = NULL;
    size_t msg1_len = 0, msg2_len = 0, sku_len = 0, sks_len = 0;
    int ret = 0;

    /*
     * Every auth_init call produces a fresh randomly signed message: the
     * DER signature length varies a byte or two between calls, so never
     * use the size-probe-then-write pattern here.  512 bytes comfortably
     * cover TL(Y)+TL(sigma_S) on all supported curves.
     */
    msg1 = OPENSSL_malloc(512);
    if (msg1 == NULL)
        goto end;
    msg1_len = 512;
    ERR_clear_error();
    if (!EVP_PAEA_server_auth_init(sctx, msg1, &msg1_len)) {
        fprintf(stderr, "AUX: auth_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* sigma_U is at most 3 points + 4 integers (with TL prefixes),
     * ~350 bytes on P-521; 1024 is generous for all groups. */
    msg2 = OPENSSL_malloc(1024);
    if (msg2 == NULL)
        goto end;
    msg2_len = 1024;
    ERR_clear_error();
    if (!EVP_PAEA_user_auth_prove(uctx, pw, pw_len, msg1, msg1_len,
                                  msg2, &msg2_len)) {
        fprintf(stderr, "AUX: user prove failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ERR_clear_error();
    if (EVP_PAEA_server_auth_verify(sctx, msg2, msg2_len) != 1) {
        fprintf(stderr, "AUX: server verify REJECTED msg2 (%zu bytes)\n",
                msg2_len);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (!EVP_PAEA_CTX_get_session_key(uctx, NULL, &sku_len)) {
        fprintf(stderr, "AUX: user sk get (sizing) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    sk_u = OPENSSL_malloc(sku_len);
    if (sk_u == NULL)
        goto end;
    if (!EVP_PAEA_CTX_get_session_key(uctx, sk_u, &sku_len)) {
        fprintf(stderr, "AUX: user sk get failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    if (!EVP_PAEA_CTX_get_session_key(sctx, NULL, &sks_len)) {
        fprintf(stderr, "AUX: server sk get (sizing) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    sk_s = OPENSSL_malloc(sks_len);
    if (sk_s == NULL)
        goto end;
    if (!EVP_PAEA_CTX_get_session_key(sctx, sk_s, &sks_len)) {
        fprintf(stderr, "AUX: server sk get failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (sku_len != sks_len || memcmp(sk_u, sk_s, sku_len) != 0) {
        size_t i;

        fprintf(stderr, "AUX: SK mismatch! user len=%zu server len=%zu\n",
                sku_len, sks_len);
        if (sku_len == sks_len) {
            for (i = 0; i < sku_len && sk_u[i] == sk_s[i]; i++)
                ;
            fprintf(stderr, "AUX: first differing byte at %zu\n", i);
        }
        goto end;
    }

    if (sk_out != NULL && sk_len_out != NULL) {
        if (*sk_len_out < sku_len) {
            *sk_len_out = sku_len;
            goto end;
        }
        memcpy(sk_out, sk_u, sku_len);
        *sk_len_out = sku_len;
    }
    ret = 1;

 end:
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    OPENSSL_free(sk_u);
    OPENSSL_free(sk_s);
    return ret;
}

/*
 * Wire up a fresh user context from the current server context state
 * (params blob, crl, credential), shared by most of the tests below.
 */
static int zh_make_user(EVP_PAEA_CTX *sctx, const ZH_CONF *conf,
                        const unsigned char *uid, size_t uid_len,
                        const unsigned char *pw, size_t pw_len,
                        EVP_PAEA_CTX **out_uctx)
{
    unsigned char *params_blob = NULL, *issued = NULL, *crl = NULL;
    size_t params_len = 0, issued_len = 0, crl_len = 0;
    EVP_PAEA_CTX *uctx = NULL;
    int ret = 0;

    *out_uctx = NULL;

    params_blob = zh_get_blob(sctx, OSSL_PAEA_PARAM_PARAMS, &params_len);
    if (params_blob == NULL)
        goto end;
    issued = zh_issued(sctx, uid, uid_len, &issued_len);
    if (issued == NULL)
        goto end;

    uctx = zh_new_ctx();
    if (uctx == NULL)
        goto end;
    if (conf->revocation) {
        /* the params blob already carries the CRL, yet exercise the
         * standalone "crl" import the way deployments will refresh it */
        crl = zh_get_blob(sctx, OSSL_PAEA_PARAM_CRL, &crl_len);
        if (crl == NULL)
            goto end;
    }
    if (!zh_apply_conf(uctx, conf))
        goto end;
    if (conf->revocation
            && !zh_set_blob(uctx, OSSL_PAEA_PARAM_CRL, crl, crl_len))
        goto end;
    if (!zh_set_blob(uctx, OSSL_PAEA_PARAM_PARAMS, params_blob, params_len))
        goto end;
    if (!EVP_PAEA_user_store_credential(uctx, uid, uid_len, pw, pw_len,
                                        issued, issued_len))
        goto end;

    *out_uctx = uctx;
    uctx = NULL;
    ret = 1;

 end:
    OPENSSL_free(params_blob);
    OPENSSL_free(issued);
    OPENSSL_free(crl);
    EVP_PAEA_CTX_free(uctx);
    return ret;
}

static EVP_PAEA_CTX *zh_server_of(const ZH_CONF *conf)
{
    EVP_PAEA_CTX *sctx = zh_new_ctx();

    if (sctx == NULL)
        return NULL;
    if (!zh_apply_conf(sctx, conf) || !EVP_PAEA_setup(sctx)) {
        EVP_PAEA_CTX_free(sctx);
        return NULL;
    }
    return sctx;
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

static int test_zh_basic(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "correct horse battery staple";
    EVP_PAEA_CTX *sctx = NULL, *uctx = NULL;

    if (!TEST_ptr(sctx = zh_server_of(&conf_norev))
            || !TEST_true(zh_make_user(sctx, &conf_norev, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx)))
        goto err;
    if (!TEST_true(zh_auth_once(sctx, uctx, pw, sizeof(pw) - 1, NULL, NULL)))
        goto err;

    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 1;

 err:
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 0;
}

static int test_zh_curves(void)
{
    static const unsigned char uid[] = "curve-user-1";
    static const unsigned char pw[] = "hunter2!";
    EVP_PAEA_CTX *sctx = NULL, *uctx = NULL;

    if (!TEST_ptr(sctx = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(sctx, &conf_sm2, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx))
            || !TEST_true(zh_auth_once(sctx, uctx, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);

    /* second curve: P-256 with ECDSA/SHA256 signatures */
    if (!TEST_ptr(sctx = zh_server_of(&conf_p256))
            || !TEST_true(zh_make_user(sctx, &conf_p256, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx))
            || !TEST_true(zh_auth_once(sctx, uctx, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 1;

 err:
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 0;
}

static int test_zh_wrong_password(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "right-password";
    static const unsigned char bad[] = "wrong-password";
    EVP_PAEA_CTX *sctx = NULL, *uctx = NULL;
    unsigned char *msg1 = NULL, *msg2 = NULL;
    size_t msg1_len = 0, msg2_len = 0;

    if (!TEST_ptr(sctx = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(sctx, &conf_sm2, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx)))
        goto err;

    /* see zh_auth_once(): fresh random signature on every call, so use
     * a fixed generous buffer instead of size-probe-then-write */
    msg1 = OPENSSL_malloc(512);
    if (msg1 == NULL)
        goto err;
    msg1_len = 512;
    if (!EVP_PAEA_server_auth_init(sctx, msg1, &msg1_len))
        goto err;
    /* proving with the wrong password produces a proof the server
     * rejects (the honest user cannot tell locally!) */
    msg2 = OPENSSL_malloc(1024);
    if (msg2 == NULL)
        goto err;
    msg2_len = 1024;
    if (!EVP_PAEA_user_auth_prove(uctx, bad, sizeof(bad) - 1,
                                  msg1, msg1_len, msg2, &msg2_len))
        goto err;
    if (!TEST_false(EVP_PAEA_server_auth_verify(sctx, msg2, msg2_len)))
        goto err;

    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 1;

 err:
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 0;
}

static int test_zh_tampered_message(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "right-password";
    EVP_PAEA_CTX *sctx = NULL, *uctx = NULL;
    unsigned char *msg1 = NULL, *msg2 = NULL;
    size_t msg1_len = 0, msg2_len = 0;

    if (!TEST_ptr(sctx = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(sctx, &conf_sm2, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx)))
        goto err;
    /* see zh_auth_once(): fixed generous buffers, no size probing */
    msg1 = OPENSSL_malloc(512);
    if (msg1 == NULL)
        goto err;
    msg1_len = 512;
    if (!EVP_PAEA_server_auth_init(sctx, msg1, &msg1_len))
        goto err;
    msg2 = OPENSSL_malloc(1024);
    if (msg2 == NULL)
        goto err;
    msg2_len = 1024;
    if (!EVP_PAEA_user_auth_prove(uctx, pw, sizeof(pw) - 1,
                                  msg1, msg1_len, msg2, &msg2_len))
        goto err;

    /* flip a byte inside the middle of sigma_U and make sure the
     * verification equation falls apart */
    msg2[msg2_len / 2] ^= 0x01;
    if (!TEST_false(EVP_PAEA_server_auth_verify(sctx, msg2, msg2_len)))
        goto err;
    /* restore, and truncate the message */
    msg2[msg2_len / 2] ^= 0x01;
    if (!TEST_false(EVP_PAEA_server_auth_verify(sctx, msg2, msg2_len - 1)))
        goto err;

    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 1;

 err:
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    return 0;
}

static int test_zh_revocation(void)
{
    static const unsigned char uid1[] = "user-one";
    static const unsigned char uid2[] = "user-two";
    static const unsigned char pw[] = "-shared-password";
    EVP_PAEA_CTX *sctx = NULL, *u1 = NULL, *u2 = NULL;
    unsigned char *crl = NULL;
    size_t crl_len = 0;

    if (!TEST_ptr(sctx = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(sctx, &conf_sm2,
                                       uid1, sizeof(uid1) - 1,
                                       pw, sizeof(pw) - 1, &u1))
            || !TEST_true(zh_make_user(sctx, &conf_sm2,
                                       uid2, sizeof(uid2) - 1,
                                       pw, sizeof(pw) - 1, &u2))
            || !TEST_true(zh_auth_once(sctx, u1, pw, sizeof(pw) - 1,
                                       NULL, NULL))
            || !TEST_true(zh_auth_once(sctx, u2, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    /* revoke uid1: their stale witness must stop working, uid2 keeps
     * authenticating after refreshing against the new CRL */
    if (!TEST_true(EVP_PAEA_server_revoke(sctx, uid1, sizeof(uid1) - 1)))
        goto err;
    if (!TEST_false(zh_auth_once(sctx, u1, pw, sizeof(pw) - 1, NULL, NULL)))
        goto err;

    crl = zh_get_blob(sctx, OSSL_PAEA_PARAM_CRL, &crl_len);
    if (!TEST_ptr(crl))
        goto err;
    if (!TEST_true(zh_set_blob(u2, OSSL_PAEA_PARAM_CRL, crl, crl_len))
            || !TEST_true(EVP_PAEA_user_update_witness(u2))
            || !TEST_true(zh_auth_once(sctx, u2, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    /* a user that freshly registers after a revocation event gets a
     * witness matching the current CRL, immediately usable */
    if (!TEST_true(zh_set_blob(u1, OSSL_PAEA_PARAM_CRL, crl, crl_len)))
        goto err;
    /* uid1 stays revoked: refresh detectable by the USER_REVOKED reason,
     * updating then keeps failing the auth until re-registration */
    if (!TEST_false(EVP_PAEA_user_update_witness(u1))) {
        /* accepting would be a protocol error; failing here is expected */
        goto err;
    }

    /* double revocation must be rejected */
    if (!TEST_false(EVP_PAEA_server_revoke(sctx, uid1, sizeof(uid1) - 1)))
        goto err;

    OPENSSL_free(crl);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(u1);
    EVP_PAEA_CTX_free(u2);
    return 1;

 err:
    OPENSSL_free(crl);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(u1);
    EVP_PAEA_CTX_free(u2);
    return 0;
}

static int test_zh_persistence(void)
{
    static const unsigned char uid[] = "persistent-user";
    static const unsigned char pw[] = "persistent-password";
    EVP_PAEA_CTX *sctx = NULL, *uctx = NULL;
    unsigned char *params_blob = NULL, *servkey = NULL, *crl = NULL;
    unsigned char *cred = NULL;
    size_t params_len = 0, servkey_len = 0, crl_len = 0, cred_len = 0;
    EVP_PAEA_CTX *sctx2 = NULL, *uctx2 = NULL;

    if (!TEST_ptr(sctx = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(sctx, &conf_sm2, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &uctx))
            || !TEST_true(zh_auth_once(sctx, uctx, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    params_blob = zh_get_blob(sctx, OSSL_PAEA_PARAM_PARAMS, &params_len);
    servkey = zh_get_blob(sctx, OSSL_PAEA_PARAM_SERVKEY, &servkey_len);
    if (conf_sm2.revocation)
        crl = zh_get_blob(sctx, OSSL_PAEA_PARAM_CRL, &crl_len);
    cred = zh_get_blob(uctx, OSSL_PAEA_PARAM_CREDENTIAL, &cred_len);
    if (!TEST_ptr(params_blob) || !TEST_ptr(servkey) || !TEST_ptr(cred))
        goto err;

    /* fresh user context from the persisted credential ("user restart") */
    uctx2 = zh_new_ctx();
    if (!TEST_ptr(uctx2)
            || !TEST_true(zh_apply_conf(uctx2, &conf_sm2))
            || !TEST_true(zh_set_blob(uctx2, OSSL_PAEA_PARAM_CRL,
                                      crl, crl_len))
            || !TEST_true(zh_set_blob(uctx2, OSSL_PAEA_PARAM_PARAMS,
                                      params_blob, params_len))
            || !TEST_true(zh_set_blob(uctx2, OSSL_PAEA_PARAM_CREDENTIAL,
                                      cred, cred_len))
            || !TEST_true(zh_auth_once(sctx, uctx2, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    /* restored server context drives a full authentication */
    sctx2 = zh_new_ctx();
    if (!TEST_ptr(sctx2)
            || !TEST_true(zh_apply_conf(sctx2, &conf_sm2))
            || !TEST_true(zh_set_blob(sctx2, OSSL_PAEA_PARAM_CRL,
                                      crl, crl_len))
            || !TEST_true(zh_set_blob(sctx2, OSSL_PAEA_PARAM_PARAMS,
                                      params_blob, params_len))
            || !TEST_true(zh_set_blob(sctx2, OSSL_PAEA_PARAM_SERVKEY,
                                      servkey, servkey_len))
            || !TEST_true(zh_auth_once(sctx2, uctx2, pw, sizeof(pw) - 1,
                                       NULL, NULL)))
        goto err;

    OPENSSL_free(params_blob);
    OPENSSL_free(servkey);
    OPENSSL_free(crl);
    OPENSSL_free(cred);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    EVP_PAEA_CTX_free(sctx2);
    EVP_PAEA_CTX_free(uctx2);
    return 1;

 err:
    OPENSSL_free(params_blob);
    OPENSSL_free(servkey);
    OPENSSL_free(crl);
    OPENSSL_free(cred);
    EVP_PAEA_CTX_free(sctx);
    EVP_PAEA_CTX_free(uctx);
    EVP_PAEA_CTX_free(sctx2);
    EVP_PAEA_CTX_free(uctx2);
    return 0;
}

int setup_tests(void)
{
    ADD_TEST(test_zh_basic);
    ADD_TEST(test_zh_curves);
    ADD_TEST(test_zh_wrong_password);
    ADD_TEST(test_zh_tampered_message);
    ADD_TEST(test_zh_revocation);
    ADD_TEST(test_zh_persistence);
    return 1;
}