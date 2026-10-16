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
 * ZYHW (GB/T 34953.4-XXXX 7.3) integration tests.
 *
 * The library has no context object.  This file keeps a party struct only
 * so a test can hold the group, keys, accumulator and CRL together.
 */

#include "testutil.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/paea.h>

typedef struct zh_conf_st {
    const char *group;
    const char *digest;
    const char *signature;
    const char *sig_digest;     /* NULL == scheme default */
    int revocation;
} ZH_CONF;

/* Test-local holder.  Not a library type. */
typedef struct zh_party_st {
    EC_GROUP *group;
    EVP_MD *md;
    EVP_MD *sig_md;
    char *digest_name;
    char *sig_type;
    char *sig_digest_name;
    EVP_PKEY *sig_key;
    EC_POINT *w;
    int revocation;
    EC_POINT *acc;
    BIGNUM *r;
    PAEA_CRL_ENTRY *crl;
    size_t crl_len;
    size_t crl_alloc;
    BIGNUM *m;
    EC_POINT *sigma_pw;
    EC_POINT *witness;
    uint32_t witness_idx;
    BIGNUM *y;
    EC_POINT *y_pt;
    unsigned char *sigma_s;
    size_t sigma_s_len;
} ZH_PARTY;

static const ZH_CONF conf_sm2 = {
    "SM2", "SM3", "SM2", NULL, 1
};
static const ZH_CONF conf_p256 = {
    "P-256", "SHA256", "EC", "SHA256", 1
};
static const ZH_CONF conf_norev = {
    "SM2", "SM3", "SM2", NULL, 0
};

static void zh_clear_session(ZH_PARTY *p)
{
    BN_clear_free(p->y);
    p->y = NULL;
    EC_POINT_free(p->y_pt);
    p->y_pt = NULL;
    OPENSSL_clear_free(p->sigma_s, p->sigma_s_len);
    p->sigma_s = NULL;
    p->sigma_s_len = 0;
}

static void zh_free(ZH_PARTY *p)
{
    if (p == NULL)
        return;
    zh_clear_session(p);
    EC_GROUP_free(p->group);
    EVP_MD_free(p->md);
    EVP_MD_free(p->sig_md);
    OPENSSL_free(p->digest_name);
    OPENSSL_free(p->sig_type);
    OPENSSL_free(p->sig_digest_name);
    EVP_PKEY_free(p->sig_key);
    EC_POINT_free(p->w);
    EC_POINT_free(p->acc);
    BN_clear_free(p->r);
    paea_crl_entries_free(p->crl, p->crl_len);
    BN_clear_free(p->m);
    EC_POINT_clear_free(p->sigma_pw);
    EC_POINT_clear_free(p->witness);
    OPENSSL_free(p);
}

/* B_n is the last CRL entry, or g when the list is empty. */
static int zh_set_acc(ZH_PARTY *p)
{
    const EC_POINT *src;

    if (!p->revocation)
        return 1;
    EC_POINT_free(p->acc);
    p->acc = EC_POINT_new(p->group);
    if (p->acc == NULL)
        return 0;
    src = p->crl_len == 0 ? EC_GROUP_get0_generator(p->group)
                          : p->crl[p->crl_len - 1].b;
    return EC_POINT_copy(p->acc, src) == 1;
}

static int zh_fetch_md(ZH_PARTY *p)
{
    EVP_MD_free(p->md);
    EVP_MD_free(p->sig_md);
    p->md = EVP_MD_fetch(NULL, p->digest_name, NULL);
    p->sig_md = EVP_MD_fetch(NULL, p->sig_digest_name, NULL);
    return p->md != NULL && p->sig_md != NULL;
}

static EC_GROUP *zh_group(const char *name)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)name, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EC_GROUP_new_from_params(params, NULL, NULL);
}

static ZH_PARTY *zh_server_of(const ZH_CONF *conf)
{
    ZH_PARTY *p = OPENSSL_zalloc(sizeof(*p));

    if (p == NULL)
        return NULL;
    p->revocation = conf->revocation;
    p->group = zh_group(conf->group);
    p->digest_name = OPENSSL_strdup(conf->digest);
    p->sig_type = OPENSSL_strdup(conf->signature);
    p->md = EVP_MD_fetch(NULL, conf->digest, NULL);
    if (p->group == NULL || p->digest_name == NULL || p->sig_type == NULL
        || p->md == NULL
        || !paea_zyhw_setup(p->group, conf->signature, conf->sig_digest, NULL,
                            NULL, NULL, conf->revocation,
                            &p->r, &p->w, &p->acc, &p->sig_key,
                            &p->sig_digest_name))
        goto err;
    p->sig_md = EVP_MD_fetch(NULL, p->sig_digest_name, NULL);
    if (p->sig_md == NULL)
        goto err;
    return p;

 err:
    zh_free(p);
    return NULL;
}

/* The user already holds the public parameters: curve, names, w, and
 * the server signature key.  CRL updates still travel as a blob. */
static int zh_copy_public(ZH_PARTY *dst, const ZH_PARTY *src)
{
    dst->revocation = src->revocation;
    dst->group = EC_GROUP_dup(src->group);
    dst->digest_name = OPENSSL_strdup(src->digest_name);
    dst->sig_type = OPENSSL_strdup(src->sig_type);
    dst->sig_digest_name = OPENSSL_strdup(src->sig_digest_name);
    dst->w = EC_POINT_dup(src->w, dst->group);
    if (dst->group == NULL || dst->digest_name == NULL
        || dst->sig_type == NULL || dst->sig_digest_name == NULL
        || dst->w == NULL || !EVP_PKEY_up_ref(src->sig_key))
        return 0;
    dst->sig_key = src->sig_key;
    return zh_fetch_md(dst);
}

static int zh_replace_crl(ZH_PARTY *p, const unsigned char *blob, size_t len)
{
    PAEA_CRL_ENTRY *crl = NULL;
    size_t n = 0;

    if (!paea_decode_crl_blob(p->group, blob, len, &crl, &n))
        return 0;
    paea_crl_entries_free(p->crl, p->crl_len);
    p->crl = crl;
    p->crl_len = n;
    p->crl_alloc = n;
    return zh_set_acc(p);
}

static int zh_make_user(ZH_PARTY *srv, const unsigned char *uid, size_t uid_len,
                        const unsigned char *pw, size_t pw_len, ZH_PARTY **out)
{
    unsigned char *crl = NULL, *issued = NULL;
    size_t crl_len = 0, issued_len = 0;
    ZH_PARTY *u = NULL;
    int ret = 0;

    *out = NULL;
    u = OPENSSL_zalloc(sizeof(*u));
    if (u == NULL || !zh_copy_public(u, srv))
        goto end;
    if (srv->revocation
        && (!paea_encode_crl_blob(srv->group, srv->crl, srv->crl_len,
                                  &crl, &crl_len)
            || !zh_replace_crl(u, crl, crl_len)))
        goto end;
    if (!paea_zyhw_issue_credential(srv->group, srv->md, srv->r,
                                    srv->revocation ? srv->acc : NULL,
                                    srv->crl_len, uid, uid_len,
                                    &issued, &issued_len))
        goto end;
    if (!paea_zyhw_wrap_credential(u->group, u->md, uid, uid_len, pw, pw_len,
                                   issued, issued_len, u->revocation,
                                   &u->m, &u->sigma_pw, &u->witness,
                                   &u->witness_idx))
        goto end;
    *out = u;
    u = NULL;
    ret = 1;

 end:
    OPENSSL_free(crl);
    OPENSSL_free(issued);
    zh_free(u);
    return ret;
}

static int zh_auth_init(ZH_PARTY *srv, unsigned char **msg, size_t *msg_len)
{
    zh_clear_session(srv);
    return paea_zyhw_server_auth_init(srv->group, srv->sig_key, srv->sig_md,
                                      msg, msg_len, &srv->y, &srv->y_pt,
                                      &srv->sigma_s, &srv->sigma_s_len);
}

static int zh_auth_once(ZH_PARTY *srv, ZH_PARTY *usr,
                        const unsigned char *pw, size_t pw_len)
{
    unsigned char *msg1 = NULL, *msg2 = NULL, *sk_u = NULL, *sk_s = NULL;
    size_t msg1_len = 0, msg2_len = 0, sku_len = 0, sks_len = 0;
    int ret = 0;

    if (!zh_auth_init(srv, &msg1, &msg1_len)
        || !paea_zyhw_user_prove(usr->group, usr->md, usr->sigma_pw, usr->m,
                                 usr->sig_key,
                                 usr->revocation ? usr->witness : NULL,
                                 usr->revocation ? usr->acc : NULL,
                                 pw, pw_len, msg1, msg1_len,
                                 &msg2, &msg2_len, &sk_u, &sku_len)
        || paea_zyhw_server_verify(srv->group, srv->md, srv->r, srv->y,
                                   srv->y_pt, srv->sigma_s, srv->sigma_s_len,
                                   srv->revocation ? srv->acc : NULL,
                                   msg2, msg2_len, &sk_s, &sks_len) != 1
        || sku_len != sks_len || memcmp(sk_u, sk_s, sku_len) != 0)
        goto end;
    ret = 1;

 end:
    ERR_clear_error();
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    OPENSSL_clear_free(sk_u, sku_len);
    OPENSSL_clear_free(sk_s, sks_len);
    return ret;
}

static int zh_revoke(ZH_PARTY *srv, const unsigned char *uid, size_t uid_len)
{
    BIGNUM *m = BN_new();
    int ok;

    if (m == NULL || !paea_m_of_uid(srv->md, srv->group, uid, uid_len, m)) {
        BN_clear_free(m);
        return 0;
    }
    ok = paea_crl_revoke(srv->group, srv->r, &srv->acc,
                         &srv->crl, &srv->crl_len, &srv->crl_alloc, m);
    BN_clear_free(m);
    return ok;
}

/* ------------------------------------------------------------------ */

static int test_zh_basic(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "correct horse battery staple";
    ZH_PARTY *srv = NULL, *usr = NULL;

    if (!TEST_ptr(srv = zh_server_of(&conf_norev))
            || !TEST_true(zh_make_user(srv, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &usr))
            || !TEST_true(zh_auth_once(srv, usr, pw, sizeof(pw) - 1)))
        goto err;
    zh_free(srv);
    zh_free(usr);
    return 1;

 err:
    zh_free(srv);
    zh_free(usr);
    return 0;
}

static int test_zh_curves(void)
{
    static const unsigned char uid[] = "curve-user-1";
    static const unsigned char pw[] = "hunter2!";
    ZH_PARTY *srv = NULL, *usr = NULL;

    if (!TEST_ptr(srv = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(srv, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &usr))
            || !TEST_true(zh_auth_once(srv, usr, pw, sizeof(pw) - 1)))
        goto err;
    zh_free(srv);
    zh_free(usr);
    srv = NULL;
    usr = NULL;

    if (!TEST_ptr(srv = zh_server_of(&conf_p256))
            || !TEST_true(zh_make_user(srv, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &usr))
            || !TEST_true(zh_auth_once(srv, usr, pw, sizeof(pw) - 1)))
        goto err;
    zh_free(srv);
    zh_free(usr);
    return 1;

 err:
    zh_free(srv);
    zh_free(usr);
    return 0;
}

static int test_zh_wrong_password(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "right-password";
    static const unsigned char bad[] = "wrong-password";
    ZH_PARTY *srv = NULL, *usr = NULL;
    unsigned char *msg1 = NULL, *msg2 = NULL;
    size_t msg1_len = 0, msg2_len = 0;

    if (!TEST_ptr(srv = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(srv, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &usr)))
        goto err;
    if (!zh_auth_init(srv, &msg1, &msg1_len))
        goto err;
    if (!paea_zyhw_user_prove(usr->group, usr->md, usr->sigma_pw, usr->m,
                              usr->sig_key, usr->witness, usr->acc,
                              bad, sizeof(bad) - 1, msg1, msg1_len,
                              &msg2, &msg2_len, NULL, NULL))
        goto err;
    if (!TEST_false(paea_zyhw_server_verify(srv->group, srv->md, srv->r,
                                            srv->y, srv->y_pt,
                                            srv->sigma_s, srv->sigma_s_len,
                                            srv->acc, msg2, msg2_len,
                                            NULL, NULL)))
        goto err;
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    zh_free(srv);
    zh_free(usr);
    return 1;

 err:
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    zh_free(srv);
    zh_free(usr);
    return 0;
}

static int test_zh_tampered_message(void)
{
    static const unsigned char uid[] = "user@example.com";
    static const unsigned char pw[] = "right-password";
    ZH_PARTY *srv = NULL, *usr = NULL;
    unsigned char *msg1 = NULL, *msg2 = NULL;
    size_t msg1_len = 0, msg2_len = 0;

    if (!TEST_ptr(srv = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(srv, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, &usr)))
        goto err;
    if (!zh_auth_init(srv, &msg1, &msg1_len))
        goto err;
    if (!paea_zyhw_user_prove(usr->group, usr->md, usr->sigma_pw, usr->m,
                              usr->sig_key, usr->witness, usr->acc,
                              pw, sizeof(pw) - 1, msg1, msg1_len,
                              &msg2, &msg2_len, NULL, NULL))
        goto err;

    msg2[msg2_len / 2] ^= 0x01;
    if (!TEST_false(paea_zyhw_server_verify(srv->group, srv->md, srv->r,
                                            srv->y, srv->y_pt,
                                            srv->sigma_s, srv->sigma_s_len,
                                            srv->acc, msg2, msg2_len,
                                            NULL, NULL)))
        goto err;
    msg2[msg2_len / 2] ^= 0x01;
    if (!TEST_false(paea_zyhw_server_verify(srv->group, srv->md, srv->r,
                                            srv->y, srv->y_pt,
                                            srv->sigma_s, srv->sigma_s_len,
                                            srv->acc, msg2, msg2_len - 1,
                                            NULL, NULL)))
        goto err;

    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    zh_free(srv);
    zh_free(usr);
    return 1;

 err:
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    zh_free(srv);
    zh_free(usr);
    return 0;
}

static int test_zh_revocation(void)
{
    static const unsigned char uid1[] = "user-one";
    static const unsigned char uid2[] = "user-two";
    static const unsigned char pw[] = "-shared-password";
    ZH_PARTY *srv = NULL, *u1 = NULL, *u2 = NULL;
    unsigned char *crl = NULL;
    size_t crl_len = 0;

    if (!TEST_ptr(srv = zh_server_of(&conf_sm2))
            || !TEST_true(zh_make_user(srv, uid1, sizeof(uid1) - 1,
                                       pw, sizeof(pw) - 1, &u1))
            || !TEST_true(zh_make_user(srv, uid2, sizeof(uid2) - 1,
                                       pw, sizeof(pw) - 1, &u2))
            || !TEST_true(zh_auth_once(srv, u1, pw, sizeof(pw) - 1))
            || !TEST_true(zh_auth_once(srv, u2, pw, sizeof(pw) - 1)))
        goto err;

    if (!TEST_true(zh_revoke(srv, uid1, sizeof(uid1) - 1)))
        goto err;
    if (!TEST_false(zh_auth_once(srv, u1, pw, sizeof(pw) - 1)))
        goto err;

    if (!TEST_true(paea_encode_crl_blob(srv->group, srv->crl, srv->crl_len,
                                        &crl, &crl_len))
            || !TEST_true(zh_replace_crl(u2, crl, crl_len))
            || !TEST_true(paea_zyhw_update_witness(u2->group, u2->m,
                                                   u2->witness,
                                                   &u2->witness_idx,
                                                   u2->crl, u2->crl_len))
            || !TEST_true(zh_auth_once(srv, u2, pw, sizeof(pw) - 1)))
        goto err;

    if (!TEST_true(zh_replace_crl(u1, crl, crl_len)))
        goto err;
    if (!TEST_false(paea_zyhw_update_witness(u1->group, u1->m, u1->witness,
                                             &u1->witness_idx,
                                             u1->crl, u1->crl_len)))
        goto err;
    if (!TEST_false(zh_revoke(srv, uid1, sizeof(uid1) - 1)))
        goto err;

    OPENSSL_free(crl);
    zh_free(srv);
    zh_free(u1);
    zh_free(u2);
    return 1;

 err:
    OPENSSL_free(crl);
    zh_free(srv);
    zh_free(u1);
    zh_free(u2);
    return 0;
}

int setup_tests(void)
{
    ADD_TEST(test_zh_basic);
    ADD_TEST(test_zh_curves);
    ADD_TEST(test_zh_wrong_password);
    ADD_TEST(test_zh_tampered_message);
    ADD_TEST(test_zh_revocation);
    return 1;
}
