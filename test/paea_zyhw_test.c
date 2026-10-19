/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "testutil.h"
#include <openssl/paea.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>

static const unsigned char password[] = "zyhw-test-password";

static EVP_PAEA_CTX *server_new(int p256, int rev)
{
    EVP_PAEA_CTX *s = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL);
    char *group = p256 ? "P-256" : "SM2";
    char *digest = p256 ? "SHA256" : "SM3";
    OSSL_PARAM params[4];

    params[0] = OSSL_PARAM_construct_utf8_string("group", group, 0);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    params[2] = OSSL_PARAM_construct_int("revocation", &rev);
    params[3] = OSSL_PARAM_construct_end();
    if (s == NULL || !EVP_PAEA_CTX_set_params(s, params) || !EVP_PAEA_setup(s)) {
        EVP_PAEA_CTX_free(s);
        return NULL;
    }
    return s;
}

static EVP_PAEA_CTX *register_user(EVP_PAEA_CTX *s, const char *uid)
{
    EVP_PAEA_CTX *u = NULL;
    unsigned char *issued = NULL, *pub = NULL;
    size_t ni = 0, np = 0;

    if (!EVP_PAEA_issue_credential(s, (const unsigned char *)uid, strlen(uid),
                                    &issued, &ni)
        || !EVP_PAEA_export_public(s, &pub, &np)
        || (u = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL)) == NULL
        || !EVP_PAEA_import_public(u, pub, np)
        || !EVP_PAEA_store_credential(u, (const unsigned char *)uid, strlen(uid),
                                       password, sizeof(password) - 1, issued, ni)) {
        EVP_PAEA_CTX_free(u);
        u = NULL;
    }
    OPENSSL_free(pub);
    OPENSSL_clear_free(issued, ni);
    return u;
}

/* fault: 1 wrong password, 2 bad signature, 3 bad proof, 4 truncated proof. */
static int exchange(EVP_PAEA_CTX *s, EVP_PAEA_CTX *u, int fault)
{
    unsigned char *m1 = NULL, *m2 = NULL, *out = NULL;
    size_t n1 = 0, n2 = 0, no = 0, ns = EVP_MAX_MD_SIZE, nu = EVP_MAX_MD_SIZE;
    unsigned char sk[EVP_MAX_MD_SIZE], uk[EVP_MAX_MD_SIZE];
    const unsigned char *pw = fault == 1 ? (const unsigned char *)"wrong" : password;
    size_t npw = fault == 1 ? 5 : sizeof(password) - 1;
    int rc = 0;

    EVP_PAEA_auth_reset(s);
    EVP_PAEA_auth_reset(u);
    if (!EVP_PAEA_auth_init(s, NULL, 0, &m1, &n1))
        goto done;
    if (fault == 2)
        m1[n1 - 1] ^= 1;
    if (!EVP_PAEA_auth_step(u, pw, npw, m1, n1, &m2, &n2))
        goto done;
    if (fault == 3)
        m2[n2 - 1] ^= 1;
    if (!EVP_PAEA_auth_step(s, NULL, 0, m2, fault == 4 ? n2 - 1 : n2, &out, &no)
        || out != NULL || no != 0
        || !EVP_PAEA_get_session_key(s, sk, &ns)
        || !EVP_PAEA_get_session_key(u, uk, &nu)
        || ns != nu || CRYPTO_memcmp(sk, uk, ns) != 0)
        goto done;
    rc = 1;
 done:
    OPENSSL_free(m1);
    OPENSSL_free(m2);
    OPENSSL_free(out);
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(uk, sizeof(uk));
    EVP_PAEA_auth_reset(s);
    EVP_PAEA_auth_reset(u);
    return rc;
}

static int test_zh_configuration(int idx)
{
    EVP_PAEA_CTX *s = server_new(idx == 2, idx != 0), *u = NULL;
    int rc = TEST_ptr(s) && TEST_ptr(u = register_user(s, "alice"))
        && TEST_true(exchange(s, u, 0));

    EVP_PAEA_CTX_free(u);
    EVP_PAEA_CTX_free(s);
    return rc;
}

static int test_zh_rejections(void)
{
    EVP_PAEA_CTX *s = server_new(0, 1), *u = NULL;
    int i, rc = 0;

    if (!TEST_ptr(s) || !TEST_ptr(u = register_user(s, "alice")))
        goto done;
    for (i = 1; i <= 4; i++) {
        if (!TEST_false(exchange(s, u, i)))
            goto done;
        ERR_clear_error();
        if (!TEST_true(exchange(s, u, 0)))
            goto done;
    }
    rc = 1;
 done:
    EVP_PAEA_CTX_free(u);
    EVP_PAEA_CTX_free(s);
    return rc;
}

static int test_zh_revocation(void)
{
    EVP_PAEA_CTX *s = server_new(0, 1), *alice = NULL, *bob = NULL, *latest = NULL;
    unsigned char *pub = NULL;
    size_t np = 0;
    int rc = 0;

    if (!TEST_ptr(s) || !TEST_ptr(alice = register_user(s, "alice"))
        || !TEST_ptr(bob = register_user(s, "bob"))
        || !TEST_true(exchange(s, alice, 0))
        || !TEST_true(exchange(s, bob, 0))
        || !TEST_true(EVP_PAEA_revoke(s, (const unsigned char *)"alice", 5))
        || !TEST_false(exchange(s, alice, 0)))
        goto done;
    ERR_clear_error();
    if (!TEST_true(EVP_PAEA_export_public(s, &pub, &np))
        || !TEST_ptr(latest = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL))
        || !TEST_true(EVP_PAEA_import_public(latest, pub, np))
        || !TEST_true(EVP_PAEA_refresh(bob, latest))
        || !TEST_true(exchange(s, bob, 0))
        || !TEST_false(EVP_PAEA_refresh(alice, latest)))
        goto done;
    ERR_clear_error();
    if (!TEST_false(EVP_PAEA_revoke(s, (const unsigned char *)"alice", 5)))
        goto done;
    ERR_clear_error();
    rc = 1;
 done:
    OPENSSL_free(pub);
    EVP_PAEA_CTX_free(latest);
    EVP_PAEA_CTX_free(alice);
    EVP_PAEA_CTX_free(bob);
    EVP_PAEA_CTX_free(s);
    return rc;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_zh_configuration, 3);
    ADD_TEST(test_zh_rejections);
    ADD_TEST(test_zh_revocation);
    return 1;
}
