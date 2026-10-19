/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include "testutil.h"
#include <openssl/paea.h>
#include <openssl/paeaerr.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <string.h>

static const unsigned char password[] = "correct horse";
static const char *mechanisms[] = {
    "ZYHW",
#ifndef OPENSSL_NO_PAIRING
    "YZW",
#endif
};

static EVP_PAEA_CTX *server_new(const char *name, int rev)
{
    EVP_PAEA_CTX *s = EVP_PAEA_CTX_new_ex(NULL, name, NULL);
    OSSL_PARAM p[] = { OSSL_PARAM_int("revocation", &rev), OSSL_PARAM_END };

    if (s == NULL || !EVP_PAEA_CTX_set_params(s, p) || !EVP_PAEA_setup(s)) {
        EVP_PAEA_CTX_free(s);
        return NULL;
    }
    return s;
}

static EVP_PAEA_CTX *register_user(EVP_PAEA_CTX *s, const char *uid)
{
    EVP_PAEA_CTX *u = NULL;
    unsigned char *issued = NULL;
    size_t n = 0;

    if (!EVP_PAEA_issue_credential(s, (const unsigned char *)uid, strlen(uid), &issued, &n)
        || (u = EVP_PAEA_CTX_dup_public(s)) == NULL
        || !EVP_PAEA_store_credential(u, (const unsigned char *)uid, strlen(uid),
                                      password, sizeof(password)-1, issued, n)) {
        EVP_PAEA_CTX_free(u);
        u = NULL;
    }
    OPENSSL_clear_free(issued, n);
    return u;
}

/* fault: 1 wrong password, 2 damaged first message, 3 bad server MAC
 * (YZW) / proof (ZYHW), 4 truncated final proof, 5 noncanonical response,
 * 6 over-limit input consumes the waiting server exchange. */
static int exchange(EVP_PAEA_CTX *s, EVP_PAEA_CTX *u, int fault)
{
    unsigned char *m1 = NULL, *m2 = NULL, *m3 = NULL, *empty = NULL;
    size_t n1 = 0, n2 = 0, n3 = 0, ne = 0, ns = 64, nu = 64;
    unsigned char sk[64], uk[64];
    const unsigned char *pw = fault == 1 ? (const unsigned char *)"wrong" : password;
    size_t pwlen = fault == 1 ? 5 : sizeof(password)-1;
    int yzw = strcmp(EVP_PAEA_CTX_get0_name(s), "YZW") == 0;
    int rc = 0;

    EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(u);
    if (yzw) {
        if (!EVP_PAEA_auth_init(u, pw, pwlen, &m1, &n1))
            goto done;
        if (fault == 2) m1[0] = 255; /* impossible framed length */
        if (!EVP_PAEA_auth_step(s, NULL, 0, m1, n1, &m2, &n2))
            goto done;
        if (fault == 3) m2[n2-1] ^= 1;
        if (!EVP_PAEA_auth_step(u, NULL, 0, m2, n2, &m3, &n3))
            goto done;
        if (fault == 5) memset(m3 + 4, 255, 32);
        if (fault == 6) {
            rc = EVP_PAEA_auth_step(s, NULL, 0, m3, 2 << 20, &empty, &ne)
                || EVP_PAEA_auth_step(s, NULL, 0, m3, n3, &empty, &ne);
            goto done;
        }
        if (!EVP_PAEA_auth_step(s, NULL, 0, m3, fault == 4 ? n3-1 : n3, &empty, &ne))
            goto done;
    } else {
        if (!EVP_PAEA_auth_init(s, NULL, 0, &m1, &n1))
            goto done;
        if (fault == 2) m1[0] = 255;
        if (!EVP_PAEA_auth_step(u, pw, pwlen, m1, n1, &m2, &n2))
            goto done;
        if (fault == 3 || fault == 5) m2[n2-1] ^= 1;
        if (fault == 6) {
            rc = EVP_PAEA_auth_step(s, NULL, 0, m2, 2 << 20, &empty, &ne)
                || EVP_PAEA_auth_step(s, NULL, 0, m2, n2, &empty, &ne);
            goto done;
        }
        if (!EVP_PAEA_auth_step(s, NULL, 0, m2, fault == 4 ? n2-1 : n2, &empty, &ne))
            goto done;
    }
    if (!TEST_true(EVP_PAEA_get_session_key(s, sk, &ns))
        || !TEST_true(EVP_PAEA_get_session_key(u, uk, &nu))
        || !TEST_mem_eq(sk, ns, uk, nu)
        || !TEST_false(EVP_PAEA_auth_step(s, NULL, 0, yzw ? m3 : m2,
                                          yzw ? n3 : n2, &empty, &ne)))
        goto done;
    ERR_clear_error();
    rc = 1;
 done:
    OPENSSL_free(m1); OPENSSL_free(m2); OPENSSL_free(m3); OPENSSL_free(empty);
    OPENSSL_cleanse(sk, sizeof(sk)); OPENSSL_cleanse(uk, sizeof(uk));
    return rc;
}

static int test_exchange(int idx)
{
    EVP_PAEA_CTX *s = server_new(mechanisms[idx], 0), *u = NULL;
    int i, rc = 0;
    unsigned char key[64];
    size_t n;

    if (!TEST_ptr(s) || !TEST_ptr(u = register_user(s, "alice"))
        || !TEST_true(exchange(s, u, 0)))
        goto done;
    for (i = 1; i <= 6; i++) {
        n = sizeof(key);
        if (!TEST_false(exchange(s, u, i))
            || !TEST_false(EVP_PAEA_get_session_key(s, key, &n)))
            goto done;
        ERR_clear_error();
    }
    if (!TEST_true(exchange(s, u, 0)))
        goto done;
    rc = 1;
 done:
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(u);
    return rc;
}

static int test_revocation(int idx)
{
    EVP_PAEA_CTX *s = server_new(mechanisms[idx], 1), *a = NULL, *b = NULL;
    EVP_PAEA_CTX *other = NULL;
    int rc = 0;

    if (!TEST_ptr(s) || !TEST_ptr(a = register_user(s, "alice"))
        || !TEST_true(exchange(s, a, 0)))
        goto done;
    EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(a);
    if (!TEST_ptr(b = register_user(s, "bob")))
        goto done;
    if (strcmp(mechanisms[idx], "YZW") == 0) {
        if (!TEST_false(exchange(s, a, 0)))
            goto done;
        ERR_clear_error();
        EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(a);
        if (!TEST_true(EVP_PAEA_refresh(a, s)) || !TEST_true(exchange(s, a, 0)))
            goto done;
    }
    EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(a);
    if (!TEST_true(EVP_PAEA_revoke(s, (const unsigned char *)"bob", 3))
        || !TEST_false(EVP_PAEA_revoke(s, (const unsigned char *)"bob", 3)))
        goto done;
    ERR_clear_error();
    if (strcmp(mechanisms[idx], "YZW") == 0
        && !TEST_false(EVP_PAEA_revoke(s, (const unsigned char *)"nobody", 6)))
        goto done;
    ERR_clear_error();
    if (!TEST_false(exchange(s, a, 0)))
        goto done;
    ERR_clear_error();
    EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(a);
    if (!TEST_true(EVP_PAEA_refresh(a, s)) || !TEST_true(exchange(s, a, 0)))
        goto done;
    EVP_PAEA_auth_reset(s); EVP_PAEA_auth_reset(a);
    if (!TEST_ptr(other = server_new(mechanisms[idx], 1))
        || !TEST_false(EVP_PAEA_refresh(a, other)))
        goto done;
    ERR_clear_error();
    if (!TEST_true(EVP_PAEA_revoke(s, (const unsigned char *)"alice", 5))
        || !TEST_false(EVP_PAEA_refresh(a, s)))
        goto done;
    ERR_clear_error();
    if (!TEST_false(exchange(s, a, 0)))
        goto done;
    ERR_clear_error();
    rc = 1;
 done:
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(a); EVP_PAEA_CTX_free(b); EVP_PAEA_CTX_free(other);
    return rc;
}

static int test_public(int idx)
{
    EVP_PAEA_CTX *s = server_new(mechanisms[idx], 0), *u = NULL, *v = NULL;
    unsigned char *p = NULL, *out = NULL;
    size_t n = 0, outlen = 0;
    int rc = 0;

    if (!TEST_ptr(s) || !TEST_true(EVP_PAEA_export_public(s, &p, &n))
        || !TEST_ptr(u = EVP_PAEA_CTX_new_ex(NULL, mechanisms[idx], NULL))
        || !TEST_false(EVP_PAEA_import_public(u, p, n-1)))
        goto done;
    ERR_clear_error();
    if (!TEST_true(EVP_PAEA_import_public(u, p, n))
        || !TEST_false(EVP_PAEA_issue_credential(u, (const unsigned char *)"a", 1, &out, &outlen)))
        goto done;
    ERR_clear_error();
    if (!TEST_ptr(v = EVP_PAEA_CTX_new_ex(NULL, mechanisms[idx], NULL)))
        goto done;
    p[4] ^= 1; /* mechanism tag */
    if (!TEST_false(EVP_PAEA_import_public(v, p, n)))
        goto done;
    ERR_clear_error();
    rc = 1;
 done:
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(u); EVP_PAEA_CTX_free(v);
    OPENSSL_free(p); OPENSSL_free(out);
    return rc;
}

static int test_ec_configuration(void)
{
    EVP_PAEA_CTX *s = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL), *u = NULL;
    char group[] = "P-256", digest[] = "SHA256";
    OSSL_PARAM p[] = { OSSL_PARAM_utf8_string("group", group, sizeof(group)),
                      OSSL_PARAM_utf8_string("digest", digest, sizeof(digest)), OSSL_PARAM_END };
    int rc = TEST_ptr(s) && TEST_true(EVP_PAEA_CTX_set_params(s, p))
        && TEST_true(EVP_PAEA_setup(s)) && TEST_ptr(u = register_user(s, "alice"))
        && TEST_true(exchange(s, u, 0));

    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(u);
    return rc;
}

static int test_sm2_configuration(void)
{
    EVP_PAEA_CTX *s = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL), *u = NULL;
    char bad[] = "SHA256", good[] = "sm3";
    OSSL_PARAM p[] = {
        OSSL_PARAM_utf8_string("digest", bad, sizeof(bad)), OSSL_PARAM_END
    };
    OSSL_PARAM q[] = {
        OSSL_PARAM_utf8_string("digest", good, sizeof(good)), OSSL_PARAM_END
    };
    int rc = 0;

    if (!TEST_ptr(s) || !TEST_true(EVP_PAEA_CTX_set_params(s, p))
        || !TEST_false(EVP_PAEA_setup(s)))
        goto done;
    ERR_clear_error();
    /* A failed setup must leave the context configurable and reusable. */
    if (!TEST_true(EVP_PAEA_CTX_set_params(s, q))
        || !TEST_true(EVP_PAEA_setup(s))
        || !TEST_ptr(u = register_user(s, "alice"))
        || !TEST_true(exchange(s, u, 0)))
        goto done;
    rc = 1;
 done:
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(u);
    return rc;
}

/* Replace a length-prefixed field in a locally generated public encoding. */
static int replace_public_field(unsigned char **buf, size_t *len, int field,
                                const unsigned char *value, size_t vlen)
{
    size_t off = 0, n = 0, total;
    unsigned char *out;
    int i;

    for (i = 0; i <= field; i++) {
        if (!TEST_size_t_ge(*len - off, 4))
            return 0;
        n = ((size_t)(*buf)[off] << 24) | ((size_t)(*buf)[off + 1] << 16)
            | ((size_t)(*buf)[off + 2] << 8) | (*buf)[off + 3];
        if (!TEST_size_t_le(n, *len - off - 4))
            return 0;
        if (i != field)
            off += 4 + n;
    }
    total = *len - n + vlen;
    if (!TEST_ptr(out = OPENSSL_malloc(total)))
        return 0;
    memcpy(out, *buf, off);
    out[off] = vlen >> 24; out[off + 1] = vlen >> 16;
    out[off + 2] = vlen >> 8; out[off + 3] = vlen;
    memcpy(out + off + 4, value, vlen);
    memcpy(out + off + 4 + vlen, *buf + off + 4 + n, *len - off - 4 - n);
    OPENSSL_free(*buf); *buf = out; *len = total;
    return 1;
}

static int test_sm2_public_digest(int idx)
{
    EVP_PAEA_CTX *s = server_new("ZYHW", 0), *u = NULL;
    EC_GROUP *group = NULL;
    unsigned char *valid = NULL, *bad = NULL, *der = NULL;
    size_t n = 0, badlen;
    int derlen, rc = 0;

    if (!TEST_ptr(s) || !TEST_true(EVP_PAEA_export_public(s, &valid, &n))
        || !TEST_ptr(bad = OPENSSL_memdup(valid, n))
        || !TEST_ptr(u = EVP_PAEA_CTX_new_ex(NULL, "ZYHW", NULL)))
        goto done;
    badlen = n;
    if (idx >= 2) {
        if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_sm2)))
            goto done;
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
        derlen = i2d_ECPKParameters(group, &der);
        if (!TEST_int_gt(derlen, 0)
            || !replace_public_field(&bad, &badlen, 1, der, (size_t)derlen))
            goto done;
    }
    /* Reject either a non-SM3 protocol hash or a non-SM3 signature hash. */
    if (!replace_public_field(&bad, &badlen, 2 + idx % 2,
                              (const unsigned char *)"SHA256", 6)
        || !TEST_false(EVP_PAEA_import_public(u, bad, badlen)))
        goto done;
    ERR_clear_error();
    if (!TEST_true(EVP_PAEA_import_public(u, valid, n)))
        goto done;
    rc = 1;
 done:
    EC_GROUP_free(group); OPENSSL_free(der);
    OPENSSL_free(valid); OPENSSL_free(bad);
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(u);
    return rc;
}

static int test_credentials(int idx)
{
    EVP_PAEA_CTX *s = server_new(mechanisms[idx], 1), *a = NULL, *b = NULL;
    EVP_PAEA_CTX *old = NULL, *u = NULL;
    unsigned char *cred = NULL;
    size_t len = 0;
    int rc = 0;

    if (!TEST_ptr(s) || !TEST_ptr(a = register_user(s, "alice"))
        || !TEST_ptr(b = register_user(s, "bob"))
        || !TEST_ptr(old = EVP_PAEA_CTX_dup_public(s))
        || !TEST_true(EVP_PAEA_revoke(s, (const unsigned char *)"bob", 3))
        || !TEST_true(EVP_PAEA_refresh(a, s))
        || !TEST_false(EVP_PAEA_refresh(a, old)))
        goto done;
    ERR_clear_error();
    /* A refreshed client must export matching public parameters and witness. */
    if (!TEST_ptr(u = EVP_PAEA_CTX_dup_public(a))
        || !TEST_true(EVP_PAEA_export_credential(a, &cred, &len))
        || !TEST_false(EVP_PAEA_import_credential(u, cred, len - 1)))
        goto done;
    ERR_clear_error();
    if (!TEST_true(EVP_PAEA_import_credential(u, cred, len))
        || !TEST_true(exchange(s, u, 0))
        || !TEST_true(exchange(s, a, 0)))
        goto done;
    rc = 1;
 done:
    OPENSSL_clear_free(cred, len);
    EVP_PAEA_CTX_free(s); EVP_PAEA_CTX_free(a); EVP_PAEA_CTX_free(b);
    EVP_PAEA_CTX_free(old); EVP_PAEA_CTX_free(u);
    return rc;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_exchange, OSSL_NELEM(mechanisms));
    ADD_ALL_TESTS(test_revocation, OSSL_NELEM(mechanisms));
    ADD_ALL_TESTS(test_public, OSSL_NELEM(mechanisms));
    ADD_ALL_TESTS(test_credentials, OSSL_NELEM(mechanisms));
    ADD_TEST(test_ec_configuration);
    ADD_TEST(test_sm2_configuration);
    ADD_ALL_TESTS(test_sm2_public_digest, 4);
    return 1;
}
