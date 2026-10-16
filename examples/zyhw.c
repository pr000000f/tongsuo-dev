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
 * ZYHW (GB/T 34953.4 clause 7.3).  The caller holds the group, keys and
 * CRL.  There is no PAEA context.  The program runs the exchange twice:
 * once without revocation, then with revocation.
 *
 * PAEA is off unless the library was configured with enable-paea.
 * From the Tongsuo source tree:
 *
 *   ./Configure darwin64-arm64-cc no-shared enable-paea && make -j8
 *   cc -I include -o examples/zyhw examples/zyhw.c libcrypto.a -lpthread
 *
 * The same link is "make -C examples zyhw".  Run ./examples/zyhw.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/paea.h>

static const unsigned char pw[] = "correct horse battery staple";

typedef struct user_st {
    BIGNUM *m;
    EC_POINT *sigma_pw;
    EC_POINT *witness;
    EC_POINT *acc;
    PAEA_CRL_ENTRY *crl;
    size_t crl_len;
    uint32_t witness_idx;
} USER;

static EC_GROUP *group_by_name(const char *name)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)name, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EC_GROUP_new_from_params(params, NULL, NULL);
}

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static void user_clear(USER *u)
{
    BN_clear_free(u->m);
    EC_POINT_clear_free(u->sigma_pw);
    EC_POINT_clear_free(u->witness);
    EC_POINT_free(u->acc);
    paea_crl_entries_free(u->crl, u->crl_len);
    memset(u, 0, sizeof(*u));
}

/* 1 when the server accepts and both sides derive the same session key. */
static int authenticate(const EC_GROUP *group, EVP_MD *md, EVP_MD *sig_md,
                        EVP_PKEY *sk, const BIGNUM *r, const USER *user,
                        const EC_POINT *server_acc)
{
    BIGNUM *y = NULL;
    EC_POINT *y_pt = NULL;
    unsigned char *msg1 = NULL, *msg2 = NULL, *sigma_s = NULL;
    unsigned char *sk_user = NULL, *sk_server = NULL;
    size_t msg1_len = 0, msg2_len = 0, sigma_s_len = 0, sku_len = 0, sks_len = 0;
    int accept = 0;

    if (!paea_zyhw_server_auth_init(group, sk, sig_md, &msg1, &msg1_len,
                                    &y, &y_pt, &sigma_s, &sigma_s_len)
        || !paea_zyhw_user_prove(group, md, user->sigma_pw, user->m, sk,
                                 user->witness, user->acc,
                                 pw, sizeof(pw) - 1, msg1, msg1_len,
                                 &msg2, &msg2_len, &sk_user, &sku_len)
        || !paea_zyhw_server_verify(group, md, r, y, y_pt, sigma_s, sigma_s_len,
                                    server_acc, msg2, msg2_len,
                                    &sk_server, &sks_len)
        || sku_len != sks_len || memcmp(sk_user, sk_server, sku_len) != 0)
        goto done;

    printf("  ACCEPT\n");
    print_hex("  session key", sk_user, sku_len);
    accept = 1;

 done:
    BN_clear_free(y);
    EC_POINT_free(y_pt);
    OPENSSL_free(msg1);
    OPENSSL_free(msg2);
    OPENSSL_clear_free(sigma_s, sigma_s_len);
    OPENSSL_clear_free(sk_user, sku_len);
    OPENSSL_clear_free(sk_server, sks_len);
    if (!accept)
        ERR_clear_error();
    return accept;
}

static int register_user(const EC_GROUP *group, EVP_MD *md, const BIGNUM *r,
                         const EC_POINT *acc, size_t crl_len,
                         const unsigned char *uid, int revocation, USER *user)
{
    unsigned char *issued = NULL;
    size_t issued_len = 0;
    int ok = 0;

    memset(user, 0, sizeof(*user));
    if (!paea_zyhw_issue_credential(group, md, r,
                                    revocation ? acc : NULL, crl_len,
                                    uid, strlen((const char *)uid),
                                    &issued, &issued_len))
        goto done;
    if (!paea_zyhw_wrap_credential(group, md, uid, strlen((const char *)uid),
                                   pw, sizeof(pw) - 1, issued, issued_len,
                                   revocation, &user->m, &user->sigma_pw,
                                   &user->witness, &user->witness_idx))
        goto done;
    if (revocation) {
        user->acc = EC_POINT_dup(acc, group);
        if (user->acc == NULL)
            goto done;
    }
    ok = 1;

 done:
    OPENSSL_free(issued);
    if (!ok)
        user_clear(user);
    return ok;
}

/* The user installs the CRL the server published and refreshes W. */
static int take_crl(const EC_GROUP *group, USER *user,
                    const unsigned char *blob, size_t len)
{
    const EC_POINT *src;
    PAEA_CRL_ENTRY *crl = NULL;
    size_t n = 0;

    if (!paea_decode_crl_blob(group, blob, len, &crl, &n))
        return 0;
    paea_crl_entries_free(user->crl, user->crl_len);
    user->crl = crl;
    user->crl_len = n;
    src = n == 0 ? EC_GROUP_get0_generator(group) : crl[n - 1].b;
    if (user->acc == NULL)
        user->acc = EC_POINT_new(group);
    return user->acc != NULL && EC_POINT_copy(user->acc, src) == 1;
}

static int demo_without_revocation(const EC_GROUP *group, EVP_MD *md)
{
    EVP_MD *sig_md = NULL;
    EVP_PKEY *sk = NULL;
    BIGNUM *r = NULL;
    EC_POINT *w = NULL, *acc = NULL;
    char *sig_digest = NULL;
    USER user;
    int ok = 0;

    memset(&user, 0, sizeof(user));
    printf("without revocation\n");
    if (!paea_zyhw_setup(group, "SM2", NULL, NULL, NULL, NULL, 0,
                         &r, &w, &acc, &sk, &sig_digest))
        goto done;
    sig_md = EVP_MD_fetch(NULL, sig_digest, NULL);
    if (sig_md == NULL
        || !register_user(group, md, r, NULL, 0,
                          (const unsigned char *)"user@example.com", 0, &user))
        goto done;
    if (!authenticate(group, md, sig_md, sk, r, &user, NULL)) {
        fprintf(stderr, "  expected ACCEPT\n");
        goto done;
    }
    ok = 1;

 done:
    user_clear(&user);
    EC_POINT_free(w);
    EC_POINT_free(acc);
    BN_clear_free(r);
    EVP_PKEY_free(sk);
    EVP_MD_free(sig_md);
    OPENSSL_free(sig_digest);
    return ok;
}

static int demo_with_revocation(const EC_GROUP *group, EVP_MD *md)
{
    static const unsigned char uid_a[] = "alice@example.com";
    static const unsigned char uid_b[] = "bob@example.com";
    EVP_MD *sig_md = NULL;
    EVP_PKEY *sk = NULL;
    BIGNUM *r = NULL, *revoked_m = NULL;
    EC_POINT *w = NULL, *acc = NULL;
    char *sig_digest = NULL;
    unsigned char *crl_blob = NULL;
    PAEA_CRL_ENTRY *crl = NULL;
    USER alice, bob;
    size_t crl_len = 0, crl_alloc = 0, blob_len = 0;
    int ok = 0;

    memset(&alice, 0, sizeof(alice));
    memset(&bob, 0, sizeof(bob));
    printf("with revocation\n");
    if (!paea_zyhw_setup(group, "SM2", NULL, NULL, NULL, NULL, 1,
                         &r, &w, &acc, &sk, &sig_digest))
        goto done;
    sig_md = EVP_MD_fetch(NULL, sig_digest, NULL);
    if (sig_md == NULL
        || !register_user(group, md, r, acc, crl_len, uid_a, 1, &alice)
        || !register_user(group, md, r, acc, crl_len, uid_b, 1, &bob))
        goto done;

    printf("  before revoke\n");
    if (!authenticate(group, md, sig_md, sk, r, &alice, acc)
        || !authenticate(group, md, sig_md, sk, r, &bob, acc)) {
        fprintf(stderr, "  expected ACCEPT\n");
        goto done;
    }

    revoked_m = BN_new();
    if (revoked_m == NULL
        || !paea_m_of_uid(md, group, uid_a, sizeof(uid_a) - 1, revoked_m)
        || !paea_crl_revoke(group, r, &acc, &crl, &crl_len, &crl_alloc,
                            revoked_m))
        goto done;
    printf("  alice revoked\n");
    if (authenticate(group, md, sig_md, sk, r, &alice, acc)) {
        fprintf(stderr, "  revoked user was accepted\n");
        goto done;
    }
    printf("  alice REJECT\n");

    if (!paea_encode_crl_blob(group, crl, crl_len, &crl_blob, &blob_len)
        || !take_crl(group, &bob, crl_blob, blob_len)
        || !paea_zyhw_update_witness(group, bob.m, bob.witness,
                                     &bob.witness_idx, bob.crl, bob.crl_len))
        goto done;
    printf("  bob refreshed witness\n");
    if (!authenticate(group, md, sig_md, sk, r, &bob, acc)) {
        fprintf(stderr, "  expected ACCEPT\n");
        goto done;
    }
    ok = 1;

 done:
    user_clear(&alice);
    user_clear(&bob);
    paea_crl_entries_free(crl, crl_len);
    OPENSSL_free(crl_blob);
    BN_clear_free(revoked_m);
    EC_POINT_free(w);
    EC_POINT_free(acc);
    BN_clear_free(r);
    EVP_PKEY_free(sk);
    EVP_MD_free(sig_md);
    OPENSSL_free(sig_digest);
    return ok;
}

int main(void)
{
    EC_GROUP *group = NULL;
    EVP_MD *md = NULL;
    int rc = 1;

    group = group_by_name("SM2");
    md = EVP_MD_fetch(NULL, "SM3", NULL);
    if (group == NULL || md == NULL)
        goto err;
    if (!demo_without_revocation(group, md)
        || !demo_with_revocation(group, md))
        goto err;
    rc = 0;
    goto done;

 err:
    ERR_print_errors_fp(stderr);
 done:
    EC_GROUP_free(group);
    EVP_MD_free(md);
    return rc;
}
