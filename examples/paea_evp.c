/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#include <stdio.h>
#include <string.h>
#include <openssl/paea.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* In-memory example only: transport and public-parameter trust are external.
 * Registration plaintext is secret; do not log it or put it in a directory. */
int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "YZW";
    const unsigned char uid[] = "alice", pw[] = "example password";
    EVP_PAEA_CTX *server = NULL, *user = NULL;
    unsigned char *issued = NULL, *m1 = NULL, *m2 = NULL, *m3 = NULL, *out = NULL;
    unsigned char sk[64], uk[64];
    size_t ni = 0, n1 = 0, n2 = 0, n3 = 0, no = 0, ns = sizeof(sk), nu = sizeof(uk);
    int rev = 1, rc = 1;
    OSSL_PARAM params[] = { OSSL_PARAM_int("revocation", &rev), OSSL_PARAM_END };

    server = EVP_PAEA_CTX_new_ex(NULL, name, NULL);
    if (server == NULL || !EVP_PAEA_CTX_set_params(server, params)
        || !EVP_PAEA_setup(server)
        || !EVP_PAEA_issue_credential(server, uid, sizeof(uid)-1, &issued, &ni)
        || (user = EVP_PAEA_CTX_dup_public(server)) == NULL
        || !EVP_PAEA_store_credential(user, uid, sizeof(uid)-1, pw, sizeof(pw)-1, issued, ni))
        goto done;
    OPENSSL_clear_free(issued, ni); issued = NULL;
    if (strcmp(EVP_PAEA_CTX_get0_name(server), "YZW") == 0) {
        if (!EVP_PAEA_auth_init(user, pw, sizeof(pw)-1, &m1, &n1)
            || !EVP_PAEA_auth_step(server, NULL, 0, m1, n1, &m2, &n2)
            || !EVP_PAEA_auth_step(user, NULL, 0, m2, n2, &m3, &n3)
            || !EVP_PAEA_auth_step(server, NULL, 0, m3, n3, &out, &no))
            goto done;
    } else {
        if (!EVP_PAEA_auth_init(server, NULL, 0, &m1, &n1)
            || !EVP_PAEA_auth_step(user, pw, sizeof(pw)-1, m1, n1, &m2, &n2)
            || !EVP_PAEA_auth_step(server, NULL, 0, m2, n2, &out, &no))
            goto done;
    }
    if (!EVP_PAEA_get_session_key(server, sk, &ns)
        || !EVP_PAEA_get_session_key(user, uk, &nu)
        || ns != nu || CRYPTO_memcmp(sk, uk, ns))
        goto done;
    printf("%s: authentication succeeded; session keys match (%zu bytes).\n", name, ns);
    EVP_PAEA_auth_reset(server); EVP_PAEA_auth_reset(user);
    if (!EVP_PAEA_revoke(server, uid, sizeof(uid)-1)
        || EVP_PAEA_refresh(user, server))
        goto done;
    ERR_clear_error();
    puts("Revoked credential: witness refresh rejected as expected.");
    rc = 0;
 done:
    if (rc != 0)
        ERR_print_errors_fp(stderr);
    OPENSSL_clear_free(issued, ni);
    OPENSSL_free(m1); OPENSSL_free(m2); OPENSSL_free(m3); OPENSSL_free(out);
    OPENSSL_cleanse(sk, sizeof(sk)); OPENSSL_cleanse(uk, sizeof(uk));
    EVP_PAEA_CTX_free(user); EVP_PAEA_CTX_free(server);
    return rc;
}
