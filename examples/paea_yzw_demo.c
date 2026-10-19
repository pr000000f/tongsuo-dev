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
 * Standalone YZW demo using only public EVP_PAEA APIs (SM9-BN256 / SM3).
 * Pairing and multiplicative finite-field ElGamal are handled by the library.
 * Build with enable-paea enable-pairing, then:
 *   make -C examples paea_yzw_demo
 *   ./examples/paea_yzw_demo
 *
 * Messages are passed in memory instead of over a network. Public parameters
 * must be authenticated; registration data also needs confidentiality.
 * The fixed passwords below are test fixtures, not application input handling.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>
#include <openssl/params.h>

#if defined(OPENSSL_NO_PAEA) || defined(OPENSSL_NO_PAIRING)
# error "Configure Tongsuo with enable-paea enable-pairing for this demo"
#endif

static const unsigned char uid[] = "alice@example.test";
static const unsigned char password[] = "demo correct password";
static const unsigned char wrong_password[] = "demo wrong password";

/* Return 1 only when the observed outcome matches this test case. */
static int authenticate(EVP_PAEA_CTX *server, EVP_PAEA_CTX *client,
                        const unsigned char *pw, size_t pwlen,
                        int tamper, int expect_reject)
{
    unsigned char *m1 = NULL, *m2 = NULL, *m3 = NULL, *out = NULL;
    unsigned char server_key[EVP_MAX_MD_SIZE], client_key[EVP_MAX_MD_SIZE];
    size_t m1len = 0, m2len = 0, m3len = 0, outlen = 0;
    size_t server_keylen = sizeof(server_key), client_keylen = sizeof(client_key);
    unsigned long error;
    const char *stage = "client creates M1";
    int rc = 0;

    /* A failed exchange is consumed. Reset both sides before a new attempt. */
    EVP_PAEA_auth_reset(server);
    EVP_PAEA_auth_reset(client);
    ERR_clear_error();

    /* M1: client -> server. The password is used only on the client. */
    if (!EVP_PAEA_auth_init(client, pw, pwlen, &m1, &m1len))
        goto done;
    printf("  M1 client -> server: %zu bytes\n", m1len);

    /* M2: server -> client, carrying the server challenge and MAC. */
    stage = "server processes M1 and creates M2";
    if (!EVP_PAEA_auth_step(server, NULL, 0, m1, m1len, &m2, &m2len))
        goto done;
    printf("  M2 server -> client: %zu bytes\n", m2len);
    if (tamper) {
        if (m2len == 0)
            goto done;
        m2[m2len - 1] ^= 1;
        puts("  Test injection: changed one bit of the server MAC.");
    }

    /* Client verifies the server MAC before releasing its final proof. */
    stage = "client verifies M2 and creates M3";
    if (!EVP_PAEA_auth_step(client, NULL, 0, m2, m2len, &m3, &m3len))
        goto rejected;
    printf("  M3 client -> server: %zu bytes\n", m3len);

    /* Server verifies M3. Completion produces no further protocol message. */
    stage = "server verifies M3";
    if (!EVP_PAEA_auth_step(server, NULL, 0, m3, m3len, &out, &outlen))
        goto rejected;
    if (expect_reject || out != NULL || outlen != 0) {
        fprintf(stderr, "Unexpected server acceptance or final output\n");
        goto done;
    }

    /* Client proof completion alone does not establish server acceptance. */
    stage = "compare session keys";
    if (!EVP_PAEA_get_session_key(server, server_key, &server_keylen)
        || !EVP_PAEA_get_session_key(client, client_key, &client_keylen)
        || server_keylen != 32 || client_keylen != server_keylen
        || CRYPTO_memcmp(server_key, client_key, server_keylen) != 0)
        goto done;
    printf("  [PASS] Authentication accepted; session keys match (%zu bytes).\n",
           server_keylen);
    rc = 1;
    goto done;

 rejected:
    /* Do not mistake initialization or state errors for proof rejection. */
    error = ERR_peek_last_error();
    if (!expect_reject || ERR_GET_LIB(error) != ERR_LIB_PAEA
        || ERR_GET_REASON(error) != PAEA_R_VERIFY_FAILED)
        goto done;
    ERR_clear_error();
    if (EVP_PAEA_get_session_key(server, server_key, &server_keylen)) {
        fprintf(stderr, "Rejected exchange exposed a server session key\n");
        goto done;
    }
    ERR_clear_error();
    printf("  [PASS] Rejected at '%s'; no server session key.\n", stage);
    rc = 1;

 done:
    if (!rc) {
        fprintf(stderr, "[FAIL] YZW: %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    OPENSSL_free(m1);
    OPENSSL_free(m2);
    OPENSSL_free(m3);
    OPENSSL_free(out);
    OPENSSL_cleanse(server_key, sizeof(server_key));
    OPENSSL_cleanse(client_key, sizeof(client_key));
    return rc;
}

int main(void)
{
    EVP_PAEA_CTX *server = NULL, *client = NULL;
    unsigned char *issued = NULL, *public_data = NULL;
    size_t issuedlen = 0, public_len = 0;
    char group[] = "SM9-BN256", digest[] = "SM3";
    int revocation = 1, rc = EXIT_FAILURE;
    unsigned long error;
    const char *stage = "setup";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("group", group, sizeof(group)),
        OSSL_PARAM_utf8_string("digest", digest, sizeof(digest)),
        OSSL_PARAM_int("revocation", &revocation),
        OSSL_PARAM_END
    };

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("YZW demo: SM9-BN256 / SM3, finite-field ElGamal, revocation enabled");
    server = EVP_PAEA_CTX_new_ex(NULL, "YZW", NULL);
    if (server == NULL || !EVP_PAEA_CTX_set_params(server, params)
        || !EVP_PAEA_setup(server))
        goto done;

    /*
     * Registration changes the YZW accumulator. Export public parameters
     * AFTER issuance, so the client imports the matching accumulator state.
     * Transfer issued data confidentially to this user.
     */
    stage = "register and store credential";
    if (!EVP_PAEA_issue_credential(server, uid, sizeof(uid) - 1,
                                   &issued, &issuedlen)
        || !EVP_PAEA_export_public(server, &public_data, &public_len))
        goto done;
    client = EVP_PAEA_CTX_new_ex(NULL, "YZW", NULL);
    if (client == NULL
        || !EVP_PAEA_import_public(client, public_data, public_len)
        || !EVP_PAEA_store_credential(client, uid, sizeof(uid) - 1,
                                       password, sizeof(password) - 1,
                                       issued, issuedlen))
        goto done;
    OPENSSL_clear_free(issued, issuedlen);
    issued = NULL;
    puts("[PASS] Registered Alice; password-wrapped credential stored locally.");

    stage = "authentication cases";
    puts("\n1. Correct password");
    if (!authenticate(server, client, password, sizeof(password) - 1, 0, 0))
        goto done;
    puts("\n2. Wrong password");
    if (!authenticate(server, client, wrong_password,
                       sizeof(wrong_password) - 1, 0, 1))
        goto done;
    puts("\n3. Tampered server MAC");
    if (!authenticate(server, client, password, sizeof(password) - 1, 1, 1))
        goto done;
    puts("\n4. Fresh authentication after failed attempts");
    if (!authenticate(server, client, password, sizeof(password) - 1, 0, 0))
        goto done;

    /* Revocation requires ready contexts, not a completed/in-flight session. */
    stage = "revoke Alice";
    EVP_PAEA_auth_reset(server);
    EVP_PAEA_auth_reset(client);
    if (!EVP_PAEA_revoke(server, uid, sizeof(uid) - 1))
        goto done;
    puts("\n5. Revoked user cannot refresh its witness");
    ERR_clear_error();
    if (EVP_PAEA_refresh(client, server)) {
        fprintf(stderr, "Revoked credential unexpectedly refreshed\n");
        goto done;
    }
    error = ERR_peek_last_error();
    if (ERR_GET_LIB(error) != ERR_LIB_PAEA
        || ERR_GET_REASON(error) != PAEA_R_WITNESS_INVALID)
        goto done;
    ERR_clear_error();
    puts("  [PASS] Witness refresh rejected.");

    /* Failed refresh leaves the old credential; it must still be rejected. */
    stage = "authenticate with revoked credential";
    puts("\n6. Revoked user attempts authentication with its old credential");
    if (!authenticate(server, client, password, sizeof(password) - 1, 0, 1))
        goto done;
    puts("\nYZW: all demo checks passed.");
    rc = EXIT_SUCCESS;

 done:
    if (rc != EXIT_SUCCESS) {
        fprintf(stderr, "[FAIL] YZW demo: %s\n", stage);
        ERR_print_errors_fp(stderr);
    }
    OPENSSL_clear_free(issued, issuedlen);
    OPENSSL_free(public_data);
    EVP_PAEA_CTX_free(client);
    EVP_PAEA_CTX_free(server);
    return rc;
}
