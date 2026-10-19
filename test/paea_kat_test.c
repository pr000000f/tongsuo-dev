/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt.
 * Synthetic KAT only; fixed randomness must never be used in applications. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/paea.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* Fixed randomness is confined to this test process and a dedicated libctx.
 * Each stage and RNG stream gets 65536 bytes:
 * SHA256(ASCII(label) || U32_BE(0)) || ... || SHA256(... || U32_BE(2047)).
 * label = PAEA-KAT-v1|<mechanism>|r<0/1>|<stage>|<stream>|
 * This is a reproducible implementation KAT, not an official standard vector.
 */
static int generate;

static int seed_stage(OSSL_LIB_CTX *ctx, const char *name, int rev,
                      const char *stage)
{
    static const char *streams[] = { "primary", "public", "private" };
    EVP_RAND_CTX *rng[3];
    unsigned char input[256], *tape = OPENSSL_malloc(65536);
    unsigned int strength = 256;
    size_t n, len;
    int i, j, rc = 0;
    OSSL_PARAM params[3];

    rng[0] = RAND_get0_primary(ctx);
    rng[1] = RAND_get0_public(ctx);
    rng[2] = RAND_get0_private(ctx);
    if (tape == NULL)
        goto done;
    for (i = 0; i < 3; i++) {
        j = snprintf((char *)input, sizeof(input), "PAEA-KAT-v1|%s|r%d|%s|%s|",
                     name, rev, stage, streams[i]);
        if (rng[i] == NULL || j < 0 || (size_t)j + 4 > sizeof(input))
            goto done;
        len = (size_t)j;
        for (n = 0; n < 2048; n++) {
            input[len] = (unsigned char)(n >> 24);
            input[len + 1] = (unsigned char)(n >> 16);
            input[len + 2] = (unsigned char)(n >> 8);
            input[len + 3] = (unsigned char)n;
            if (!EVP_Q_digest(ctx, "SHA256", NULL, input, len + 4,
                              tape + 32 * n, NULL))
                goto done;
        }
        params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,
                                               &strength);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_RAND_PARAM_TEST_ENTROPY, tape, 65536);
        params[2] = OSSL_PARAM_construct_end();
        if (!EVP_RAND_CTX_set_params(rng[i], params))
            goto done;
    }
    rc = 1;
 done:
    OPENSSL_clear_free(tape, 65536);
    return rc;
}

/* Normal runs open frozen answers read-only and compare every byte. */
static int check(const char *dir, const char *mechanism, int rev,
                 const char *kind, const unsigned char *data, size_t len)
{
    char path[1024];
    FILE *f;
    size_t i;
    int n, rc = 1;

    n = snprintf(path, sizeof(path), "%s/%s-r%d-%s.bin",
                 dir, mechanism, rev, kind);
    if (n < 0 || (size_t)n >= sizeof(path)
        || (f = fopen(path, generate ? "wb" : "rb")) == NULL) {
        fprintf(stderr, "Cannot open KAT: %s/%s-r%d-%s.bin\n",
                dir, mechanism, rev, kind);
        return 0;
    }
    if (generate) {
        rc = fwrite(data, 1, len, f) == len;
    } else {
        for (i = 0; i < len; i++) {
            if (fgetc(f) != data[i]) {
                fprintf(stderr, "KAT mismatch: %s at byte %zu\n", path, i);
                rc = 0;
                break;
            }
        }
        if (rc && fgetc(f) != EOF) {
            fprintf(stderr, "KAT length mismatch: %s\n", path);
            rc = 0;
        }
    }
    if (ferror(f))
        rc = 0;
    if (fclose(f) != 0)
        rc = 0;
    return rc;
}

static int run_case(const char *dir, const char *name, int rev)
{
    static const unsigned char uid[] = "kat-alice";
    static const unsigned char pw[] = "kat-test-password";
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new(), *previous = NULL;
    EVP_PAEA_CTX *s = NULL, *u = NULL;
    unsigned char *issued = NULL, *pub = NULL, *cred = NULL;
    unsigned char *m1 = NULL, *m2 = NULL, *m3 = NULL, *out = NULL;
    unsigned char *updated = NULL;
    size_t ni = 0, np = 0, nc = 0, n1 = 0, n2 = 0, n3 = 0, no = 0, nr = 0;
    unsigned char sk[64], uk[64];
    size_t ns = sizeof(sk), nu = sizeof(uk);
    OSSL_PARAM params[] = {
        OSSL_PARAM_int("revocation", &rev), OSSL_PARAM_END
    };
    int rc = 0, yzw = strcmp(name, "YZW") == 0;

    if (libctx == NULL)
        goto done;
    previous = OSSL_LIB_CTX_set0_default(libctx);
    if (!RAND_set_DRBG_type(libctx, "TEST-RAND", "provider=default", NULL, NULL)
        || !seed_stage(libctx, name, rev, "setup"))
        goto done;
    s = EVP_PAEA_CTX_new_ex(libctx, name, NULL);
    u = EVP_PAEA_CTX_new_ex(libctx, name, NULL);
    if (s == NULL || u == NULL || !EVP_PAEA_CTX_set_params(s, params)
        || !EVP_PAEA_setup(s)
        || !seed_stage(libctx, name, rev, "issue")
        || !EVP_PAEA_issue_credential(s, uid, sizeof(uid) - 1, &issued, &ni)
        || !EVP_PAEA_export_public(s, &pub, &np)
        || !EVP_PAEA_import_public(u, pub, np)
        || !seed_stage(libctx, name, rev, "store")
        || !EVP_PAEA_store_credential(u, uid, sizeof(uid) - 1,
                                       pw, sizeof(pw) - 1, issued, ni)
        || !EVP_PAEA_export_credential(u, &cred, &nc))
        goto done;
    if (!seed_stage(libctx, name, rev, "m1"))
        goto done;
    if (yzw) {
        if (!EVP_PAEA_auth_init(u, pw, sizeof(pw) - 1, &m1, &n1)
            || !seed_stage(libctx, name, rev, "m2")
            || !EVP_PAEA_auth_step(s, NULL, 0, m1, n1, &m2, &n2)
            || !seed_stage(libctx, name, rev, "m3")
            || !EVP_PAEA_auth_step(u, NULL, 0, m2, n2, &m3, &n3)
            || !seed_stage(libctx, name, rev, "verify")
            || !EVP_PAEA_auth_step(s, NULL, 0, m3, n3, &out, &no))
            goto done;
    } else {
        if (!EVP_PAEA_auth_init(s, NULL, 0, &m1, &n1)
            || !seed_stage(libctx, name, rev, "m2")
            || !EVP_PAEA_auth_step(u, pw, sizeof(pw) - 1, m1, n1, &m2, &n2)
            || !seed_stage(libctx, name, rev, "verify")
            || !EVP_PAEA_auth_step(s, NULL, 0, m2, n2, &out, &no))
            goto done;
    }
    if (out != NULL || no != 0
        || !EVP_PAEA_get_session_key(s, sk, &ns)
        || !EVP_PAEA_get_session_key(u, uk, &nu)
        || ns != 32 || nu != ns || CRYPTO_memcmp(sk, uk, ns) != 0
        || !check(dir, name, rev, "public", pub, np)
        || !check(dir, name, rev, "issued", issued, ni)
        || !check(dir, name, rev, "credential", cred, nc)
        || !check(dir, name, rev, "m1", m1, n1)
        || !check(dir, name, rev, "m2", m2, n2)
        || (yzw && !check(dir, name, rev, "m3", m3, n3))
        || !check(dir, name, rev, "session-key", sk, ns))
        goto done;
    if (rev) {
        EVP_PAEA_auth_reset(s);
        EVP_PAEA_auth_reset(u);
        if (!seed_stage(libctx, name, rev, "revoke")
            || !EVP_PAEA_revoke(s, uid, sizeof(uid) - 1)
            || !EVP_PAEA_export_public(s, &updated, &nr)
            || !check(dir, name, rev, "public-revoked", updated, nr))
            goto done;
    }
    printf("%s revocation=%d: %s\n", name, rev,
           generate ? "answers generated" : "KAT PASS (all bytes match)");
    rc = 1;
 done:
    if (!rc)
        ERR_print_errors_fp(stderr);
    OPENSSL_clear_free(issued, ni);
    OPENSSL_clear_free(cred, nc);
    OPENSSL_free(pub);
    OPENSSL_free(updated);
    OPENSSL_free(m1);
    OPENSSL_free(m2);
    OPENSSL_free(m3);
    OPENSSL_free(out);
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(uk, sizeof(uk));
    EVP_PAEA_CTX_free(s);
    EVP_PAEA_CTX_free(u);
    if (libctx != NULL)
        OSSL_LIB_CTX_set0_default(previous);
    OSSL_LIB_CTX_free(libctx);
    return rc;
}

int main(int argc, char **argv)
{
    const char *dir;

    if (argc == 3 && strcmp(argv[1], "--generate") == 0) {
        generate = 1;
        dir = argv[2];
    } else if (argc == 2) {
        dir = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [--generate] KAT_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!run_case(dir, "ZYHW", 0) || !run_case(dir, "ZYHW", 1))
        return EXIT_FAILURE;
#ifndef OPENSSL_NO_PAIRING
    if (!run_case(dir, "YZW", 0) || !run_case(dir, "YZW", 1))
        return EXIT_FAILURE;
#endif
    return EXIT_SUCCESS;
}
