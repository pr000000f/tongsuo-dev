/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Portions of test vectors Copyright 2014-2024 The GmSSL Project.
 * Licensed under the Apache License 2.0. See LICENSE.txt.
 * SM9 signature example e(P1,ks*P2), GM/T 0044.2 appendix A.
 */
#include "testutil.h"
#include <openssl/pairing.h>
#include <openssl/err.h>
#ifndef OPENSSL_NO_PAEA
# include "crypto/paea/paea_elgamal.h"
#endif

static const char pairing_kat[] =
    "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"
    "28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000"
    "38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f"
    "a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db"
    "67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f"
    "5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6"
    "1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b"
    "93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439"
    "b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d"
    "4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b"
    "84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a"
    "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb";

static int test_pairing(void)
{
    EC_GROUP *g = PAIRING_GROUP_new_sm9();
    EC_POINT *p = NULL;
    PAIRING_G2 *q = PAIRING_G2_new(), *copy = PAIRING_G2_new();
    PAIRING_GT *t = PAIRING_GT_new(), *u = PAIRING_GT_new(), *v = PAIRING_GT_new();
    BIGNUM *a = BN_new(), *b = BN_new(), *ab = BN_new();
    BN_CTX *bn = BN_CTX_new();
    unsigned char buf[384], qb[129], *expected = NULL;
    long len;
    int rc = 0;

    if (!TEST_ptr(g) || !TEST_ptr(p = EC_POINT_new(g)) || !TEST_ptr(q) || !TEST_ptr(copy)
        || !TEST_ptr(t) || !TEST_ptr(u) || !TEST_ptr(v)
        || !TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(ab) || !TEST_ptr(bn)
        || !TEST_true(EC_GROUP_check(g, bn))
        || !TEST_true(BN_hex2bn(&a, "000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"))
        || !TEST_true(PAIRING_G2_generator(q)) || !TEST_true(PAIRING_G2_mul(q, q, a))
        || !TEST_true(PAIRING_apply(t, EC_GROUP_get0_generator(g), q))
        || !TEST_true(PAIRING_GT_to_bytes(t, buf))
        || !TEST_ptr(expected = OPENSSL_hexstr2buf(pairing_kat, &len))
        || !TEST_mem_eq(buf, sizeof(buf), expected, (size_t)len)
        || !TEST_true(PAIRING_GT_from_bytes(v, buf, sizeof(buf)))
        || !TEST_int_eq(PAIRING_GT_cmp(v, t), 0)
        || !TEST_true(PAIRING_G2_to_bytes(q, qb))
        || !TEST_true(PAIRING_G2_from_bytes(copy, qb, sizeof(qb)))
        || !TEST_true(PAIRING_apply(u, EC_GROUP_get0_generator(g), copy))
        || !TEST_int_eq(PAIRING_GT_cmp(u, t), 0))
        goto done;
    /* Bilinearity with unrelated scalars, plus inverse and identity. */
    if (!TEST_true(BN_set_word(a, 17)) || !TEST_true(BN_set_word(b, 31))
        || !TEST_true(BN_mul(ab, a, b, bn)) || !TEST_true(PAIRING_G2_generator(q))
        || !TEST_true(PAIRING_apply(t, EC_GROUP_get0_generator(g), q))
        || !TEST_true(PAIRING_GT_pow(t, t, ab)) || !TEST_true(PAIRING_G2_mul(q, q, b))
        || !TEST_true(EC_POINT_mul(g, p, a, NULL, NULL, bn))
        || !TEST_true(PAIRING_apply(u, p, q)) || !TEST_int_eq(PAIRING_GT_cmp(t, u), 0)
        || !TEST_true(PAIRING_GT_inv(u, u)) || !TEST_true(PAIRING_GT_mul(t, t, u)))
        goto done;
    BN_zero(a);
    if (!TEST_true(PAIRING_GT_pow(v, v, a)) || !TEST_int_eq(PAIRING_GT_cmp(t, v), 0)
        || !TEST_false(PAIRING_GT_pow(v, v, EC_GROUP_get0_order(g)))
        || !TEST_false(PAIRING_G2_from_bytes(copy, qb, 128))
        || !TEST_false(PAIRING_GT_from_bytes(v, buf, 383)))
        goto done;
    ERR_clear_error();
    memset(buf, 0, sizeof(buf)); buf[383] = 2; /* Fp element 2 is not in GT. */
    memset(qb + 1, 255, 32); /* noncanonical Fp2 coordinate */
    if (!TEST_false(PAIRING_GT_from_bytes(v, buf, sizeof(buf)))
        || !TEST_false(PAIRING_G2_from_bytes(copy, qb, sizeof(qb))))
        goto done;
    ERR_clear_error();
    rc = 1;
 done:
    OPENSSL_free(expected); BN_free(a); BN_free(b); BN_free(ab); BN_CTX_free(bn);
    PAIRING_G2_free(q); PAIRING_G2_free(copy); PAIRING_GT_free(t); PAIRING_GT_free(u); PAIRING_GT_free(v);
    EC_POINT_free(p); EC_GROUP_free(g);
    return rc;
}

#ifndef OPENSSL_NO_PAEA
static int test_multiplicative_elgamal(void)
{
    EC_GROUP *g = PAIRING_GROUP_new_sm9();
    PAEA_HE_KEY *key = ossl_paea_he_new(), *pub = ossl_paea_he_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new(), *b = BN_new(), *product = BN_new(), *got = BN_new();
    unsigned char pk[384], ca[768], cb[768], cc[768];
    int rc = 0;

    if (!TEST_ptr(g) || !TEST_ptr(key) || !TEST_ptr(pub) || !TEST_ptr(ctx)
        || !TEST_ptr(a) || !TEST_ptr(b) || !TEST_ptr(product) || !TEST_ptr(got)
        || !TEST_true(ossl_paea_he_generate(key))
        || !TEST_int_eq(BN_bn2binpad(key->pub, pk, 384), 384)
        || !TEST_true(ossl_paea_he_set_public(pub, pk))
        || !TEST_ptr(BN_copy(a, EC_GROUP_get0_order(g))) || !TEST_true(BN_sub_word(a, 1))
        || !TEST_ptr(BN_copy(b, a)) || !TEST_true(BN_sub_word(b, 1))
        || !TEST_true(BN_mul(product, a, b, ctx))
        || !TEST_int_gt(BN_cmp(product, EC_GROUP_get0_order(g)), 0)
        || !TEST_true(ossl_paea_he_encrypt(pub, a, ca))
        || !TEST_true(ossl_paea_he_encrypt(pub, b, cb))
        || !TEST_true(ossl_paea_he_mul(pub, ca, cb, cc))
        || !TEST_true(ossl_paea_he_decrypt(key, cc, got))
        || !TEST_BN_eq(product, got))
        goto done;
    memset(cc, 0, 384); cc[383] = 1;
    if (!TEST_false(ossl_paea_he_decrypt(key, cc, got))
        || !TEST_false(ossl_paea_he_encrypt(pub, key->p, ca)))
        goto done;
    ERR_clear_error();
    BN_zero(a);
    if (!TEST_false(ossl_paea_he_encrypt(pub, a, ca)))
        goto done;
    ERR_clear_error(); rc = 1;
 done:
    EC_GROUP_free(g); ossl_paea_he_free(key); ossl_paea_he_free(pub); BN_CTX_free(ctx);
    BN_free(a); BN_free(b); BN_free(product); BN_free(got);
    return rc;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_pairing);
#ifndef OPENSSL_NO_PAEA
    ADD_TEST(test_multiplicative_elgamal);
#endif
    return 1;
}
