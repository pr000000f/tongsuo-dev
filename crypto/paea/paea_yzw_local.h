/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#ifndef OSSL_PAEA_YZW_LOCAL_H
# define OSSL_PAEA_YZW_LOCAL_H
# include "paea_evp_local.h"
# include "paea_elgamal.h"
# include <openssl/pairing.h>
# include <openssl/rand.h>
# include <openssl/err.h>

enum { YZ_A, YZ_B, YZ_D, YZ_G, YZ_G0, YZ_G1, YZ_ACC_BASE, YZ_BASES };
enum { YZ_M, YZ_GAMMA, YZ_K, YZ_ALPHA, YZ_MU, YZ_BETA,
       YZ_ZETA, YZ_XI, YZ_ETA, YZ_SECRETS };
enum { YZ_EA, YZ_ED, YZ_EG0W, YZ_EG0H, YZ_EB, YZ_EG0WA, YZ_CACHE };
# define YZ_MAX_EVENTS 4096

typedef struct {
    unsigned char uid[32];
    BIGNUM *k;
    int active;
} YZ_USER;
typedef struct {
    int add;
    BIGNUM *k;
    EC_POINT *acc;
} YZ_EVENT;
typedef struct {
    BIGNUM *v[YZ_SECRETS], *mask[YZ_SECRETS], *ephemeral, *ns;
    EC_POINT *X, *Y, *T1, *T2, *R2, *T1r, *T2r, *R2r;
    PAIRING_GT *R1, *R1r, *be;
    unsigned char nu[64];
} YZ_SESSION;
typedef struct {
    EC_GROUP *group;
    EVP_MD *md;
    EC_POINT *base[YZ_BASES], *acc;
    PAIRING_G2 *h, *w, *wa;
    PAIRING_GT *cache[YZ_CACHE];
    PAEA_HE_KEY *he;
    BIGNUM *x, *chi;
    YZ_USER *users;
    size_t nusers;
    YZ_EVENT *events;
    size_t nevents;
    /* User credential: only mprime is password encrypted. */
    EC_POINT *credential, *witness;
    BIGNUM *k;
    unsigned char encrypted_m[64], iv[16], encrypted_s[768];
    uint32_t index;
    YZ_SESSION *session;
} YZW;
YZW *ossl_yzw_new(EVP_PAEA_CTX *ctx);
int ossl_yzw_cache(YZW *z);
void ossl_yzw_free(EVP_PAEA_CTX *ctx);
void ossl_yzw_reset(EVP_PAEA_CTX *ctx);
YZ_SESSION *ossl_yzw_session_new(YZW *z);
int ossl_yzw_setup(EVP_PAEA_CTX *ctx);
int ossl_yzw_export(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len);
int ossl_yzw_import(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len);
int ossl_yzw_issue(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                    unsigned char **out, size_t *len);
int ossl_yzw_store(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                    const unsigned char *pw, size_t pwlen, const unsigned char *in, size_t len);
int ossl_yzw_revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen);
int ossl_yzw_refresh(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *source);
int ossl_yzw_init(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                   unsigned char **out, size_t *len);
int ossl_yzw_step(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                   const unsigned char *in, size_t inlen, unsigned char **out, size_t *len);
int ossl_yzw_crypt(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                    const unsigned char iv[16], const unsigned char in[64], unsigned char out[64]);
int ossl_yzw_read_scalar(PAEA_READER *r, YZW *z, BIGNUM *n, int nonzero);
int ossl_yzw_put_gt(PAEA_BUF *b, const PAIRING_GT *a);
int ossl_yzw_read_gt(PAEA_READER *r, PAIRING_GT *a);
int ossl_yzw_put_g2(PAEA_BUF *b, const PAIRING_G2 *a);
int ossl_yzw_read_g2(PAEA_READER *r, PAIRING_G2 *a);
int ossl_yzw_equation(YZW *z, int rev, BIGNUM *const v[], PAIRING_GT *out);
int ossl_yzw_linear(YZW *z, EC_POINT *out, const EC_POINT *a, const BIGNUM *x,
                     const EC_POINT *b, const BIGNUM *y);
int ossl_yzw_mac(EVP_PAEA_CTX *ctx, unsigned char out[32]);
int ossl_yzw_session_key(EVP_PAEA_CTX *ctx);
int ossl_yzw_client_step(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t inlen,
                          unsigned char **out, size_t *len);
int ossl_yzw_export_credential(const EVP_PAEA_CTX *, unsigned char **, size_t *);
int ossl_yzw_import_credential(EVP_PAEA_CTX *, const unsigned char *, size_t);
#endif
