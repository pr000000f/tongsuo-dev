/* Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0. See LICENSE.txt. */
#ifndef OSSL_PAEA_EVP_LOCAL_H
# define OSSL_PAEA_EVP_LOCAL_H
# include "paea_local.h"
# include <openssl/paeaerr.h>
# include <openssl/params.h>

typedef struct paea_method_st PAEA_METHOD;
struct evp_paea_ctx_st {
    const PAEA_METHOD *meth;
    OSSL_LIB_CTX *libctx;
    char *propq;
    char group[80], digest[80];
    int revocation, server, stage;
    void *data;
    unsigned char key[EVP_MAX_MD_SIZE];
    size_t keylen;
};
struct paea_method_st {
    const char *name;
    void (*free)(EVP_PAEA_CTX *ctx);
    int (*setup)(EVP_PAEA_CTX *ctx);
    int (*export_public)(const EVP_PAEA_CTX *ctx, unsigned char **out, size_t *len);
    int (*import_public)(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t len);
    int (*issue)(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                 unsigned char **out, size_t *len);
    int (*store)(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen,
                 const unsigned char *pw, size_t pwlen,
                 const unsigned char *in, size_t len);
    int (*revoke)(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen);
    int (*refresh)(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *source);
    int (*init)(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                unsigned char **out, size_t *len);
    int (*step)(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                const unsigned char *in, size_t inlen,
                unsigned char **out, size_t *len);
    void (*reset)(EVP_PAEA_CTX *ctx);
    int (*export_credential)(const EVP_PAEA_CTX *, unsigned char **, size_t *);
    int (*import_credential)(EVP_PAEA_CTX *, const unsigned char *, size_t);
};
extern const PAEA_METHOD ossl_paea_zyhw_method;
# ifndef OPENSSL_NO_PAIRING
extern const PAEA_METHOD ossl_paea_yzw_method;
# endif

/* Private, bounded public-parameter framing. All variable-width fields
 * have u32 lengths. Parsers must consume the complete input. */
typedef struct { unsigned char *buf; size_t len, cap; } PAEA_BUF;
typedef struct { const unsigned char *p; size_t len; } PAEA_READER;
int ossl_paea_put(PAEA_BUF *b, const void *p, size_t len);
int ossl_paea_get(PAEA_READER *r, const unsigned char **p, size_t *len);
int ossl_paea_put_point(PAEA_BUF *b, const EC_GROUP *g, const EC_POINT *p);
int ossl_paea_read_point(PAEA_READER *r, const EC_GROUP *g, EC_POINT *p);
int ossl_paea_put_bn(PAEA_BUF *b, const BIGNUM *n, size_t width);
int ossl_paea_read_bn(PAEA_READER *r, BIGNUM *n, size_t width);
int ossl_paea_key(EVP_PAEA_CTX *ctx, unsigned char *key, size_t len);
#endif
