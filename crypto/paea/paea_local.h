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

#ifndef OSSL_CRYPTO_PAEA_LOCAL_H
# define OSSL_CRYPTO_PAEA_LOCAL_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_PAEA

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/params.h>
# include <openssl/paea.h>
# include "crypto/paeaerr.h"

/*
 * ZYHW mechanism (GB/T 34953.4-XXXX, 7.3), based on the auxiliary storage
 * PAEA model.  In the elliptic curve instanti
ation the multiplicative
 * notation of the standard text maps to the EC additive group as follows:
 *
 *   g^k          -> k * g          (generator g = generator of the curve)
 *   g1 * g2      -> G1 + G2
 *   g1 / g2      -> G1 - G2
 *   x^(1/y)      -> x * 1/y        (scalars reduced mod q, the group order)
 *
 * Cross reference to the standard text:
 *   7.3.2 setup:          r, w = g^r, revocation key ACC(r) = chi,
 *                         ACC(w) = g^chi, signing key pair (pk, sk)
 *   7.3.3 registration:   m = BS2IP(H_lamda(I_U)) mod q,
 *                         sigma = (1/(r+m)) * g,
 *                         sigma_pw = sigma + H_g(pw),
 *                         W = (1/(chi+m)) * B_n   (revocation only)
 *   7.3.4 authentication: 3-pass protocol Sign_sk / ZK proof of (m, a, ...)
 *   7.3.5 revocation:     CRL = { <m_i, B_i> }, with
 *                         B_i = (1/prod_{j<=i}(chi+m_j)) * g   (B_n = g on an
 *                         empty CRL, i.e. the empty product is 1), and the
 *                         witness update W' = (W - B_{j+1}) * 1/(m_{j+1}-m)
 *
 * Wire encoding (not specified by the standard, see the accompanying
 * implementation notes): every variable-size field is prefixed by a 4-byte
 * big-endian length ("TL"), group elements use the SEC1/GB-T 32918.1
 * uncompressed point encoding and integers are fixed-size big-endian
 * ("I2OSP", left zero padded to the byte size of q).
 */

/*
 * Object format version for the serialised blobs (params/servkey/crl/
 * credential).  Bumped whenever the internal layout changes.
 */
# define PAEA_BLOB_VERSION          1

/*
 * Maximum number of retries for the hash-to-group "try and increment"
 * construction of H_g().  2^256 attempts are way beyond a collision, 64
 * is already overkill for any sane curve.
 */
# define PAEA_MAX_HG_TRIES           64

/* Reasonable sanity limits for parsed blobs and CRLs */
# define PAEA_MAX_BLOB_LEN           (1 << 20)
# define PAEA_MAX_CRL_ENTRIES       (1 << 20)

/*
 * SM2 signing user id used in this implementation (both ends fixed by
 * the params blob implicitly; the distinguiding identifier default of
 * GB/T 32918.2 is "1234567812345678").
 */
# define PAEA_SM2_DEFAULT_ID         "1234567812345678"

typedef struct paea_crl_entry_st {
    BIGNUM *m;                      /* m_i = BS2IP(H_lamda(I_{U_i})) mod q */
    EC_POINT *b;                    /* B_i = (1/prod_{j<=i}(chi+m_j)) * g */
} PAEA_CRL_ENTRY;

struct evp_paea_ctx_st {
    OSSL_LIB_CTX *libctx;
    char *propq;

    int mechanism;                   /* NID_zyhw_mechanism, ... */

    /* The prime order cyclic group G, with generator g and order q. */
    EC_GROUP *group;
    BIGNUM *q;                      /* group order q */
    BIGNUM *cofactor;
    size_t qlen;                    /* byte length of q (I2OSP width) */
    EC_POINT *gpt;                  /* g, own reference (not const) */

    /* H_lamda and the signing scheme used by the server. */
    EVP_MD *md;
    EVP_MD *sig_md;                  /* digest bound to the signature scheme */
    char *digest_name;
    char *sig_type;                 /* "SM2" or "EC" */
    char *sig_digest_name;
    char *sig_curve_name;           /* curve for the generated EC signing key */
    EVP_PKEY *sig_key;              /* server: sk, user: pk */

    /* Public parameters (server generated, user imports them) */
    EC_POINT *w;                    /* w = r * g */
    int revocation;                 /* revocation support enabled */
    EC_POINT *acc_w;                /* ACC(w) = chi * g, revocation only */
    EC_POINT *acc;                  /* current B_n accumulator value */

    /* Server private material (absent on the user side) */
    BIGNUM *r;                      /* ServK r */
    BIGNUM *acckey;                 /* ACC(r) = chi, revocation only */

    /* The server maintained CRL (also mirrored on the user side for
     * witness updates). */
    PAEA_CRL_ENTRY *crl;
    size_t crl_len;
    size_t crl_alloc;

    /* User material */
    unsigned char *uid;
    size_t uid_len;
    BIGNUM *m;                      /* m for uid */
    EC_POINT *sigma_pw;              /* password wrapped credential */
    EC_POINT *witness;               /* W, revocation only */
    uint32_t witness_crl_index;      /* CRL size W was issued with */

    /* Session state, one authentication exchange per ctx */
    int srv_pend;                   /* server: msg1 pending (y alive) */
    BIGNUM *sess_y;
    EC_POINT *sess_y_pt;             /* y * g */
    unsigned char *sess_sig;        /* exact bytes of sigma_S */
    size_t sess_sig_len;

    int accepted;
    unsigned char *sk;               /* session key */
    size_t sk_len;

    /* Bookkeeping */
    int params_ready;               /* group/md/w/scheme in place (setup or import) */
    int server_secret;              /* r (and chi when enabled) available */
};

/*
 * Internal flags encoded in the presence of pointers above; helpers below.
 */

/* paea_common.c */
void paea_ctx_clear_group(EVP_PAEA_CTX *ctx);
void paea_ctx_clear_credential(EVP_PAEA_CTX *ctx);
void paea_ctx_clear_session(EVP_PAEA_CTX *ctx);
int paea_ctx_set_group_by_name(EVP_PAEA_CTX *ctx, const char *group_name);
int paea_ctx_install_group(EVP_PAEA_CTX *ctx, EC_GROUP *group);
int paea_ctx_set_md_by_name(EVP_PAEA_CTX *ctx, const char *digest_name);
int paea_ctx_setup_crl(EVP_PAEA_CTX *ctx, int capacity);
void paea_ctx_clear_crl(EVP_PAEA_CTX *ctx);

/* Simple growable buffer with TL (length prefix) helpers. */
typedef struct paea_buf_st {
    unsigned char *data;
    size_t len;
    size_t alloc;
    int error;                       /* sticky error flag */
} PAEA_BUF;

int paea_buf_init(PAEA_BUF *b);
void paea_buf_cleanup(PAEA_BUF *b);
unsigned char *paea_buf_release(PAEA_BUF *b, size_t *len);
int paea_buf_u8(PAEA_BUF *b, unsigned char v);
int paea_buf_u32(PAEA_BUF *b, uint32_t v);
int paea_buf_raw(PAEA_BUF *b, const void *p, size_t len);
int paea_buf_point(EVP_PAEA_CTX *ctx, PAEA_BUF *b, const EC_POINT *pt);
int paea_buf_int(EVP_PAEA_CTX *ctx, PAEA_BUF *b, const BIGNUM *bn);

/* Reader over a byte range, TL helpers. */
typedef struct paea_rdr_st {
    const unsigned char *p;
    size_t remaining;
    int error;                       /* sticky error flag */
} PAEA_RDR;

int paea_rdr_take(PAEA_RDR *r, size_t len, const unsigned char **out);
int paea_rdr_take_u8(PAEA_RDR *r, unsigned char *out);
int paea_rdr_take_u32(PAEA_RDR *r, uint32_t *out);
int paea_rdr_take_tl(PAEA_RDR *r, size_t *len, const unsigned char **out);
int paea_rdr_take_point(const EC_GROUP *group, PAEA_RDR *r, EC_POINT *pt,
                        size_t *consumed);
int paea_rdr_take_int(PAEA_RDR *r, BIGNUM *bn, size_t *consumed);

/* Low level primitives */
size_t paea_i2osp_len(EVP_PAEA_CTX *ctx);        /* fixed integer width  */
int paea_m_of_uid(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uid_len,
                  BIGNUM *m);                     /* m, reduced mod q */
int paea_hash_bs2ip(EVP_PAEA_CTX *ctx, const unsigned char *msg,
                    size_t msg_len, BIGNUM *bn);  /* BS2IP(H(msg)) */
int paea_rand_in_zq_star(EVP_PAEA_CTX *ctx, BIGNUM *out);
int paea_h_g(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t in_len,
             EC_POINT *out);                       /* H_g team -> G element */
int paea_point_valid_pub(EVP_PAEA_CTX *ctx, const EC_POINT *pt); /* on curve,
                                                     in <g>, not infinity */
int paea_scalar_mul(EVP_PAEA_CTX *ctx, const BIGNUM *scalar,
                    const EC_POINT *in, EC_POINT *out);  /* scalar * in */
int paea_generator_mul(EVP_PAEA_CTX *ctx, const BIGNUM *scalar,
                       EC_POINT *out);              /* scalar * g */
int paea_point_add(EVP_PAEA_CTX *ctx, const EC_POINT *a, const EC_POINT *b,
                   EC_POINT *out);
int paea_point_sub(EVP_PAEA_CTX *ctx, const EC_POINT *a, const EC_POINT *b,
                   EC_POINT *out);
int paea_muls(EVP_PAEA_CTX *ctx, EC_POINT *out, const BIGNUM *g_scalar,
              size_t num, const EC_POINT *points[], const BIGNUM *scalars[]);
int paea_inverse_mod_q(EVP_PAEA_CTX *ctx, const BIGNUM *a, BIGNUM *out);

/* Signature helpers (scheme keyed by ctx->sig_type / sig_digest_name) */
int paea_sign_init(EVP_PAEA_CTX *ctx, EVP_MD_CTX *mctx, EVP_PKEY_CTX **ppctx,
                   int signing);
int paea_sig_sign(EVP_PAEA_CTX *ctx, EVP_MD_CTX *mctx,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char **out, size_t *out_len);
int paea_sig_verify(EVP_PAEA_CTX *ctx, const unsigned char *sig,
                    size_t sig_len, const unsigned char *msg, size_t msg_len);

/* paea_ops.c: ZYHW setup/registration/revocation internals */
int paea_zyhw_setup(EVP_PAEA_CTX *ctx);
int paea_encode_params_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *out);
int paea_decode_params_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                            size_t blob_len);
int paea_encode_servkey_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *out);
int paea_decode_servkey_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                             size_t blob_len);
int paea_encode_crl_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *out);
int paea_decode_crl_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                          size_t blob_len);
int paea_encode_credential_blob(EVP_PAEA_CTX *ctx, PAEA_BUF *out);
int paea_decode_credential_blob(EVP_PAEA_CTX *ctx, const unsigned char *blob,
                                size_t blob_len);
int paea_crl_revoke(EVP_PAEA_CTX *ctx, const BIGNUM *m);

/* paea_auth.c: ZYHW 3-pass anonymous authentication */
int paea_zyhw_server_auth_init(EVP_PAEA_CTX *ctx, PAEA_BUF *msg);
int paea_zyhw_user_prove(EVP_PAEA_CTX *ctx, const unsigned char *pw,
                         size_t pw_len, const unsigned char *msg1,
                         size_t msg1_len, PAEA_BUF *msg2);
int paea_zyhw_server_verify(EVP_PAEA_CTX *ctx, const unsigned char *msg2,
                            size_t msg2_len);

# endif /* OPENSSL_NO_PAEA */
#endif /* OSSL_CRYPTO_PAEA_LOCAL_H */