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
# include <openssl/paea.h>
# include "crypto/paeaerr.h"

/*
 * ZYHW mechanism (GB/T 34953.4-XXXX, 7.3), based on the auxiliary storage
 * PAEA model.  In the elliptic curve instantiation the multiplicative
 * notation of the standard text maps to the EC additive group as follows:
 *
 *   g^k          -> k * g          (generator g = generator of the curve)
 *   g1 * g2      -> G1 + G2
 *   g1 / g2      -> G1 - G2
 *   x^(1/y)      -> x * 1/y        (scalars reduced mod q, the group order)
 *
 * Cross reference to the standard text:
 *   7.3.2 setup:          r, w = g^r, signing key pair (pk, sk)
 *   7.3.3 registration:   m = BS2IP(H_lamda(I_U)) mod q,
 *                         sigma = (1/(r+m)) * g,
 *                         sigma_pw = sigma + H_g(pw),
 *                         W = (1/(r+m)) * B_n     (revocation only)
 *   7.3.4 authentication: 3-pass protocol Sign_sk / ZK proof of (m, a, ...)
 *   7.3.5 revocation:     the same r (and w = g^r already in params).
 *                         CRL = { <m_i, B_i> }, with
 *                         B_i = (1/prod_{j<=i}(r+m_j)) * g    (B_n = g on an
 *                         empty CRL, i.e. the empty product is 1), and the
 *                         witness update W' = (W - B_{j+1}) * 1/(m_{j+1}-m)
 *                         Server check: P = r * M.
 *
 * The standard does not define a wire encoding. Lengths that the curve
 * or the digest already determine are written with no length prefix:
 *   point    uncompressed GB/T 32918.1 4.2.9, width fixed by the field
 *   scalar   |q| bytes (q = group order, not the field prime)
 *   c        |H| bytes, the hash as an integer, not reduced mod q
 * A field whose size is not determined that way (DER, a name) is a
 * 4-byte length followed by the value.
 */

/*
 * Object format version for the serialised params/crl blobs.
 * Bumped whenever those layouts change.
 */
# define PAEA_BLOB_VERSION          3

/*
 * Maximum number of retries for the hash-to-group "try and increment"
 * construction of H_g().  2^256 attempts are way beyond a collision, 64
 * is already overkill for any sane curve.
 */
# define PAEA_MAX_HG_TRIES           64

/* Reasonable sanity limits for parsed blobs and CRLs.
 * Integers are scalars or a hash; 128 covers P-521 and EVP_MAX_MD_SIZE. */
# define PAEA_MAX_BLOB_LEN           (1 << 20)
# define PAEA_MAX_INT_LEN            128
# define PAEA_MAX_CRL_ENTRIES        (1 << 20)

/*
 * SM2 signing user id.  Both ends use the GB/T 32918.2 default,
 * "1234567812345678".
 */
# define PAEA_SM2_DEFAULT_ID         "1234567812345678"

/* Fixed widths, no length prefix. Return the number of bytes written, or 0.
 * paea_point_len is the uncompressed size of a finite point on group.
 * paea_put_bn / paea_get_bn use the caller-supplied width (|q| or |H|). */
size_t paea_point_len(const EC_GROUP *group);
size_t paea_put_point(const EC_GROUP *group, unsigned char *p,
                     const EC_POINT *pt);
size_t paea_put_bn(size_t len, unsigned char *p, const BIGNUM *bn);

/* On success *pp / *rem move past the field. *data points into the
 * caller's buffer; nothing is copied. paea_get_bytes is for a field
 * that still carries a 4-byte length. */
int paea_get_bytes(const unsigned char **pp, size_t *rem,
                 const unsigned char **data, size_t *len);
int paea_get_point(const EC_GROUP *group, const unsigned char **pp,
                       size_t *rem, EC_POINT *pt);
int paea_get_bn(const unsigned char **pp, size_t *rem, size_t len, BIGNUM *bn);

/* Internal ZYHW implementation; applications use EVP_PAEA_* only. */
/*
 * GB/T 34953.4 ZYHW (7.3).  Callers hold the group, keys, accumulator and
 * CRL themselves; these low-level functions do not use EVP_PAEA_CTX.
 *
 * Setup returns r, w = r*g, the signing key and (when revocation is on)
 * the empty accumulator B_0 = g.  Registration returns an issued byte
 * string; the user wraps that into sigma_pw.  Authentication is the
 * 3-pass exchange: the server keeps y, Y and sigma_S from init and
 * passes them back into verify.
 *
 * The caller frees every *out buffer with OPENSSL_free.  Byte strings
 * use the following fields.  A field whose width the curve or the digest
 * already determines has no length prefix.
 *
 *   point    uncompressed, GB/T 32918.1 4.2.9: 0x04 || X || Y.
 *            X and Y are field elements (4.2.6).  The width is fixed
 *            by the curve.
 *   scalar   an integer in Z_q, |q| bytes.  q is the group order.
 *   c        the challenge, |H| bytes.  H is the digest named by md.
 *   u32      four bytes, most significant byte first.
 */

typedef struct paea_crl_entry_st {
    BIGNUM *m;                  /* identifier, in Z_q */
    EC_POINT *b;                /* accumulator value B_i */
} PAEA_CRL_ENTRY;

/** Frees an array from paea_crl_revoke or paea_decode_crl_blob.
 *  \param  arr  entry array, or NULL
 *  \param  n    number of entries
 */
void paea_crl_entries_free(PAEA_CRL_ENTRY *arr, size_t n);

/** m = BS2IP(H(uid)) mod q.  The caller owns m.
 *  \param  md       H_λ
 *  \param  group    curve; q is its order
 *  \param  uid      user identifier I_U
 *  \param  uid_len  length of uid
 *  \param  m        output, already allocated
 *  \return 1 on success, 0 on error
 */
int paea_m_of_uid(const EVP_MD *md, const EC_GROUP *group,
                  const unsigned char *uid, size_t uid_len, BIGNUM *m);

/** Setup (7.3.2).  Outputs are newly allocated.
 *  \param  group            mechanism curve
 *  \param  sig_type         "SM2", or "EC" / "ECDSA"
 *  \param  sig_digest_name  signature digest for a non-SM2 key.
 *                           NULL selects SHA-256.  SM2 always uses SM3.
 *  \param  sig_curve_name   curve of a non-SM2 signing key.  NULL uses
 *                           the name of group.  Ignored for SM2.
 *  \param  libctx           library context, or NULL
 *  \param  propq            property query, or NULL
 *  \param  revocation       non-zero to enable revocation
 *  \param  r                server secret, in Z_q*
 *  \param  w                w = r*g
 *  \param  acc              B_0 = g when revocation is on, otherwise NULL
 *  \param  sig_key          signing key pair
 *  \param  sig_digest_out   digest name actually selected; free with
 *                           OPENSSL_free
 *  \return 1 on success, 0 on error
 */
int paea_zyhw_setup(const EC_GROUP *group, const char *sig_type,
                    const char *sig_digest_name, const char *sig_curve_name,
                    OSSL_LIB_CTX *libctx, const char *propq, int revocation,
                    BIGNUM **r, EC_POINT **w, EC_POINT **acc,
                    EVP_PKEY **sig_key, char **sig_digest_out);

/** Registration (7.3.3).
 *  Format of *out:
 *    no revocation:   point(sigma)
 *    revocation:      point(sigma) || u32 index || point(W)
 *  index is crl_len, the witness version.
 *  \param  group    mechanism curve
 *  \param  md       H_λ, the same digest the user will use
 *  \param  r        server secret from setup
 *  \param  acc      current accumulator B_n, or NULL if revocation is off
 *  \param  crl_len  CRL length this witness is issued against
 *  \param  uid      user identifier I_U
 *  \param  uid_len  length of uid
 *  \param  out      issued byte string
 *  \param  out_len  length of *out
 *  \return 1 on success, 0 on error
 */
int paea_zyhw_issue_credential(const EC_GROUP *group, const EVP_MD *md,
                               const BIGNUM *r, const EC_POINT *acc,
                               size_t crl_len,
                               const unsigned char *uid, size_t uid_len,
                               unsigned char **out, size_t *out_len);

/** sigma_pw = sigma + H_g(pw).  m, sigma_pw and, when revocation is on,
 *  witness are newly allocated.
 *  \param  group         mechanism curve
 *  \param  md            H_λ
 *  \param  uid           the same I_U the server registered
 *  \param  uid_len       length of uid
 *  \param  pw            password
 *  \param  pw_len        length of pw
 *  \param  issued        byte string from paea_zyhw_issue_credential
 *  \param  issued_len    length of issued
 *  \param  revocation    non-zero if issued contains index and W
 *  \param  m             output, m = BS2IP(H(uid)) mod q
 *  \param  sigma_pw      output, the password-wrapped credential
 *  \param  witness       output W, or NULL when revocation is off
 *  \param  witness_idx   output, the CRL index stored in issued, or 0
 *  \return 1 on success, 0 on error
 */
int paea_zyhw_wrap_credential(const EC_GROUP *group, const EVP_MD *md,
                              const unsigned char *uid, size_t uid_len,
                              const unsigned char *pw, size_t pw_len,
                              const unsigned char *issued, size_t issued_len,
                              int revocation,
                              BIGNUM **m, EC_POINT **sigma_pw,
                              EC_POINT **witness, uint32_t *witness_idx);

/** Append m to the CRL and replace *acc with B_n^(1/(r+m)).
 *  The new entry's point is owned by the CRL.
 *  \param  group      mechanism curve
 *  \param  r          server secret
 *  \param  acc        current B_n; replaced by the new accumulator
 *  \param  crl        entry array, grown as needed; NULL is an empty list
 *  \param  crl_len    number of entries
 *  \param  crl_alloc  allocated capacity of *crl, in entries
 *  \param  m          identifier to revoke, in Z_q
 *  \return 1 on success, 0 on error.  A repeated m is rejected.
 */
int paea_crl_revoke(const EC_GROUP *group, const BIGNUM *r, EC_POINT **acc,
                    PAEA_CRL_ENTRY **crl, size_t *crl_len, size_t *crl_alloc,
                    const BIGNUM *m);

/** Apply CRL entries from *witness_idx onward:
 *    W <- (W - B_i) * 1/(m_i - m)
 *  \param  group        mechanism curve
 *  \param  m            this user's identifier
 *  \param  witness      in/out W
 *  \param  witness_idx  in/out index of the next entry to apply
 *  \param  crl          CRL the user now holds
 *  \param  crl_len      number of entries
 *  \return 1 on success, 0 on error.  m_i = m means this user is revoked.
 */
int paea_zyhw_update_witness(const EC_GROUP *group, const BIGNUM *m,
                             EC_POINT *witness, uint32_t *witness_idx,
                             const PAEA_CRL_ENTRY *crl, size_t crl_len);

/** Encode a CRL.
 *  Format of *out:
 *    u8 version (3) || u32 count || count * (scalar(m_i) || point(B_i))
 *  \param  group    mechanism curve
 *  \param  crl      entries; NULL is allowed when crl_len is 0
 *  \param  crl_len  number of entries
 *  \param  out      encoded byte string
 *  \param  out_len  length of *out
 *  \return 1 on success, 0 on error
 */
int paea_encode_crl_blob(const EC_GROUP *group, const PAEA_CRL_ENTRY *crl,
                         size_t crl_len, unsigned char **out, size_t *out_len);

/** Decode the byte string from paea_encode_crl_blob.
 *  *crl is newly allocated; free it with paea_crl_entries_free.
 *  \param  group     mechanism curve
 *  \param  blob      encoded CRL
 *  \param  blob_len  length of blob
 *  \param  crl       output entry array
 *  \param  crl_len   number of entries
 *  \return 1 on success, 0 on error
 */
int paea_decode_crl_blob(const EC_GROUP *group, const unsigned char *blob,
                         size_t blob_len, PAEA_CRL_ENTRY **crl, size_t *crl_len);

/** Pass 1, server to user.
 *  Format of *out:
 *    point(Y) || u32 sig_len || sigma_S
 *  sigma_S is the DER signature over point(Y).
 *  \param  group        mechanism curve
 *  \param  sign_key     server signing key
 *  \param  md           signature digest; SM3 when sign_key is SM2
 *  \param  out          message sent to the user
 *  \param  out_len      length of *out
 *  \param  y            server ephemeral scalar; pass back to verify
 *  \param  y_pt         Y = y*g; pass back to verify
 *  \param  sigma_s      signature bytes, the same sigma_S without its length
 *  \param  sigma_s_len  length of *sigma_s
 *  \return 1 on success, 0 on error
 */
int paea_zyhw_server_auth_init(const EC_GROUP *group, EVP_PKEY *sign_key,
                               const EVP_MD *md,
                               unsigned char **out, size_t *out_len,
                               BIGNUM **y, EC_POINT **y_pt,
                               unsigned char **sigma_s, size_t *sigma_s_len);

/** Pass 2, user to server.  Revocation is on when acc != NULL.
 *  Format of *out is point(X) || sigma_U, where sigma_U is:
 *    no revocation:  point(T) || c || scalar(s_m) || scalar(s_a)
 *    revocation:     point(T) || point(M) || c || scalar(s_m)
 *                    || scalar(s_a) || scalar(s_z)
 *  \param  group           mechanism curve
 *  \param  md              H_λ
 *  \param  pw_credential   sigma_pw from paea_zyhw_wrap_credential
 *  \param  m               this user's identifier
 *  \param  verify_key      server signature public key
 *  \param  witness         W, or NULL when revocation is off
 *  \param  acc             user's B_n, or NULL when revocation is off
 *  \param  pw              password
 *  \param  pw_len          length of pw
 *  \param  msg1            message from paea_zyhw_server_auth_init
 *  \param  msg1_len        length of msg1
 *  \param  out             message sent to the server
 *  \param  out_len         length of *out
 *  \param  session_key     optional.  Both this and session_key_len must
 *                          be non-NULL to receive it.  Raw digest, |H| bytes.
 *  \param  session_key_len length of *session_key
 *  \return 1 on success, 0 on error
 */
int paea_zyhw_user_prove(const EC_GROUP *group, EVP_MD *md,
                         const EC_POINT *pw_credential, const BIGNUM *m,
                         EVP_PKEY *verify_key,
                         const EC_POINT *witness, const EC_POINT *acc,
                         const unsigned char *pw, size_t pw_len,
                         const unsigned char *msg1, size_t msg1_len,
                         unsigned char **out, size_t *out_len,
                         unsigned char **session_key, size_t *session_key_len);

/** Pass 3.  Returns 1 for ACCEPT and 0 for REJECT.
 *  \param  group            mechanism curve
 *  \param  md               H_λ
 *  \param  r                server secret
 *  \param  y                ephemeral scalar from paea_zyhw_server_auth_init
 *  \param  y_pt             Y from paea_zyhw_server_auth_init
 *  \param  sigma_s          signature bytes from paea_zyhw_server_auth_init,
 *                           not the whole first message
 *  \param  sigma_s_len      length of sigma_s
 *  \param  acc              server's current B_n, or NULL when revocation
 *                           is off
 *  \param  msg2             message from paea_zyhw_user_prove
 *  \param  msg2_len         length of msg2
 *  \param  session_key      optional, same rule as paea_zyhw_user_prove.
 *                           Raw digest, |H| bytes.
 *  \param  session_key_len  length of *session_key
 */
int paea_zyhw_server_verify(const EC_GROUP *group, EVP_MD *md,
                            const BIGNUM *r, const BIGNUM *y,
                            const EC_POINT *y_pt,
                            const unsigned char *sigma_s, size_t sigma_s_len,
                            const EC_POINT *acc,
                            const unsigned char *msg2, size_t msg2_len,
                            unsigned char **session_key,
                            size_t *session_key_len);

/* Low level primitives */
int paea_check_group(const EC_GROUP *group);
int paea_check_digest(const EC_GROUP *group, const EVP_MD *md);
int paea_rand_in_zq_star(const BIGNUM *q, BIGNUM *out);
int paea_h_g(const EC_GROUP *group, const EVP_MD *md,
             const unsigned char *in, size_t in_len, EC_POINT *out);

int paea_sig_sign(EVP_PKEY *pkey, const EVP_MD *md,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char **out, size_t *out_len);
int paea_sig_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t sig_len,
                    const unsigned char *msg, size_t msg_len);

# endif /* OPENSSL_NO_PAEA */
#endif /* OSSL_CRYPTO_PAEA_LOCAL_H */
