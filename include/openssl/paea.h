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

#ifndef OPENSSL_PAEA_H
# define OPENSSL_PAEA_H

# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/params.h>
# include <openssl/obj_mac.h>

# ifndef OPENSSL_NO_PAEA
# ifdef  __cplusplus
extern "C" {
# endif

/*
 * GB/T 34953.4 anonymous entity authentication based on weak secrets.
 *
 * Mechanisms are selected by their NID, as defined by the OIDs in
 * appendix A of the standard text (see also crypto/objects/objects.txt):
 *   NID_zyhw_mechanism  {iso(1) standard(0) anonymous-entity-authentication(20009)
 *                        part4(4) storage-extra(2) zyhw(2)}
 *
 * Currently implemented mechanism(s):
 *   - ZYHW (7.3): anonymous entity authentication based on auxiliary storage
 *     (password wrapped credential), with optional user revocation support.
 *
 * A ZYHW instance is driven by an EVP_PAEA_CTX.  Typical call sequences:
 *
 * Server:
 *   ctx = EVP_PAEA_CTX_new(libctx, propq);
 *   EVP_PAEA_CTX_set_params(ctx, [mechanism, group, digest, signature,
 *                                 revocation, ...]);
 *   EVP_PAEA_setup(ctx);
 *   // publish "params", keep "servkey" (both via EVP_PAEA_CTX_get_params)
 *   EVP_PAEA_server_issue_credential(ctx, uid, ..., out, &len);  // -> user
 *   ...
 *   EVP_PAEA_server_auth_init(ctx, msg1, &len);       // -> user
 *   EVP_PAEA_server_auth_verify(ctx, msg2, len);      // <- user, returns 1/0
 *   EVP_PAEA_CTX_get_session_key(ctx, sk, &sklen);    // if ACCEPT
 *   EVP_PAEA_server_revoke(ctx, uid, ...);            // revocation
 *
 * User:
 *   ctx = EVP_PAEA_CTX_new(libctx, propq);
 *   EVP_PAEA_CTX_set_params(ctx, [mechanism=zyhw, params, credential]);
 *   // or: register with the issued credential:
 *   // EVP_PAEA_user_store_credential(ctx, uid, pw, issued, ...);
 *   EVP_PAEA_user_auth_prove(ctx, pw, ..., msg1, len, msg2, &msg2len);
 *   EVP_PAEA_CTX_get_session_key(ctx, sk, &sklen);
 *   EVP_PAEA_user_update_witness(ctx);  // after importing an updated "crl"
 */

/*
 * EVP_PAEA_CTX set_params() keys
 */

/* Operational parameters (all UTF8 strings unless stated otherwise) */
# define OSSL_PAEA_PARAM_MECHANISM       "mechanism"    /* NID, integer */
# define OSSL_PAEA_PARAM_GROUP            "group"        /* EC curve name */
# define OSSL_PAEA_PARAM_DIGEST           "digest"       /* H_lamda digest */
# define OSSL_PAEA_PARAM_SIGNATURE        "signature"    /* sig key type:
                                                          * "SM2" or "EC" */
# define OSSL_PAEA_PARAM_SIG_DIGEST       "sig-digest"   /* digest used with
                                                         * the signature
                                                         * scheme */
# define OSSL_PAEA_PARAM_SIG_CURVE        "sig-curve"   /* ECDSA signing key
                                                         * curve (keytype EC) */
# define OSSL_PAEA_PARAM_REVOCATION        "revocation"  /* 0/1, integer */

/* Serialised objects, octet strings.  Shared "params" is the trusted copy of
 * the public system parameters the user retrieves out of band.  */
# define OSSL_PAEA_PARAM_PARAMS           "params"       /* server public
                                                         * parameters blob */
# define OSSL_PAEA_PARAM_SERVKEY          "servkey"     /* server private
                                                         * key blob */
# define OSSL_PAEA_PARAM_CRL              "crl"         /* credential
                                                         * revocation list */
# define OSSL_PAEA_PARAM_CREDENTIAL       "credential"  /* password wrapped
                                                         * credential blob */
# define OSSL_PAEA_PARAM_SESSION_KEY      "session-key" /* negotiated SK */

/*
 * PAEA context: the state of one mechanism instance (server or user
 * side).  The internals are opaque and live in crypto/paea/.
 */
typedef struct evp_paea_ctx_st EVP_PAEA_CTX;

/*
 * Output buffers of EVP_PAEA_server_issue_credential(),
 * EVP_PAEA_server_auth_init(), EVP_PAEA_user_auth_prove() and
 * EVP_PAEA_CTX_get_session_key() may be NULL, in which case the required
 * size is returned in *out_len and the call succeeds without writing
 * anything.
 */

EVP_PAEA_CTX *EVP_PAEA_CTX_new(OSSL_LIB_CTX *libctx, const char *propq);
void EVP_PAEA_CTX_free(EVP_PAEA_CTX *ctx);

int EVP_PAEA_CTX_set_params(EVP_PAEA_CTX *ctx, const OSSL_PARAM params[]);
int EVP_PAEA_CTX_get_params(EVP_PAEA_CTX *ctx, OSSL_PARAM params[]);

/* Setup (server side): pick fresh r, revocation key and signing key */
int EVP_PAEA_setup(EVP_PAEA_CTX *ctx);

/* Registration */
int EVP_PAEA_server_issue_credential(EVP_PAEA_CTX *ctx,
                                     const unsigned char *uid, size_t uid_len,
                                     unsigned char *out, size_t *out_len);
int EVP_PAEA_user_store_credential(EVP_PAEA_CTX *ctx,
                                   const unsigned char *uid, size_t uid_len,
                                   const unsigned char *pw, size_t pw_len,
                                   const unsigned char *issued,
                                   size_t issued_len);

/* Anonymous entity authentication */
int EVP_PAEA_server_auth_init(EVP_PAEA_CTX *ctx,
                              unsigned char *out, size_t *out_len);
int EVP_PAEA_user_auth_prove(EVP_PAEA_CTX *ctx,
                             const unsigned char *pw, size_t pw_len,
                             const unsigned char *msg1, size_t msg1_len,
                             unsigned char *out, size_t *out_len);
int EVP_PAEA_server_auth_verify(EVP_PAEA_CTX *ctx,
                                const unsigned char *msg2, size_t msg2_len);
int EVP_PAEA_CTX_get_session_key(EVP_PAEA_CTX *ctx,
                                 unsigned char *out, size_t *out_len);

/* Revocation */
int EVP_PAEA_server_revoke(EVP_PAEA_CTX *ctx,
                           const unsigned char *uid, size_t uid_len);
int EVP_PAEA_user_update_witness(EVP_PAEA_CTX *ctx);

# ifdef  __cplusplus
}
# endif
# endif /* OPENSSL_NO_PAEA */
#endif