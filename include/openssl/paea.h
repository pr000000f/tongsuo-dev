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
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>

# ifndef OPENSSL_NO_PAEA
# ifdef  __cplusplus
extern "C" {
# endif

/* Unified EVP protocol interface. Each context has one in-flight exchange.
 * new_ex selects "ZYHW" or "YZW". Setup makes a server; importing public
 * parameters makes a client. New contexts default to SM2/SM3 (ZYHW) or
 * SM9-BN256/SM3 (YZW). set_params accepts "group", "digest", "revocation".
 * ZYHW with the SM2 curve requires SM3; setup and public import enforce this.
 * Public parameters and registration data require an authenticated channel;
 * registration data additionally requires confidentiality.
 * Outputs are allocated once; release with OPENSSL_free (registration data
 * contains secrets and should be released with OPENSSL_clear_free).
 * YZW: client init -> server step -> client step -> server step.
 * ZYHW: server init -> client step -> server step.
 * A client completing its proof does not confirm server acceptance.
 * Auth failure consumes the exchange. reset permits a fresh exchange only.
 * Contexts are not safe for concurrent calls. Serialize complete exchanges
 * on a server context. There is no API to duplicate server secrets.
 */
typedef struct evp_paea_ctx_st EVP_PAEA_CTX;

/* Create an empty context for one protocol mechanism.
 * @param libctx Borrowed library context; NULL selects the default context.
 *               It must outlive the returned PAEA context.
 * @param mechanism "ZYHW" or "YZW" (case-insensitive). YZW requires pairing.
 * @param propq Optional algorithm property query; copied by the new context.
 * @return Newly owned context, or NULL on failure; free with
 *         EVP_PAEA_CTX_free(). */
EVP_PAEA_CTX *EVP_PAEA_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *mechanism,
                                 const char *propq);

/* Release a context, including its credentials, keys and exchange state.
 * @param ctx Owned context to release; NULL is allowed. */
void EVP_PAEA_CTX_free(EVP_PAEA_CTX *ctx);

/* Get the selected mechanism name.
 * @param ctx Context created by EVP_PAEA_CTX_new_ex().
 * @return Borrowed constant string, valid until ctx is freed. */
const char *EVP_PAEA_CTX_get0_name(const EVP_PAEA_CTX *ctx);

/* Set configuration before setup or public-parameter import.
 * @param ctx Empty context to configure.
 * @param params OSSL_PARAM_END-terminated array. Recognized entries are
 *               "group" and "digest" (UTF8_STRING), and "revocation"
 *               (INTEGER, 0 or 1). Unspecified entries retain their defaults.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_CTX_set_params(EVP_PAEA_CTX *ctx, const OSSL_PARAM params[]);

/* Generate long-term server parameters and secrets.
 * @param ctx Empty, configured context; it becomes a server on success.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_setup(EVP_PAEA_CTX *ctx);

/* Encode the current public parameters, including public revocation state.
 * @param ctx Initialized server or client context.
 * @param out Receives one library-allocated byte string; the caller frees it
 *            with OPENSSL_free(). Set to NULL on failure.
 * @param outlen Receives its byte length; set to zero on failure.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_export_public(const EVP_PAEA_CTX *ctx,
                           unsigned char **out, size_t *outlen);

/* Install a server's public parameters into a new client context.
 * @param ctx Empty context of the same mechanism as the encoded parameters.
 * @param in Public-parameter bytes from an authenticated source.
 * @param inlen Length of in in bytes, at most 1 MiB.
 * @return 1 on success, 0 on failure; this does not authenticate in. */
int EVP_PAEA_import_public(EVP_PAEA_CTX *ctx,
                           const unsigned char *in, size_t inlen);

/* Export a client's password-wrapped credential and current witness.
 * YZW output is 973/1050 bytes without/with revocation. Default ZYHW SM2/SM3
 * output is 113/190 bytes; other group/digest settings can change its length.
 * @param ctx Client context with a stored or imported credential.
 * @param out Receives allocated sensitive bytes; the caller releases them
 *            with OPENSSL_clear_free(*out, *outlen). NULL on failure.
 * @param outlen Receives the byte length; zero on failure.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_export_credential(const EVP_PAEA_CTX *ctx,
                               unsigned char **out, size_t *outlen);

/* Restore a previously exported password-wrapped client credential.
 * @param ctx Idle client with corresponding public parameters already loaded.
 * @param in Bytes returned by EVP_PAEA_export_credential(); the password is
 *           not checked by this import operation.
 * @param inlen Length of in in bytes, at most 1 MiB.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_import_credential(EVP_PAEA_CTX *ctx,
                               const unsigned char *in, size_t inlen);

/* Make a client context from another context's public parameters only.
 * @param ctx Initialized server or client whose public data is copied.
 * @return Newly owned client context, or NULL on failure. No server secret,
 *         credential or session key is copied; free with EVP_PAEA_CTX_free(). */
EVP_PAEA_CTX *EVP_PAEA_CTX_dup_public(const EVP_PAEA_CTX *ctx);

/* Issue secret registration data for one user on an idle server.
 * YZW output is 209/286 bytes without/with revocation. Default ZYHW SM2/SM3
 * output is 65/134 bytes; other group/digest settings can change its length.
 * @param ctx Initialized, idle server context.
 * @param uid User identifier bytes; at most 512 bytes. Reuse these exact
 *            bytes to revoke this user. YZW derives its credential independently
 *            of uid but, with revocation enabled, indexes the user by its hash.
 * @param uidlen Length of uid in bytes.
 * @param out Receives allocated secret registration data; deliver it over a
 *            confidential authenticated channel, then OPENSSL_clear_free().
 *            Set to NULL on failure.
 * @param outlen Receives the output byte length; zero on failure.
 * @return 1 on success, 0 on failure. */
int EVP_PAEA_issue_credential(EVP_PAEA_CTX *ctx,
                              const unsigned char *uid, size_t uidlen,
                              unsigned char **out, size_t *outlen);

/* Password-wrap issued registration data inside an idle client context.
 * @param ctx Client with current public parameters already imported.
 * @param uid Identifier used at registration, at most 512 bytes. ZYHW uses
 *            it in credential computation; YZW currently does not bind it.
 * @param uidlen Length of uid in bytes.
 * @param pw Local password bytes; never sent to the server.
 * @param pwlen Length of pw in bytes.
 * @param issued Secret bytes returned by EVP_PAEA_issue_credential().
 * @param issuedlen Length of issued in bytes, at most 1 MiB.
 * @return 1 on success, 0 on failure. Use EVP_PAEA_export_credential() to
 *         persist the wrapped credential. */
int EVP_PAEA_store_credential(EVP_PAEA_CTX *ctx,
                              const unsigned char *uid, size_t uidlen,
                              const unsigned char *pw, size_t pwlen,
                              const unsigned char *issued, size_t issuedlen);

/* Revoke a registered user on an idle server with revocation enabled.
 * @param ctx Initialized server context with revocation enabled.
 * @param uid Exact identifier bytes used when the user was registered.
 * @param uidlen Length of uid in bytes, at most 512 bytes.
 * @return 1 on success, 0 on failure. Export updated public parameters and
 *         distribute the new revocation state to clients. */
int EVP_PAEA_revoke(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uidlen);

/* Refresh an idle client's public revocation state and local witness.
 * @param ctx Client with revocation enabled and a stored/imported credential.
 * @param source Initialized server or separate public client context with
 *               trusted newer state from the same system and mechanism.
 *               Borrowed; no secret key is copied from it.
 * @return 1 on success, 0 on failure. Re-export the credential and matching
 *         public parameters to persist the updated witness. */
int EVP_PAEA_refresh(EVP_PAEA_CTX *ctx, const EVP_PAEA_CTX *source);

/* Start one authentication exchange on an idle initialized context.
 * YZW client M1 is 2208/2803 bytes without/with revocation. ZYHW server M1
 * has a variable-length DER signature; do not infer its length from a prior
 * invocation.
 * @param ctx ZYHW server or YZW client with a stored/imported credential.
 *            Only the YZW client needs a credential.
 * @param pw Client password bytes for YZW; NULL on the ZYHW server.
 * @param pwlen Length of pw in bytes; zero on the ZYHW server.
 * @param out Receives an allocated M1 byte string; free with OPENSSL_free().
 *            Set to NULL on failure.
 * @param outlen Receives the M1 byte length; zero on failure.
 * @return 1 on success, 0 on failure. Reset after a failed exchange. */
int EVP_PAEA_auth_init(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                       unsigned char **out, size_t *outlen);

/* Process the next complete authentication message.
 * YZW server M2 is always 141 bytes; client M3 is 216/324 bytes without/with
 * revocation. Default ZYHW SM2/SM3 client M2 is 226/323 bytes; other
 * group/digest settings can change its length. The final server step of
 * either mechanism succeeds with NULL output and zero length.
 * @param ctx Context at the next stage of its in-flight exchange.
 * @param pw Client password bytes only for the ZYHW client processing M1;
 *           otherwise NULL.
 * @param pwlen Length of pw in bytes; otherwise zero.
 * @param in Complete message received from the peer.
 * @param inlen Length of in in bytes, at most 1 MiB.
 * @param out Receives an allocated outgoing message, or NULL for a successful
 *            final server step; free non-NULL output with OPENSSL_free().
 *            Set to NULL on failure.
 * @param outlen Receives the outgoing byte length; zero for final success
 *               or failure.
 * @return 1 on success, 0 on failure. Reset before a new exchange. */
int EVP_PAEA_auth_step(EVP_PAEA_CTX *ctx, const unsigned char *pw, size_t pwlen,
                       const unsigned char *in, size_t inlen,
                       unsigned char **out, size_t *outlen);

/* Discard the current exchange and session key; retain long-term state.
 * @param ctx Initialized context to reset before a new authentication or
 *            management operation. */
void EVP_PAEA_auth_reset(EVP_PAEA_CTX *ctx);

/* Read the locally completed session key.
 * With the default SM3 digest (including YZW), its length is 32 bytes;
 * other supported ZYHW digests use their own output length.
 * @param ctx Context whose exchange completed locally; client completion
 *            alone does not confirm server acceptance.
 * @param out Caller-owned output buffer, or NULL to query the required size.
 *            Clear its contents when no longer needed.
 * @param outlen On input, buffer capacity when out is non-NULL; on output,
 *               actual length or required length if capacity was too small.
 * @return 1 on success (including size query), 0 on failure. */
int EVP_PAEA_get_session_key(const EVP_PAEA_CTX *ctx,
                             unsigned char *out, size_t *outlen);

# ifdef  __cplusplus
}
# endif
# endif /* OPENSSL_NO_PAEA */
#endif
