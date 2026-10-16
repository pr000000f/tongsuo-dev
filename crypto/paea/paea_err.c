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

#include <openssl/err.h>
#include <openssl/paeaerr.h>
#include "crypto/paeaerr.h"

#ifndef OPENSSL_NO_ERR

static const ERR_STRING_DATA PAEA_str_reasons[] = {
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_BAD_CRL_BLOB),
    "bad credential revocation list blob"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_BAD_MESSAGE),
    "bad protocol message"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_BAD_POINT),
    "invalid group element"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_COORDINATE_FAILED),
    "failed to map hash to an EC point"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_HASH_FAILED),
    "hash computation failed"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_KEYGEN_FAILED),
    "signing key generation failed"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_NOT_INITIALIZED),
    "missing required parameter"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_RANDOM_FAILED),
    "random number generation failed"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_SIGN_FAILED),
    "signing operation failed"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_UID_REJECTED),
    "user identifier rejected by the server"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_USER_REVOKED),
    "user has been revoked"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_VERIFY_FAILED),
    "signature verification failed"},
    {ERR_PACK(ERR_LIB_PAEA, 0, PAEA_R_WITNESS_INVALID),
    "revocation witness invalid or stale, re-registration required"},
    {0, NULL}
};

#endif

int ossl_err_load_PAEA_strings(void)
{
#ifndef OPENSSL_NO_ERR
    if (ERR_reason_error_string(PAEA_str_reasons[0].error) == NULL)
        ERR_load_strings_const(PAEA_str_reasons);
#endif
    return 1;
}
