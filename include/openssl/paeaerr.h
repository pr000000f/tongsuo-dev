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

#ifndef OPENSSL_PAEAERR_H
# define OPENSSL_PAEAERR_H
# pragma once

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_PAEA

/*
 * PAEA reason codes.
 */
# define PAEA_R_BAD_CRL_BLOB                        113
# define PAEA_R_BAD_MESSAGE                         114
# define PAEA_R_BAD_POINT                           120
# define PAEA_R_COORDINATE_FAILED                   124
# define PAEA_R_HASH_FAILED                         122
# define PAEA_R_KEYGEN_FAILED                       123
# define PAEA_R_NOT_INITIALIZED                     109
# define PAEA_R_RANDOM_FAILED                       121
# define PAEA_R_SIGN_FAILED                         107
# define PAEA_R_UID_REJECTED                        115
# define PAEA_R_USER_REVOKED                        119
# define PAEA_R_VERIFY_FAILED                       108
# define PAEA_R_WITNESS_INVALID                     118

# endif /* OPENSSL_NO_PAEA */
#endif