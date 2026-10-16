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

/*
 * CRL serialisation.  The standard does not define this byte layout.
 * Each entry is m as |q| bytes, then B as an uncompressed point.
 * Neither field carries a length.
 */

#include <openssl/byteorder.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

#include "paea_local.h"

void paea_crl_entries_free(PAEA_CRL_ENTRY *arr, size_t n)
{
    size_t i;

    if (arr == NULL)
        return;
    for (i = 0; i < n; i++) {
        BN_clear_free(arr[i].m);
        EC_POINT_free(arr[i].b);
    }
    OPENSSL_free(arr);
}

/* ------------------------------------------------------------------ */
/* CRL                                                                 */
/*                                                                     */
/*   u8 version                                                        */
/*   u32 n                                                             */
/*   n * { m_i (|q| bytes), B_i }                                      */
/* ------------------------------------------------------------------ */

/*
 * Parse CRL payload starting at *pp / *rem.  On success advances the
 * cursor past the CRL and returns the freshly allocated entry array.
 */
static int paea_parse_crl_content(const EC_GROUP *group,
                                  const unsigned char **pp, size_t *rem,
                                  PAEA_CRL_ENTRY **out_arr, size_t *out_n)
{
    const BIGNUM *q = EC_GROUP_get0_order(group);
    const unsigned char *p = *pp;
    size_t left = *rem, qlen;
    uint32_t n = 0;
    PAEA_CRL_ENTRY *arr = NULL;
    size_t i;

    *out_arr = NULL;
    *out_n = 0;

    if (q == NULL || left < 1 + 4 || p[0] != PAEA_BLOB_VERSION)
        goto err;
    qlen = (size_t)BN_num_bytes(q);
    p++;
    left--;
    p = OPENSSL_load_u32_be(&n, p);
    left -= 4;
    if (n > PAEA_MAX_CRL_ENTRIES)
        goto err;
    if (n > 0) {
        arr = OPENSSL_zalloc(n * sizeof(*arr));
        if (arr == NULL)
            goto err;
        for (i = 0; i < n; i++) {
            arr[i].m = BN_new();
            arr[i].b = EC_POINT_new(group);
            if (arr[i].m == NULL || arr[i].b == NULL
                || !paea_get_bn(&p, &left, qlen, arr[i].m)
                || BN_is_zero(arr[i].m) || BN_ucmp(arr[i].m, q) >= 0
                || !paea_get_point(group, &p, &left, arr[i].b))
                goto err;
        }
    }
    *pp = p;
    *rem = left;
    *out_arr = arr;
    *out_n = n;
    return 1;

 err:
    paea_crl_entries_free(arr, n);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;
}

int paea_encode_crl_blob(const EC_GROUP *group, const PAEA_CRL_ENTRY *crl,
                         size_t crl_len, unsigned char **out, size_t *out_len)
{
    const BIGNUM *q;
    size_t i, total, off, n, qlen, ptlen;
    unsigned char *buf;

    *out = NULL;
    *out_len = 0;
    if (group == NULL || (q = EC_GROUP_get0_order(group)) == NULL)
        return 0;
    qlen = (size_t)BN_num_bytes(q);
    ptlen = paea_point_len(group);
    if (qlen == 0 || ptlen == 0)
        return 0;

    total = 1 + 4 + crl_len * (qlen + ptlen);

    buf = OPENSSL_malloc(total);
    if (buf == NULL)
        return 0;
    buf[0] = PAEA_BLOB_VERSION;
    OPENSSL_store_u32_be(buf + 1, (uint32_t)crl_len);
    off = 5;
    for (i = 0; i < crl_len; i++) {
        n = paea_put_bn(qlen, buf + off, crl[i].m);
        if (n == 0)
            goto err;
        off += n;
        n = paea_put_point(group, buf + off, crl[i].b);
        if (n == 0)
            goto err;
        off += n;
    }
    if (off != total)
        goto err;
    *out = buf;
    *out_len = total;
    return 1;

 err:
    OPENSSL_free(buf);
    return 0;
}

int paea_decode_crl_blob(const EC_GROUP *group, const unsigned char *blob,
                         size_t blob_len, PAEA_CRL_ENTRY **crl, size_t *crl_len)
{
    const unsigned char *p = blob;
    size_t rem = blob_len;
    PAEA_CRL_ENTRY *arr = NULL;
    size_t n = 0;

    *crl = NULL;
    *crl_len = 0;
    if (group == NULL)
        goto err;
    if (!paea_parse_crl_content(group, &p, &rem, &arr, &n))
        return 0;
    if (rem != 0)
        goto err;
    *crl = arr;
    *crl_len = n;
    return 1;

 err:
    paea_crl_entries_free(arr, n);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_CRL_BLOB);
    return 0;
}
