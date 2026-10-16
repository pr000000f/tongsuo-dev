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
 * ZYHW (GB/T 34953.4-XXXX 7.3) common helpers: buffer/TL encoding, group
 * arithmetic wrappers with scalars always reduced into [0, q), the H_g()
 * hash-to-group construction, H_lamda based hashing, random sampling from
 * Z_q* and server signature helpers.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/paea.h>
#include <openssl/paeaerr.h>

/* EC_GROUP_method_of() and EC_POINTs_mul() are used below; they are the
 * recommended EC primitives inside libcrypto. */
#include "internal/deprecated.h"

#include "paea_local.h"

#define PAEA_MAX_RAND_TRIES     128

/*
 * Context housekeeping
 */

void paea_ctx_clear_credential(EVP_PAEA_CTX *ctx)
{
    OPENSSL_clear_free(ctx->uid, ctx->uid_len);
    ctx->uid = NULL;
    ctx->uid_len = 0;
    BN_clear_free(ctx->m);
    ctx->m = NULL;
    EC_POINT_clear_free(ctx->sigma_pw);
    ctx->sigma_pw = NULL;
    EC_POINT_clear_free(ctx->witness);
    ctx->witness = NULL;
    ctx->witness_crl_index = 0;
}

void paea_ctx_clear_session(EVP_PAEA_CTX *ctx)
{
    BN_clear_free(ctx->sess_y);
    ctx->sess_y = NULL;
    EC_POINT_free(ctx->sess_y_pt);
    ctx->sess_y_pt = NULL;
    OPENSSL_clear_free(ctx->sess_sig, ctx->sess_sig_len);
    ctx->sess_sig = NULL;
    ctx->sess_sig_len = 0;
    ctx->srv_pend = 0;

    OPENSSL_clear_free(ctx->sk, ctx->sk_len);
    ctx->sk = NULL;
    ctx->sk_len = 0;
    ctx->accepted = 0;
}

void paea_ctx_clear_crl(EVP_PAEA_CTX *ctx)
{
    size_t i;

    for (i = 0; i < ctx->crl_len; i++) {
        if (ctx->crl != NULL) {
            BN_clear_free(ctx->crl[i].m);
            EC_POINT_free(ctx->crl[i].b);
        }
    }
    OPENSSL_free(ctx->crl);
    ctx->crl = NULL;
    ctx->crl_len = 0;
    ctx->crl_alloc = 0;

    EC_POINT_free(ctx->acc);
    ctx->acc = NULL;
}

/*
 * Changing the group invalidates every group element and every group
 * dependent state held in the context.
 */
void paea_ctx_clear_group(EVP_PAEA_CTX *ctx)
{
    paea_ctx_clear_session(ctx);
    paea_ctx_clear_credential(ctx);
    paea_ctx_clear_crl(ctx);

    EC_GROUP_free(ctx->group);
    ctx->group = NULL;
    BN_free(ctx->q);
    ctx->q = NULL;
    BN_free(ctx->cofactor);
    ctx->cofactor = NULL;
    EC_POINT_free(ctx->gpt);
    ctx->gpt = NULL;
    ctx->qlen = 0;

    EC_POINT_free(ctx->w);
    ctx->w = NULL;
    EC_POINT_free(ctx->acc_w);
    ctx->acc_w = NULL;

    BN_clear_free(ctx->r);
    ctx->r = NULL;
    BN_clear_free(ctx->acckey);
    ctx->acckey = NULL;

    EVP_PKEY_free(ctx->sig_key);
    ctx->sig_key = NULL;

    ctx->params_ready = 0;
    ctx->server_secret = 0;
}

/*
 * Install a group, taking ownership of it (freed here on failure, cleared
 * together with the rest of the context otherwise).  All group dependent
 * state of the old group is dropped.
 */
int paea_ctx_install_group(EVP_PAEA_CTX *ctx, EC_GROUP *group)
{
    BIGNUM *cofactor = NULL;
    EC_POINT *gpt = NULL;
    BIGNUM *q = NULL;

    /* The standard (7.3.2, referring to 6.2.1 a) asks for prime field
     * curves with cofactor 1 (or 2 when infeasible), so that cheap
     * subgroup checks are possible. */
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
            != NID_X9_62_prime_field)
        goto err;

    cofactor = BN_new();
    if (cofactor == NULL || !EC_GROUP_get_cofactor(group, cofactor, NULL))
        goto err;
    if (BN_is_one(cofactor) == 0 && !BN_is_word(cofactor, 2))
        goto err;

    gpt = EC_POINT_new(group);
    if (gpt == NULL
            || !EC_POINT_copy(gpt, EC_GROUP_get0_generator(group)))
        goto err;

    q = BN_dup(EC_GROUP_get0_order(group));
    if (q == NULL)
        goto err;

    /* Everything derived from the old group is obsolete now. */
    paea_ctx_clear_group(ctx);

    ctx->group = group;
    ctx->cofactor = cofactor;
    ctx->gpt = gpt;
    ctx->q = q;
    ctx->qlen = (size_t)BN_num_bytes(q);
    return 1;

 err:
    EC_GROUP_free(group);
    BN_free(cofactor);
    EC_POINT_free(gpt);
    BN_free(q);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_GROUP);
    return 0;
}

int paea_ctx_set_group_by_name(EVP_PAEA_CTX *ctx, const char *group_name)
{
    int nid;
    EC_GROUP *group = NULL;

    if (group_name == NULL || *group_name == '\0')
        goto err;

    /*
     * Accept every curve naming scheme known to libcrypto: short/long
     * names and dotted OID numbers through OBJ_txt2nid() ("SM2",
     * "prime256v1", ...) plus the RFC 5480 NIST names through the EC
     * layer ("P-256", "P-384", "P-521", ...).
     */
    nid = OBJ_txt2nid(group_name);
    if (nid == NID_undef) {
        ERR_clear_error();      /* name lookup miss is not an error here */
        nid = EC_curve_nist2nid(group_name);
    }
    if (nid == NID_undef)
        goto err;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
        goto err;

    return paea_ctx_install_group(ctx, group);

 err:
    EC_GROUP_free(group);
    ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_GROUP);
    return 0;
}

int paea_ctx_set_md_by_name(EVP_PAEA_CTX *ctx, const char *digest_name)
{
    EVP_MD *md;
    char *name;

    if (digest_name == NULL || *digest_name == '\0')
        goto err;
    md = EVP_MD_fetch(ctx->libctx, digest_name, ctx->propq);
    if (md == NULL)
        goto err;
    name = OPENSSL_strdup(digest_name);
    if (name == NULL) {
        EVP_MD_free(md);
        goto err;
    }
    EVP_MD_free(ctx->md);
    ctx->md = md;
    OPENSSL_free(ctx->digest_name);
    ctx->digest_name = name;
    return 1;

 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_DIGEST);
    return 0;
}

int paea_ctx_setup_crl(EVP_PAEA_CTX *ctx, int capacity)
{
    PAEA_CRL_ENTRY *crl;

    if (ctx->crl != NULL)
        return 1;
    if (capacity <= 0)
        capacity = 4;
    crl = OPENSSL_zalloc(sizeof(*crl) * (size_t)capacity);
    if (crl == NULL)
        return 0;
    ctx->crl = crl;
    ctx->crl_alloc = (size_t)capacity;
    return 1;
}

/*
 * Encoded sizes
 */

size_t paea_i2osp_len(EVP_PAEA_CTX *ctx)
{
    return ctx->qlen;
}

/*
 * Growable output buffer
 */

int paea_buf_init(PAEA_BUF *b)
{
    b->data = NULL;
    b->len = 0;
    b->alloc = 0;
    b->error = 0;
    return 1;
}

void paea_buf_cleanup(PAEA_BUF *b)
{
    OPENSSL_clear_free(b->data, b->len);
    b->data = NULL;
    b->len = 0;
    b->alloc = 0;
    b->error = 0;
}

unsigned char *paea_buf_release(PAEA_BUF *b, size_t *len)
{
    unsigned char *data;

    if (b->error) {
        OPENSSL_clear_free(b->data, b->len);
        data = NULL;
        *len = 0;
    } else {
        data = b->data;
        *len = b->len;
    }
    b->data = NULL;
    b->len = 0;
    b->alloc = 0;
    return data;
}

static int paea_buf_reserve(PAEA_BUF *b, size_t extra)
{
    size_t new_alloc;
    unsigned char *tmp;

    if (b->error)
        return 0;
    if (extra <= b->alloc - b->len)
        return 1;
    new_alloc = b->alloc > 0 ? b->alloc : 256;
    while (new_alloc - b->len < extra)
        new_alloc *= 2;
    tmp = OPENSSL_realloc(b->data, new_alloc);
    if (tmp == NULL) {
        b->error = 1;
        return 0;
    }
    b->data = tmp;
    b->alloc = new_alloc;
    return 1;
}

int paea_buf_u8(PAEA_BUF *b, unsigned char v)
{
    if (!paea_buf_reserve(b, 1))
        return 0;
    b->data[b->len++] = v;
    return 1;
}

int paea_buf_u32(PAEA_BUF *b, uint32_t v)
{
    unsigned char t[4];

    t[0] = (unsigned char)((v >> 24) & 0xff);
    t[1] = (unsigned char)((v >> 16) & 0xff);
    t[2] = (unsigned char)((v >> 8) & 0xff);
    t[3] = (unsigned char)(v & 0xff);
    return paea_buf_raw(b, t, sizeof(t));
}

int paea_buf_raw(PAEA_BUF *b, const void *p, size_t len)
{
    if (b->error)
        return 0;
    if (len == 0)
        return 1;
    if (p == NULL)
        return 0;
    if (!paea_buf_reserve(b, len))
        return 0;
    memcpy(b->data + b->len, p, len);
    b->len += len;
    return 1;
}

/* TL(group element): len = encoded point size */
int paea_buf_point(EVP_PAEA_CTX *ctx, PAEA_BUF *b, const EC_POINT *pt)
{
    size_t octlen = EC_POINT_point2oct(ctx->group, pt,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       NULL, 0, NULL);

    if (octlen == 0)
        return 0;
    if (!paea_buf_u32(b, (uint32_t)octlen))
        return 0;
    if (!paea_buf_reserve(b, octlen))
        return 0;
    if (EC_POINT_point2oct(ctx->group, pt, POINT_CONVERSION_UNCOMPRESSED,
                           b->data + b->len, octlen, NULL) == 0) {
        b->error = 1;
        return 0;
    }
    b->len += octlen;
    return 1;
}

/*
 * TL(integer): canonical "at least q-width" big endian encoding.  Values
 * are zero padded to the byte size of q; values exceeding that width
 * (e.g. the Fiat-Shamir challenge c, a full hash output that may well be
 * >= q) are encoded with their natural byte size.  Readers accept any
 * width (paea_rdr_take_int), so both sides stay in agreement.
 */
int paea_buf_int(EVP_PAEA_CTX *ctx, PAEA_BUF *b, const BIGNUM *bn)
{
    size_t qlen = ctx->qlen;
    size_t blen;

    if (bn == NULL || BN_is_negative(bn))
        return 0;
    blen = (size_t)BN_num_bytes(bn);
    if (blen < qlen)
        blen = qlen;
    if (!paea_buf_u32(b, (uint32_t)blen))
        return 0;
    if (!paea_buf_reserve(b, blen))
        return 0;
    if (BN_bn2binpad(bn, b->data + b->len, (int)blen) != (int)blen) {
        b->error = 1;
        return 0;
    }
    b->len += blen;
    return 1;
}

/*
 * Reader
 */

int paea_rdr_take(PAEA_RDR *r, size_t len, const unsigned char **out)
{
    if (r->error || r->remaining < len) {
        r->error = 1;
        return 0;
    }
    *out = r->p;
    r->p += len;
    r->remaining -= len;
    return 1;
}

int paea_rdr_take_u8(PAEA_RDR *r, unsigned char *out)
{
    const unsigned char *p;

    if (!paea_rdr_take(r, 1, &p))
        return 0;
    *out = *p;
    return 1;
}

int paea_rdr_take_u32(PAEA_RDR *r, uint32_t *out)
{
    const unsigned char *p;

    if (!paea_rdr_take(r, 4, &p))
        return 0;
    *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return 1;
}

int paea_rdr_take_tl(PAEA_RDR *r, size_t *len, const unsigned char **out)
{
    uint32_t l;

    if (!paea_rdr_take_u32(r, &l))
        return 0;
    if (l > PAEA_MAX_BLOB_LEN) {
        r->error = 1;
        return 0;
    }
    if (!paea_rdr_take(r, l, out))
        return 0;
    *len = l;
    return 1;
}

/* NOTE: The caller must make sure curvature checks (paea_point_valid_pub)
 * are performed; parsing alone only checks the encoding.  *consumed
 * receives the total field size including the length prefix so the caller
 * may compute byte ranges in the original message buffer. */
int paea_rdr_take_point(const EC_GROUP *group, PAEA_RDR *r, EC_POINT *pt,
                        size_t *consumed)
{
    size_t len;
    const unsigned char *p;

    if (consumed != NULL)
        *consumed = 0;
    if (!paea_rdr_take_tl(r, &len, &p))
        return 0;
    if (EC_POINT_oct2point(group, pt, p, len, NULL) == 0) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
        return 0;
    }
    if (consumed != NULL)
        *consumed = 4 + len;
    return 1;
}

/*
 * Variable width integers: the encoded width is taken from the TL length
 * (bounded), so not to tie the caller to any specific group.  Callers
 * needing fixed width validation (protocol messages) are expected to
 * check the exact upper bound themselves.
 */
int paea_rdr_take_int(PAEA_RDR *r, BIGNUM *bn, size_t *consumed)
{
    size_t len;
    const unsigned char *p;

    if (consumed != NULL)
        *consumed = 0;
    if (!paea_rdr_take_tl(r, &len, &p))
        return 0;
    if (len == 0 || len > 64) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        return 0;
    }
    if (BN_bin2bn(p, (int)len, bn) == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_MESSAGE);
        return 0;
    }
    if (consumed != NULL)
        *consumed = 4 + len;
    return 1;
}

/*
 * m = BS2IP(H_lamda(I_U)) mod q
 *
 * The standard text (7.3.3) does not spell out whether the hash output
 * needs reduction mod q; all the group arithmetic later is mod q, so the
 * identifier is reduced here (see implementation notes, issue #2).
 */
int paea_m_of_uid(EVP_PAEA_CTX *ctx, const unsigned char *uid, size_t uid_len,
                  BIGNUM *m)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t mdlen = (size_t)EVP_MD_get_size(ctx->md);
    BIGNUM *tmp = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    if (EVP_Q_digest(ctx->libctx, ctx->digest_name, ctx->propq,
                     uid, uid_len, md, &mdlen) != 1)
        goto end;
    tmp = BN_bin2bn(md, mdlen, NULL);
    if (tmp == NULL)
        goto end;
    bctx = BN_CTX_new();
    if (bctx == NULL)
        goto end;
    if (BN_mod(m, tmp, ctx->q, bctx) != 1)
        goto end;
    ret = 1;

 end:
    OPENSSL_cleanse(md, sizeof(md));
    BN_free(tmp);
    BN_CTX_free(bctx);
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
    return ret;
}

/* BS2IP(H_lamda(msg)), no reduction (used for the challenge c) */
int paea_hash_bs2ip(EVP_PAEA_CTX *ctx, const unsigned char *msg,
                    size_t msg_len, BIGNUM *bn)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t mdlen = (size_t)EVP_MD_get_size(ctx->md);
    int ret = 0;

    if (EVP_Q_digest(ctx->libctx, ctx->digest_name, ctx->propq,
                     msg, msg_len, md, &mdlen) != 1)
        goto end;
    if (BN_bin2bn(md, mdlen, bn) == NULL)
        goto end;
    ret = 1;

 end:
    OPENSSL_cleanse(md, sizeof(md));
    if (ret == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_HASH_FAILED);
    return ret;
}

/*
 * Random sampling from Z_q* (non-zero).
 */
int paea_rand_in_zq_star(EVP_PAEA_CTX *ctx, BIGNUM *out)
{
    int i;

    for (i = 0; i < PAEA_MAX_RAND_TRIES; i++) {
        if (BN_priv_rand_range(out, ctx->q) != 1)
            break;
        if (!BN_is_zero(out))
            return 1;
    }
    ERR_raise(ERR_LIB_PAEA, PAEA_R_RANDOM_FAILED);
    return 0;
}

/*
 * H_g(): maps a byte string to a generator of G.
 *
 * The standard text only references the R_1EC primitive of ISO/IEC
 * 11770-4 for this mapping without defining it.  We use the classic
 * "try and increment" construction: input || ctr is hashed (share the
 * H_lamda digest), the output is interpreted as an x coordinate by
 * rejection sampling and lifted with the fixed compression bit 0.  On
 * curves with cofactor 2 the point is multiplied by the cofactor and
 * rejected if the result is the point at infinity (see implementation
 * notes, issue #1).
 */
int paea_h_g(EVP_PAEA_CTX *ctx, const unsigned char *in, size_t in_len,
             EC_POINT *out)
{
    BIGNUM *p = NULL, *x = NULL;
    EC_POINT *pt = NULL;
    BN_CTX *bctx = NULL;
    unsigned char *buf = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t mdlen = (size_t)EVP_MD_get_size(ctx->md);
    int ctr;
    int ret = 0;

    if (ctx->group == NULL || ctx->md == NULL || out == NULL)
        goto end;

    buf = OPENSSL_malloc(in_len + 1);
    if (buf == NULL)
        goto end;
    if (in_len > 0)
        memcpy(buf, in, in_len);

    p = BN_new();
    x = BN_new();
    bctx = BN_CTX_new();
    pt = EC_POINT_new(ctx->group);
    if (p == NULL || x == NULL || bctx == NULL || pt == NULL)
        goto end;
    if (EC_GROUP_get_curve(ctx->group, p, NULL, NULL, NULL) != 1)
        goto end;

    for (ctr = 0; ctr < PAEA_MAX_HG_TRIES; ctr++) {
        buf[in_len] = (unsigned char)ctr;
        if (EVP_Q_digest(ctx->libctx, ctx->digest_name, ctx->propq,
                         buf, in_len + 1, md, &mdlen) != 1)
            goto end;
        if (BN_bin2bn(md, mdlen, x) == NULL)
            goto end;
        /* rejection sampling, keeps the distribution flat */
        if (BN_is_zero(x) || BN_ucmp(x, p) >= 0)
            continue;
        if (EC_POINT_set_compressed_coordinates(ctx->group, pt, x, 0,
                                                bctx) != 1) {
            /*
             * Expected during the search (roughly every second candidate
             * is not the x coordinate of a curve point): retry with the
             * next counter instead of leaving errors in the queue.
             */
            ERR_clear_error();
            continue;
        }
        if (!BN_is_one(ctx->cofactor)) {
            /* ensure the point is in the prime order subgroup */
            if (EC_POINT_mul(ctx->group, pt, NULL, pt, ctx->cofactor,
                             bctx) != 1)
                goto end;
            if (EC_POINT_is_at_infinity(ctx->group, pt) == 1)
                continue;
        }
        if (EC_POINT_copy(out, pt) != 1)
            goto end;
        ret = 1;
        goto end;
    }
    ERR_raise(ERR_LIB_PAEA, PAEA_R_COORDINATE_FAILED);

 end:
    OPENSSL_cleanse(md, sizeof(md));
    OPENSSL_free(buf);
    BN_free(p);
    BN_clear_free(x);          /* x is a hash output, still cleanse */
    EC_POINT_free(pt);
    BN_CTX_free(bctx);
    return ret;
}

/*
 * Public element validation: on curve, not infinity and (for cofactor 2
 * curves) inside the prime order subgroup.
 */
int paea_point_valid_pub(EVP_PAEA_CTX *ctx, const EC_POINT *pt)
{
    int ok = 0;
    EC_POINT *tmp = NULL;
    BN_CTX *bctx = NULL;

    if (pt == NULL)
        goto end;
    if (EC_POINT_is_at_infinity(ctx->group, pt) == 1)
        goto end;
    bctx = BN_CTX_new();
    if (bctx == NULL)
        goto end;
    if (EC_POINT_is_on_curve(ctx->group, pt, bctx) != 1)
        goto end;
    if (!BN_is_one(ctx->cofactor)) {
        tmp = EC_POINT_new(ctx->group);
        if (tmp == NULL)
            goto end;
        if (EC_POINT_mul(ctx->group, tmp, NULL, pt, ctx->cofactor,
                         bctx) != 1)
            goto end;
        if (EC_POINT_is_at_infinity(ctx->group, tmp) == 1)
            goto end;
    }
    ok = 1;

 end:
    EC_POINT_free(tmp);
    BN_CTX_free(bctx);
    if (ok == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
    return ok;
}

/*
 * Group arithmetic wrappers.  All scalars are reduced into [0, q) before
 * being handed to the EC layer, which keeps the semantics of negative
 * and out of range scalars equivalent to exponent arithmetic mod q.
 */

static int paea_reduce_mod_q(EVP_PAEA_CTX *ctx, const BIGNUM *in, BIGNUM *out)
{
    BN_CTX *bctx = BN_CTX_new();
    int ok;

    if (bctx == NULL)
        return 0;
    if (in != out) {
        if (BN_is_negative(in) || BN_ucmp(in, ctx->q) >= 0)
            ok = BN_mod(out, in, ctx->q, bctx) == 1;
        else
            ok = BN_copy(out, in) != NULL;
    } else if (BN_is_negative(in) || BN_ucmp(in, ctx->q) >= 0) {
        BIGNUM *t = BN_dup(in);

        if (t == NULL) {
            BN_CTX_free(bctx);
            return 0;
        }
        ok = BN_mod(out, t, ctx->q, bctx) == 1;
        BN_free(t);
    } else {
        ok = 1;
    }
    BN_CTX_free(bctx);
    if (ok == 0)
        ERR_raise(ERR_LIB_PAEA, PAEA_R_BAD_POINT);
    return ok;
}

int paea_scalar_mul(EVP_PAEA_CTX *ctx, const BIGNUM *scalar,
                    const EC_POINT *in, EC_POINT *out)
{
    BIGNUM *s = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    if (in == NULL || scalar == NULL)
        goto end;
    s = BN_new();
    bctx = BN_CTX_new();
    if (s == NULL || bctx == NULL)
        goto end;
    if (!paea_reduce_mod_q(ctx, scalar, s))
        goto end;
    if (EC_POINT_mul(ctx->group, out, NULL, in, s, bctx) != 1)
        goto end;
    ret = 1;

 end:
    BN_clear_free(s);
    BN_CTX_free(bctx);
    return ret;
}

int paea_generator_mul(EVP_PAEA_CTX *ctx, const BIGNUM *scalar, EC_POINT *out)
{
    BIGNUM *s = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    if (scalar == NULL)
        goto end;
    s = BN_new();
    bctx = BN_CTX_new();
    if (s == NULL || bctx == NULL)
        goto end;
    if (!paea_reduce_mod_q(ctx, scalar, s))
        goto end;
    if (EC_POINT_mul(ctx->group, out, s, NULL, NULL, bctx) != 1)
        goto end;
    ret = 1;

 end:
    BN_clear_free(s);
    BN_CTX_free(bctx);
    return ret;
}

int paea_point_add(EVP_PAEA_CTX *ctx, const EC_POINT *a, const EC_POINT *b,
                   EC_POINT *out)
{
    BN_CTX *bctx = BN_CTX_new();
    int ret = 0;

    if (bctx == NULL)
        goto end;
    if (EC_POINT_add(ctx->group, out, a, b, bctx) == 1)
        ret = 1;
 end:
    BN_CTX_free(bctx);
    return ret;
}

int paea_point_sub(EVP_PAEA_CTX *ctx, const EC_POINT *a, const EC_POINT *b,
                   EC_POINT *out)
{
    /* out = a - b computed as a + (-b); b itself is const, so the
     * negation happens on a copy. */
    BN_CTX *bctx = NULL;
    EC_POINT *t = NULL;
    int ret = 0;

    bctx = BN_CTX_new();
    t = EC_POINT_new(ctx->group);
    if (bctx == NULL || t == NULL)
        goto end;
    if (EC_POINT_copy(t, b) != 1
            || EC_POINT_invert(ctx->group, t, bctx) != 1
            || EC_POINT_add(ctx->group, out, a, t, bctx) != 1)
        goto end;
    ret = 1;

 end:
    EC_POINT_free(t);
    BN_CTX_free(bctx);
    return ret;
}

/* out = g_scalar * g + sum_i scalars[i] * points[i] */
int paea_muls(EVP_PAEA_CTX *ctx, EC_POINT *out, const BIGNUM *g_scalar,
              size_t num, const EC_POINT *points[], const BIGNUM *scalars[])
{
    BIGNUM *gs = NULL, **ss = NULL;
    BN_CTX *bctx = NULL;
    size_t i;
    int ret = 0;

    bctx = BN_CTX_new();
    gs = BN_new();
    if (bctx == NULL || gs == NULL)
        goto end;
    if (num > 0) {
        ss = OPENSSL_malloc(num * sizeof(*ss));
        if (ss == NULL)
            goto end;
        for (i = 0; i < num; i++) {
            ss[i] = BN_new();
            if (ss[i] == NULL)
                goto end;
            if (!paea_reduce_mod_q(ctx, scalars[i], ss[i]))
                goto end;
        }
    }
    if (g_scalar != NULL) {
        if (!paea_reduce_mod_q(ctx, g_scalar, gs))
            goto end;
    } else {
        BN_zero(gs);
    }
    if (EC_POINTs_mul(ctx->group, out,
                      BN_is_zero(gs) ? NULL : gs,
                      num, points, (const BIGNUM **)ss, bctx) != 1)
        goto end;
    ret = 1;

 end:
    BN_free(gs);
    if (ss != NULL) {
        for (i = 0; i < num; i++)
            BN_clear_free(ss[i]);
        OPENSSL_free(ss);
    }
    BN_CTX_free(bctx);
    return ret;
}

int paea_inverse_mod_q(EVP_PAEA_CTX *ctx, const BIGNUM *a, BIGNUM *out)
{
    BIGNUM *t = NULL, *r = NULL;
    BN_CTX *bctx = NULL;
    int ret = 0;

    if (a == NULL || out == NULL || BN_is_zero(a))
        goto end;
    bctx = BN_CTX_new();
    if (bctx == NULL)
        goto end;
    if (out == a) {
        t = BN_dup(a);
        if (t == NULL)
            goto end;
        a = t;
    }
    r = BN_mod_inverse(NULL, a, ctx->q, bctx);
    if (r == NULL)
        goto end;
    if (BN_copy(out, r) == NULL)
        goto end;
    ret = 1;

 end:
    BN_free(t);
    BN_free(r);
    BN_CTX_free(bctx);
    return ret;
}

/*
 * Signature helpers around EVP_DigestSign/Verify.
 */

int paea_sign_init(EVP_PAEA_CTX *ctx, EVP_MD_CTX *mctx, EVP_PKEY_CTX **ppctx,
                   int signing)
{
    const char *mdname;

    if (ctx->sig_key == NULL) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_NOT_INITIALIZED);
        return 0;
    }

    /* Bind and normalise the digest used with the signature scheme: SM2
     * signs with SM3 (GB/T 32918 based schemes), EC keys may use
     * SM3/SHA256/.... */
    mdname = ctx->sig_digest_name;
    if (mdname == NULL && EVP_PKEY_is_a(ctx->sig_key, "SM2"))
        mdname = "SM3";
    if (EVP_PKEY_is_a(ctx->sig_key, "SM2") && mdname != NULL
            && OPENSSL_strcasecmp(mdname, "SM3") != 0)
        mdname = "SM3";
    if (mdname == NULL)
        mdname = "SHA256";

    if (ctx->sig_md == NULL) {
        ctx->sig_md = EVP_MD_fetch(ctx->libctx, mdname, ctx->propq);
        if (ctx->sig_md == NULL) {
            ERR_raise(ERR_LIB_PAEA, PAEA_R_INVALID_DIGEST);
            return 0;
        }
        /*
         * Careful: mdname may be the very buffer ctx->sig_digest_name
         * points at (or a literal), and it must stay valid until the end
         * of this function.  Only replace the stored name when it
         * differs, and never through a dangling alias.
         */
        if (mdname != ctx->sig_digest_name) {
            char *tmp = OPENSSL_strdup(mdname);

            if (tmp == NULL) {
                EVP_MD_free(ctx->sig_md);
                ctx->sig_md = NULL;
                return 0;
            }
            OPENSSL_free(ctx->sig_digest_name);
            ctx->sig_digest_name = tmp;
        }
    }

    if (signing) {
        if (EVP_DigestSignInit_ex(mctx, ppctx, mdname, ctx->libctx,
                                   ctx->propq, ctx->sig_key, NULL) != 1)
            goto err;
    } else {
        if (EVP_DigestVerifyInit_ex(mctx, ppctx, mdname, ctx->libctx,
                                    ctx->propq, ctx->sig_key, NULL) != 1)
            goto err;
    }

    /* Explicit user id for SM2 signatures; both sides use the default
     * distinguished identifier of GB/T 32918.2. */
    if (EVP_PKEY_is_a(ctx->sig_key, "SM2") && *ppctx != NULL) {
        size_t idlen = strlen(PAEA_SM2_DEFAULT_ID);

        if (EVP_PKEY_CTX_set1_id(*ppctx, PAEA_SM2_DEFAULT_ID,
                                 (int)idlen) != 1)
            goto err;
    }
    return 1;

 err:
    ERR_raise(ERR_LIB_PAEA, PAEA_R_DIGEST_INIT_FAILED);
    return 0;
}

/*
 * One shot sign: the caller provides a fresh EVP_MD_CTX, gets back a
 * freshly allocated signature in *out.  SM2/ECDSA signatures never
 * exceed 256 bytes for any supported curve, a larger buffer failing to
 * fit is an error.
 */
int paea_sig_sign(EVP_PAEA_CTX *ctx, EVP_MD_CTX *mctx,
                  const unsigned char *msg, size_t msg_len,
                  unsigned char **out, size_t *out_len)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char buf[256];
    size_t len = sizeof(buf);

    *out = NULL;
    *out_len = 0;
    if (!paea_sign_init(ctx, mctx, &pctx, 1))
        return 0;
    if (EVP_DigestSign(mctx, buf, &len, msg, msg_len) != 1) {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_SIGN_FAILED);
        return 0;
    }
    *out = OPENSSL_memdup(buf, len);
    if (*out == NULL)
        return 0;
    *out_len = len;
    return 1;
}

int paea_sig_verify(EVP_PAEA_CTX *ctx, const unsigned char *sig,
                    size_t sig_len, const unsigned char *msg, size_t msg_len)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;
    if (!paea_sign_init(ctx, mctx, &pctx, 0))
        goto end;
    if (EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len) == 1) {
        ret = 1;
    } else {
        ERR_raise(ERR_LIB_PAEA, PAEA_R_VERIFY_FAILED);
    }

 end:
    EVP_MD_CTX_free(mctx);
    return ret;
}