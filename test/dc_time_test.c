/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression for DC_check_time_valid(): deadline must be computed on the UTC
 * calendar, not via mktime() which interprets ASN.1 UTC fields as local time.
 * A west-of-UTC TZ previously could accept a DC that expired a few hours ago.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/x509.h>
#include "testutil.h"

#define SECS_PER_DAY (24 * 60 * 60)
#define SECS_PER_HOUR (60 * 60)

/*
 * Parent notBefore = now - 7d - 6h, DC valid_time = 7d
 * → real deadline is 6 hours in the past and must be rejected in any TZ.
 */
#define EXPIRED_NOTBEFORE_DAYS (-7)
#define EXPIRED_NOTBEFORE_SECS (-6 * SECS_PER_HOUR)
#define EXPIRED_VALID_TIME ((unsigned long)(7 * SECS_PER_DAY))

/* Parent notBefore = now - 1d, DC valid_time = 2d → still valid. */
#define VALID_NOTBEFORE_DAYS (-1)
#define VALID_NOTBEFORE_SECS 0
#define VALID_VALID_TIME ((unsigned long)(2 * SECS_PER_DAY))

static int set_tz(const char *tz)
{
#if defined(OPENSSL_SYS_WINDOWS)
    {
        char buf[64];

        if (BIO_snprintf(buf, sizeof(buf), "TZ=%s", tz) >= (int)sizeof(buf))
            return 0;
        return _putenv(buf) == 0;
    }
#else
    return setenv("TZ", tz, 1) == 0;
#endif
}

static void apply_tz(void)
{
#if defined(OPENSSL_SYS_WINDOWS)
    _tzset();
#else
    tzset();
#endif
}

static int restore_tz(const char *saved)
{
    int ok;

    if (saved != NULL)
        ok = set_tz(saved);
    else
#if defined(OPENSSL_SYS_WINDOWS)
        ok = _putenv("TZ=") == 0;
#else
        ok = unsetenv("TZ") == 0;
#endif
    apply_tz();
    return ok;
}

static X509 *make_parent_with_notBefore(int offset_day, long offset_sec)
{
    X509 *cert = NULL;
    ASN1_TIME *nb = NULL;
    time_t now = time(NULL);

    if (!TEST_ptr(cert = X509_new()))
        return NULL;
    if (!TEST_ptr(nb = ASN1_TIME_adj(NULL, now, offset_day, offset_sec))
        || !TEST_true(X509_set1_notBefore(cert, nb))) {
        X509_free(cert);
        cert = NULL;
    }
    ASN1_TIME_free(nb);
    return cert;
}

static DELEGATED_CREDENTIAL *make_dc(unsigned long valid_time)
{
    DELEGATED_CREDENTIAL *dc = NULL;

    if (!TEST_ptr(dc = DC_new())
        || !TEST_true(DC_set_valid_time(dc, valid_time))) {
        DC_free(dc);
        return NULL;
    }
    return dc;
}

static int check_time_valid_under_tz(const char *tz, int offset_day,
                                     long offset_sec, unsigned long valid_time,
                                     int expect_valid)
{
    char *saved = NULL;
    const char *envtz;
    X509 *parent = NULL;
    DELEGATED_CREDENTIAL *dc = NULL;
    int ok = 0;

    envtz = getenv("TZ");
    if (envtz != NULL && !TEST_ptr(saved = OPENSSL_strdup(envtz)))
        return 0;

    if (!TEST_true(set_tz(tz)))
        goto err;
    apply_tz();

    if (!TEST_ptr(parent = make_parent_with_notBefore(offset_day, offset_sec))
        || !TEST_ptr(dc = make_dc(valid_time)))
        goto err;

    if (expect_valid) {
        if (!TEST_true(DC_check_time_valid(parent, dc)))
            goto err;
    } else {
        if (!TEST_false(DC_check_time_valid(parent, dc)))
            goto err;
    }

    ok = 1;
 err:
    DC_free(dc);
    X509_free(parent);
    if (!restore_tz(saved))
        ok = 0;
    OPENSSL_free(saved);
    return ok;
}

/* Must reject under Etc/GMT+12; old mktime path would wrongly accept. */
static int test_dc_expired_rejected_west_of_utc(void)
{
    return check_time_valid_under_tz("Etc/GMT+12",
                                     EXPIRED_NOTBEFORE_DAYS,
                                     EXPIRED_NOTBEFORE_SECS,
                                     EXPIRED_VALID_TIME, 0);
}

/* Same fixture under UTC must also reject (sanity / non-TZ control). */
static int test_dc_expired_rejected_utc(void)
{
    return check_time_valid_under_tz("UTC",
                                     EXPIRED_NOTBEFORE_DAYS,
                                     EXPIRED_NOTBEFORE_SECS,
                                     EXPIRED_VALID_TIME, 0);
}

/* Still-valid DC must be accepted even under the adversarial TZ. */
static int test_dc_unexpired_accepted_west_of_utc(void)
{
    return check_time_valid_under_tz("Etc/GMT+12",
                                     VALID_NOTBEFORE_DAYS,
                                     VALID_NOTBEFORE_SECS,
                                     VALID_VALID_TIME, 1);
}

int setup_tests(void)
{
    ADD_TEST(test_dc_expired_rejected_west_of_utc);
    ADD_TEST(test_dc_expired_rejected_utc);
    ADD_TEST(test_dc_unexpired_accepted_west_of_utc);
    return 1;
}
