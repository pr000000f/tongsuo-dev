/*
 * Copyright 2015-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This must be the first #include file */
#include "../async_local.h"

#ifdef ASYNC_WIN

# include <windows.h>
# include "internal/cryptlib.h"

int ASYNC_is_capable(void)
{
    return 1;
}

int ASYNC_set_mem_functions(ASYNC_stack_alloc_fn alloc_fn,
                            ASYNC_stack_free_fn free_fn)
{
    return 0;
}

void ASYNC_get_mem_functions(ASYNC_stack_alloc_fn *alloc_fn,
                             ASYNC_stack_free_fn *free_fn)
{
    if (alloc_fn != NULL)
        *alloc_fn = NULL;
    if (free_fn != NULL)
        *free_fn = NULL;
}

void async_local_cleanup(void)
{
    if (GetCurrentFiber())
        ConvertFiberToThread();
}

int async_fibre_init_dispatcher(async_ctx *ctx)
{
    ConvertThreadToFiber(NULL);
    return 1;
}

VOID CALLBACK async_start_func_win(PVOID unused)
{
    async_start_func();
}

#endif
