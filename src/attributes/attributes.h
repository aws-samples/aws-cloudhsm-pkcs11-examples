/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 *
 * @author Nabil S. Al-Ramli
 */

#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <inttypes.h>

#include "common.h"

CK_RV attributes_get(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE object,
        CK_ATTRIBUTE_TYPE type,
        uint8_t *buf,
        size_t *buf_len );

int attributes_output(
        uint8_t *buf,
        size_t buf_len,
        FILE *f);

CK_RV attributes_output_all(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE object,
        FILE *f );

#ifdef  __cplusplus
}
#endif

#endif
