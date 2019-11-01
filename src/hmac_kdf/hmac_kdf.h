/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* HMAC KDF Mechanism */
#define CKM_SP800_108_COUNTER_KDF    (CKM_VENDOR_DEFINED | 0x00000001UL)

typedef struct CK_SP800_108_COUNTER_FORMAT {
  CK_ULONG   ulWidthInBits;
} CK_SP800_108_COUNTER_FORMAT;

typedef CK_SP800_108_COUNTER_FORMAT CK_PTR CK_SP800_108_COUNTER_FORMAT_PTR;

typedef struct CK_SP800_108_DKM_LENGTH_FORMAT {
    CK_ULONG  dkmLengthMethod;
    CK_ULONG  ulWidthInBits;
} CK_SP800_108_DKM_LENGTH_FORMAT;

typedef CK_SP800_108_DKM_LENGTH_FORMAT CK_PTR CK_SP800_108_DKM_LENGTH_FORMAT_PTR;

#define SP800_108_DKM_LENGTH_SUM_OF_KEYS 1
#define SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS 2

typedef CK_ULONG CK_PRF_DATA_TYPE;
/* PRF data types */
#define SP800_108_COUNTER_FORMAT       0x0004
#define SP800_108_PRF_LABEL            0x0005
#define SP800_108_PRF_CONTEXT          0x0006
#define SP800_108_DKM_FORMAT           0x0007
#define SP800_108_BYTE_ARRAY           0x0008

typedef CK_MECHANISM_TYPE CK_PRF_TYPE;

typedef struct CK_PRF_DATA_PARAM {
    CK_PRF_DATA_TYPE   type;
    CK_VOID_PTR        pValue;
    CK_ULONG           ulValueLen;
} CK_PRF_DATA_PARAM;

typedef CK_PRF_DATA_PARAM CK_PTR CK_PRF_DATA_PARAM_PTR;

typedef struct CK_SP800_108_KDF_PARAMS {
    CK_PRF_TYPE            prftype;
    CK_ULONG               ulNumberOfDataParams;
    CK_PRF_DATA_PARAM_PTR  pDataParams;
} CK_SP800_108_KDF_PARAMS;


/* Note: CK_SP800_108_KDF_PARAMS will be sent as the mechanism parameter of
 * HMAC KDF mechanism (CKM_SP800_108_COUNTER_KDF).
 * prftype can be one of CKM_SHA_1_HMAC / SHA224_HMAC / SHA256_HMAC /
 * SHA384_HMAC / SHA512_HMAC.
 * Corrsponding to the mechanism, data has to be sent. This data will be stored
 * in a buffer pointed to by pDataParams. Each data param will be of tlv form
 * For eg. if we are using counter kdf mechanism (CKM_SP800_108_COUNTER_KDF),
 * we have to send counter format, prf label, prf context and dkm format in
 * the data param buffer. Eg. {SP800_108_COUNTER_FORMAT, (pointer to buff
 * containing CK_SP800_108_COUNTER_FORMAT), length of buffer},
 * {SP800_108_PRF_LABEL, (pointer to buff containing prf label), buffer length}
 * and so on.
 */

typedef enum {
  HMAC_KDF_PRF_TYPE_NONE = 0,
  HMAC_KDF_PRF_TYPE_FIRST = 1,
  HMAC_KDF_PRF_TYPE_SHA_1_HMAC = 1,
  HMAC_KDF_PRF_TYPE_SHA224_HMAC,
  HMAC_KDF_PRF_TYPE_SHA256_HMAC,
  HMAC_KDF_PRF_TYPE_SHA384_HMAC,
  HMAC_KDF_PRF_TYPE_SHA512_HMAC,
  HMAC_KDF_PRF_TYPE_COUNT
} HMAC_KDF_PRF_TYPE;

typedef enum {
  HMAC_KDF_KEY_TYPE_NONE = 0,
  HMAC_KDF_KEY_TYPE_FIRST = 1,
  HMAC_KDF_KEY_TYPE_AES = 1,
  HMAC_KDF_KEY_TYPE_DES3,
  HMAC_KDF_KEY_TYPE_GENERIC_SECRET,
  /* HMAC_KDF_KEY_TYPE_RC4, */
  HMAC_KDF_KEY_TYPE_COUNT
} HMAC_KDF_KEY_TYPE;

typedef enum {
  HMAC_KDF_COUNTER_FORMAT_NONE = 0,
  HMAC_KDF_COUNTER_FORMAT_FIRST = 1,
  HMAC_KDF_COUNTER_FORMAT_16 = 1,
  HMAC_KDF_COUNTER_FORMAT_32,
  HMAC_KDF_COUNTER_FORMAT_64,
  HMAC_KDF_COUNTER_FORMAT_COUNT
} HMAC_KDF_COUNTER_FORMAT;

typedef enum {
  HMAC_KDF_DKM_METHOD_NONE = 0,
  HMAC_KDF_DKM_METHOD_FIRST = 1,
  HMAC_KDF_DKM_METHOD_SUM_OF_KEYS = 1,
  /* HMAC_KDF_DKM_METHOD_SUM_OF_SEGMENTS, */
  HMAC_KDF_DKM_METHOD_COUNT
} HMAC_KDF_DKM_METHOD;

typedef enum {
  HMAC_KDF_DKM_WIDTH_NONE = 0,
  HMAC_KDF_DKM_WIDTH_FIRST = 1,
  HMAC_KDF_DKM_WIDTH_8 = 1,
  HMAC_KDF_DKM_WIDTH_16,
  HMAC_KDF_DKM_WIDTH_32,
  HMAC_KDF_DKM_WIDTH_64,
  HMAC_KDF_DKM_WIDTH_COUNT
} HMAC_KDF_DKM_WIDTH;

HMAC_KDF_PRF_TYPE hmac_kdf_get_prf_type_by_name(const char *prf_type_name);

const char * const hmac_kdf_get_prf_name_by_type(HMAC_KDF_PRF_TYPE prf_type);

HMAC_KDF_KEY_TYPE hmac_kdf_get_key_type_by_name(const char *key_type_name);

const char * const hmac_kdf_get_key_name_by_type(HMAC_KDF_KEY_TYPE key_type);

HMAC_KDF_COUNTER_FORMAT hmac_kdf_get_counter_format_by_value(
    size_t counter_format_value );

size_t hmac_kdf_get_counter_format_value(
    HMAC_KDF_COUNTER_FORMAT counter_format );

HMAC_KDF_DKM_METHOD hmac_kdf_get_dkm_method_by_value(
    size_t dkm_method_value );

size_t hmac_kdf_get_dkm_method_value(HMAC_KDF_DKM_METHOD dkm_method);

HMAC_KDF_DKM_WIDTH hmac_kdf_get_dkm_width_by_value(size_t dkm_width_value);

size_t hmac_kdf_get_dkm_width_value(HMAC_KDF_DKM_WIDTH dkm_width);

CK_RV hmac_kdf_do(
  CK_SESSION_HANDLE session,
  CK_OBJECT_HANDLE key_in,
  size_t key_in_val_len,
  HMAC_KDF_PRF_TYPE prf_type,
  HMAC_KDF_KEY_TYPE key_type,
  const void *context,
  size_t context_len,
  const void *label,
  size_t label_len,
  HMAC_KDF_COUNTER_FORMAT counter_format,
  HMAC_KDF_DKM_METHOD dkm_method,
  HMAC_KDF_DKM_WIDTH dkm_width,
  uint8_t is_token,
  CK_OBJECT_HANDLE_PTR key_out );

#ifdef  __cplusplus
}
#endif

#endif
