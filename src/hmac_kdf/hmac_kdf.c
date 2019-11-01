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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>

#include "common.h"
#include "hmac_kdf.h"

static const char * _HMAC_KDF_PRF_TYPE_name[] = {
  "" /* invalid */,
  "sha1-hmac",
  "sha224-hmac",
  "sha256-hmac",
  "sha384-hmac",
  "sha512-hmac",
  "" /* invalid */,
};

CK_PRF_TYPE _HMAC_KDF_PRF_TYPE_value[] = {
  CKM_VENDOR_DEFINED /* invalid */,
  CKM_SHA_1_HMAC,
  CKM_SHA224_HMAC,
  CKM_SHA256_HMAC,
  CKM_SHA384_HMAC,
  CKM_SHA512_HMAC,
  CKM_VENDOR_DEFINED /* invalid */,
};

static const char * _HMAC_KDF_KEY_TYPE_name[] = {
  "" /* invalid */,
  "aes",
  "des3",
  "generic-secret",
  "" /* invalid */,
};

CK_KEY_TYPE _HMAC_KDF_KEY_TYPE_value[] = {
  CKK_VENDOR_DEFINED /* invalid */,
  CKK_AES,
  CKK_DES3,
  CKK_GENERIC_SECRET,
  /* CKK_RC4, */
  CKK_VENDOR_DEFINED /* invalid */,
};

size_t _HMAC_KDF_COUNTER_FORMAT_value[] = {
  (size_t)0 /* invalid */,
  (size_t)16,
  (size_t)32,
  (size_t)64,
  (size_t)0 /* invalid */,
};

size_t _HMAC_KDF_DKM_METHOD_value[] = {
  (size_t)0 /* invalid */,
  (size_t)SP800_108_DKM_LENGTH_SUM_OF_KEYS,
  /* (size_t)SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS, */
  (size_t)0 /* invalid */,
};

size_t _HMAC_KDF_DKM_WIDTH_value[] = {
  (size_t)0 /* invalid */,
  (size_t)8,
  (size_t)16,
  (size_t)32,
  (size_t)64,
  (size_t)0 /* invalid */,
};

HMAC_KDF_PRF_TYPE hmac_kdf_get_prf_type_by_name(const char *prf_type_name) {
  size_t _i = (size_t)0;

  if ( NULL == prf_type_name )
    return HMAC_KDF_PRF_TYPE_NONE;

  for ( _i = HMAC_KDF_PRF_TYPE_FIRST; _i < HMAC_KDF_PRF_TYPE_COUNT; _i++ )
    if ( 0 == strcmp(_HMAC_KDF_PRF_TYPE_name[_i], prf_type_name) )
      return (HMAC_KDF_PRF_TYPE)_i;

  return HMAC_KDF_PRF_TYPE_NONE;
}

const char * const hmac_kdf_get_prf_name_by_type(HMAC_KDF_PRF_TYPE prf_type) {
  if ( ( HMAC_KDF_PRF_TYPE_NONE > prf_type ) ||
      ( HMAC_KDF_PRF_TYPE_COUNT < prf_type ) )
    return "";

  return _HMAC_KDF_PRF_TYPE_name[prf_type];
}

HMAC_KDF_KEY_TYPE hmac_kdf_get_key_type_by_name(const char *key_type_name)
{
  size_t _i = (size_t)0;

  if ( NULL == key_type_name )
    return HMAC_KDF_KEY_TYPE_NONE;

  for ( _i = HMAC_KDF_KEY_TYPE_FIRST; _i < HMAC_KDF_KEY_TYPE_COUNT; _i++ )
    if ( 0 == strcmp(_HMAC_KDF_KEY_TYPE_name[_i], key_type_name) )
      return (HMAC_KDF_KEY_TYPE)_i;

  return HMAC_KDF_KEY_TYPE_NONE;
}

const char * const hmac_kdf_get_key_name_by_type(HMAC_KDF_KEY_TYPE key_type)
{
  if ( ( HMAC_KDF_KEY_TYPE_NONE > key_type ) ||
      ( HMAC_KDF_KEY_TYPE_COUNT < key_type ) )
    return "";

  return _HMAC_KDF_KEY_TYPE_name[key_type];
}

HMAC_KDF_COUNTER_FORMAT hmac_kdf_get_counter_format_by_value(
    size_t counter_format_value ) {
  size_t _i = (size_t)0;

  for ( _i = HMAC_KDF_COUNTER_FORMAT_FIRST;
      _i < HMAC_KDF_COUNTER_FORMAT_COUNT; _i++ )
    if ( _HMAC_KDF_COUNTER_FORMAT_value[_i] == counter_format_value )
      return (HMAC_KDF_COUNTER_FORMAT)_i;

  return HMAC_KDF_COUNTER_FORMAT_NONE;
}

size_t hmac_kdf_get_counter_format_value(
    HMAC_KDF_COUNTER_FORMAT counter_format ) {
  if ( ( HMAC_KDF_COUNTER_FORMAT_NONE > counter_format ) ||
      ( HMAC_KDF_COUNTER_FORMAT_COUNT < counter_format ) )
    return (size_t)0;

  return _HMAC_KDF_COUNTER_FORMAT_value[counter_format];
}

HMAC_KDF_DKM_METHOD hmac_kdf_get_dkm_method_by_value(
    size_t dkm_method_value ) {
  size_t _i = (size_t)0;

  for ( _i = HMAC_KDF_DKM_METHOD_FIRST;
      _i < HMAC_KDF_DKM_METHOD_COUNT; _i++ )
    if ( _HMAC_KDF_DKM_METHOD_value[_i] == dkm_method_value )
      return (HMAC_KDF_DKM_METHOD)_i;

  return HMAC_KDF_DKM_METHOD_NONE;
}

size_t hmac_kdf_get_dkm_method_value(HMAC_KDF_DKM_METHOD dkm_method) {
  if ( ( HMAC_KDF_DKM_METHOD_NONE > dkm_method ) ||
      ( HMAC_KDF_DKM_METHOD_COUNT < dkm_method ) )
    return (size_t)0;

  return _HMAC_KDF_DKM_METHOD_value[dkm_method];
}

HMAC_KDF_DKM_WIDTH hmac_kdf_get_dkm_width_by_value(size_t dkm_width_value) {
  size_t _i = (size_t)0;

  for ( _i = HMAC_KDF_DKM_WIDTH_FIRST;
      _i < HMAC_KDF_DKM_WIDTH_COUNT; _i++ )
    if ( _HMAC_KDF_DKM_WIDTH_value[_i] == dkm_width_value )
      return (HMAC_KDF_DKM_WIDTH)_i;

  return HMAC_KDF_DKM_WIDTH_NONE;
}

size_t hmac_kdf_get_dkm_width_value(HMAC_KDF_DKM_WIDTH dkm_width) {
  if ( ( HMAC_KDF_DKM_WIDTH_NONE > dkm_width ) ||
      ( HMAC_KDF_DKM_WIDTH_COUNT < dkm_width ) )
    return (size_t)0;

  return _HMAC_KDF_DKM_WIDTH_value[dkm_width];
}

CK_RV hmac_kdf_do(
    /** [in] Valid PKCS11 session. */
    CK_SESSION_HANDLE session,
    /** [in] The input key handle (KDK). */
    CK_OBJECT_HANDLE key_in,
    /** [in] The size of the key referred to by key_in. */
    size_t key_in_val_len,
    /** [in] The PRF type. */
    HMAC_KDF_PRF_TYPE prf_type,
    /** [in] The derived key type. */
    HMAC_KDF_KEY_TYPE key_type,
    /** [in] The context buffer. Maybe set to NULL. */
    const void *context,
    /** [in] The size of context. Must be zero if context is NULL. */
    size_t context_len,
    /** [in] The label buffer. Maybe set to NULL. */
    const void *label,
    /** [in] The size of label. Must be zero if label is NULL. */
    size_t label_len,
    /** [in] The counter_format. */
    HMAC_KDF_COUNTER_FORMAT counter_format,
    /** [in] The DMK method. */
    HMAC_KDF_DKM_METHOD dkm_method,
    /** [in] The DKM width. */
    HMAC_KDF_DKM_WIDTH dkm_width,
    /** [in] Is the derived key a token key. */
    uint8_t is_token,
    /** [out] The derived key handle. */
    CK_OBJECT_HANDLE_PTR key_out ) {
  CK_SP800_108_COUNTER_FORMAT _counter = {};
  CK_SP800_108_DKM_LENGTH_FORMAT _dkm = {};
  CK_PRF_DATA_PARAM _data_params[] = {
    { SP800_108_COUNTER_FORMAT,
        (CK_VOID_PTR)&_counter, (CK_ULONG)sizeof(_counter) },
    { SP800_108_DKM_FORMAT, (CK_VOID_PTR)&_dkm, (CK_ULONG)sizeof(_dkm) },
    { SP800_108_PRF_LABEL, (CK_VOID_PTR)label, (CK_ULONG)label_len },
    { SP800_108_PRF_CONTEXT, (CK_VOID_PTR)context, (CK_ULONG)context_len },
  };
  CK_SP800_108_KDF_PARAMS _params = {};
  CK_MECHANISM _mechanism = {};
  CK_OBJECT_CLASS _class = CKO_SECRET_KEY;
  CK_BBOOL _true = CK_TRUE;
  CK_BBOOL _is_token = (CK_BBOOL)is_token;
  CK_ATTRIBUTE _derived_key_template[] = {
    { CKA_TOKEN, (CK_VOID_PTR)&_is_token, (CK_ULONG)sizeof(_is_token) },
    { CKA_KEY_TYPE,
        (CK_VOID_PTR)(_HMAC_KDF_KEY_TYPE_value + key_type),
        (CK_ULONG)sizeof(CK_KEY_TYPE) },
    { CKA_CLASS, &_class, (CK_ULONG)sizeof(_class) },
    { CKA_LABEL, (CK_VOID_PTR)label, (CK_ULONG)label_len },
    { CKA_VERIFY, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_ENCRYPT, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_WRAP, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_SIGN, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_DECRYPT, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_UNWRAP, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    { CKA_EXTRACTABLE, (CK_VOID_PTR)&_true, (CK_ULONG)sizeof(_true) },
    {}, /* reserve extra position for CKA_VALUE_LEN */
  };
  size_t _derived_key_template_len =
    sizeof(_derived_key_template) / sizeof(CK_ATTRIBUTE);
  CK_ULONG _value = (CK_ULONG)key_in_val_len;
  CK_RV _rv = CKR_OK;

  if (CK_INVALID_HANDLE == session)
    return CKR_ARGUMENTS_BAD;

  if (CK_INVALID_HANDLE == key_in)
    return CKR_ARGUMENTS_BAD;

  if ( ( HMAC_KDF_PRF_TYPE_NONE >= prf_type ) ||
      ( HMAC_KDF_PRF_TYPE_COUNT <= prf_type ) )
    return CKR_ARGUMENTS_BAD;

  if( NULL == context )
    return CKR_ARGUMENTS_BAD;

  if( NULL == label )
    return CKR_ARGUMENTS_BAD;

  if ( ( HMAC_KDF_COUNTER_FORMAT_NONE >= counter_format ) ||
      ( HMAC_KDF_COUNTER_FORMAT_COUNT <= counter_format ) )
    return CKR_ARGUMENTS_BAD;

  if ( ( HMAC_KDF_DKM_METHOD_NONE >= dkm_method ) ||
      ( HMAC_KDF_DKM_METHOD_COUNT <= dkm_method ) )
    return CKR_ARGUMENTS_BAD;

  if ( ( HMAC_KDF_DKM_WIDTH_NONE >= dkm_width ) ||
      ( HMAC_KDF_DKM_WIDTH_COUNT <= dkm_width ) )
    return CKR_ARGUMENTS_BAD;

  if( NULL_PTR == key_out )
    return CKR_ARGUMENTS_BAD;

  _counter.ulWidthInBits = _HMAC_KDF_COUNTER_FORMAT_value[counter_format];
  _dkm.dkmLengthMethod = _HMAC_KDF_DKM_METHOD_value[dkm_method];
  _dkm.ulWidthInBits = _HMAC_KDF_DKM_WIDTH_value[dkm_width];
  _params.prftype = _HMAC_KDF_PRF_TYPE_value[prf_type];
  _params.ulNumberOfDataParams =
      sizeof(_data_params) / sizeof(CK_PRF_DATA_PARAM);
  _params.pDataParams = (CK_VOID_PTR)_data_params;
  _mechanism.mechanism = CKM_SP800_108_COUNTER_KDF;
  _mechanism.pParameter = (CK_VOID_PTR)&_params;
  _mechanism.ulParameterLen = (CK_ULONG)sizeof(_params);
  *key_out = CK_INVALID_HANDLE;

  if( HMAC_KDF_KEY_TYPE_DES3 == key_type )
    _derived_key_template_len--;
  else
  {
    const size_t _pos = _derived_key_template_len - (size_t)1;
    _derived_key_template[_pos].type = CKA_VALUE_LEN;
    _derived_key_template[_pos].pValue = (CK_VOID_PTR)&_value;
    _derived_key_template[_pos].ulValueLen = (CK_ULONG)sizeof(_value);
  }

  // perform the key derivation
  _rv = funcs->C_DeriveKey(
    session,
    &_mechanism,
    key_in,
    (CK_ATTRIBUTE_PTR)_derived_key_template,
    (CK_ULONG)_derived_key_template_len,
    key_out );

  return _rv;
}
