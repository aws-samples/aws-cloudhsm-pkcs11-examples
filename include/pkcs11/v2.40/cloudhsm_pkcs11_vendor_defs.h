/*
 * Copyright (c) 2017, Cavium, Inc. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Cavium, Inc. nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY CAVIUM INC. ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CAVIUM, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _CLOUDHSM_PKCS11_VENDOR_DEFS_H_
#define _CLOUDHSM_PKCS11_VENDOR_DEFS_H_

#include "pkcs11.h"

#ifdef _WIN32
#pragma pack(push, cloudhsm_pkcs11_vendor_defines, 1)
#endif

#define CKM_DES3_NIST_WRAP             (CKM_VENDOR_DEFINED | 0x00008000UL)
#define CKM_CLOUDHSM_AES_GCM           (CKM_VENDOR_DEFINED | CKM_AES_GCM)

// More information can be found at https://docs.aws.amazon.com/cloudhsm/latest/userguide/manage-aes-key-wrapping.html
#define CKM_CLOUDHSM_AES_KEY_WRAP_NO_PAD        (CKM_VENDOR_DEFINED | CKM_AES_KEY_WRAP)
#define CKM_CLOUDHSM_AES_KEY_WRAP_PKCS5_PAD     (CKM_VENDOR_DEFINED | CKM_AES_KEY_WRAP_PAD)
#define CKM_CLOUDHSM_AES_KEY_WRAP_ZERO_PAD     (CKM_VENDOR_DEFINED | 0x0000216FUL)

/* HMAC KDF Mechanism */
#define CKM_SP800_108_COUNTER_KDF      (CKM_VENDOR_DEFINED | 0x00000001UL)

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

#ifdef _WIN32
#pragma pack(pop, cloudhsm_pkcs11_vendor_defines)
#endif

#endif /* _CLOUDHSM_PKCS11_VENDOR_DEFS_H_ */
