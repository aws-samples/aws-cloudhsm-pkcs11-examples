#ifndef _CLOUDHSM_VENDOR_DEFINES_H_
#define _CLOUDHSM_VENDOR_DEFINES_H_

#include "pkcs11t.h"

#define CKM_DES3_NIST_WRAP             (CKM_VENDOR_DEFINED | 0x00008000UL)
#define CKM_CLOUDHSM_AES_GCM           (CKM_VENDOR_DEFINED | CKM_AES_GCM)

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

#endif

