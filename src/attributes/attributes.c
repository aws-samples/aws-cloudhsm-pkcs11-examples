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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "common.h"
#include "attributes.h"

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    const char *name;
} attributes_type;

static const attributes_type attributes_types[] = {
        { CKA_CLASS, "CKA_CLASS", },
        { CKA_TOKEN, "CKA_TOKEN", },
        { CKA_PRIVATE, "CKA_PRIVATE", },
        { CKA_LABEL, "CKA_LABEL", },
        { CKA_APPLICATION, "CKA_APPLICATION", },
        { CKA_VALUE, "CKA_VALUE", },
        { CKA_OBJECT_ID, "CKA_OBJECT_ID", },
        { CKA_CERTIFICATE_TYPE, "CKA_CERTIFICATE_TYPE", },
        { CKA_ISSUER, "CKA_ISSUER", },
        { CKA_SERIAL_NUMBER, "CKA_SERIAL_NUMBER", },
        { CKA_AC_ISSUER, "CKA_AC_ISSUER", },
        { CKA_OWNER, "CKA_OWNER", },
        { CKA_ATTR_TYPES, "CKA_ATTR_TYPES", },
        { CKA_TRUSTED, "CKA_TRUSTED", },
        { CKA_CERTIFICATE_CATEGORY, "CKA_CERTIFICATE_CATEGORY", },
        { CKA_JAVA_MIDP_SECURITY_DOMAIN, "CKA_JAVA_MIDP_SECURITY_DOMAIN", },
        { CKA_URL, "CKA_URL", },
        { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", },
        { CKA_HASH_OF_ISSUER_PUBLIC_KEY, "CKA_HASH_OF_ISSUER_PUBLIC_KEY", },
        { CKA_NAME_HASH_ALGORITHM, "CKA_NAME_HASH_ALGORITHM", },
        { CKA_CHECK_VALUE, "CKA_CHECK_VALUE", },
        { CKA_KEY_TYPE, "CKA_KEY_TYPE", },
        { CKA_SUBJECT, "CKA_SUBJECT", },
        { CKA_ID, "CKA_ID", },
        { CKA_SENSITIVE, "CKA_SENSITIVE", },
        { CKA_ENCRYPT, "CKA_ENCRYPT", },
        { CKA_DECRYPT, "CKA_DECRYPT", },
        { CKA_WRAP, "CKA_WRAP", },
        { CKA_UNWRAP, "CKA_UNWRAP", },
        { CKA_SIGN, "CKA_SIGN", },
        { CKA_SIGN_RECOVER, "CKA_SIGN_RECOVER", },
        { CKA_VERIFY, "CKA_VERIFY", },
        { CKA_VERIFY_RECOVER, "CKA_VERIFY_RECOVER", },
        { CKA_DERIVE, "CKA_DERIVE", },
        { CKA_START_DATE, "CKA_START_DATE", },
        { CKA_END_DATE, "CKA_END_DATE", },
        { CKA_MODULUS, "CKA_MODULUS", },
        { CKA_MODULUS_BITS, "CKA_MODULUS_BITS", },
        { CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT", },
        { CKA_PRIVATE_EXPONENT, "CKA_PRIVATE_EXPONENT", },
        { CKA_PRIME_1, "CKA_PRIME_1", },
        { CKA_PRIME_2, "CKA_PRIME_2", },
        { CKA_EXPONENT_1, "CKA_EXPONENT_1", },
        { CKA_EXPONENT_2, "CKA_EXPONENT_2", },
        { CKA_COEFFICIENT, "CKA_COEFFICIENT", },
        { CKA_PUBLIC_KEY_INFO, "CKA_PUBLIC_KEY_INFO", },
        { CKA_PRIME, "CKA_PRIME", },
        { CKA_SUBPRIME, "CKA_SUBPRIME", },
        { CKA_BASE, "CKA_BASE", },
        { CKA_PRIME_BITS, "CKA_PRIME_BITS", },
        { CKA_SUBPRIME_BITS, "CKA_SUBPRIME_BITS", },
        { CKA_SUB_PRIME_BITS, "CKA_SUB_PRIME_BITS", },
        { CKA_VALUE_BITS, "CKA_VALUE_BITS", },
        { CKA_VALUE_LEN, "CKA_VALUE_LEN", },
        { CKA_EXTRACTABLE, "CKA_EXTRACTABLE", },
        { CKA_LOCAL, "CKA_LOCAL", },
        { CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE", },
        { CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE", },
        { CKA_KEY_GEN_MECHANISM, "CKA_KEY_GEN_MECHANISM", },
        { CKA_MODIFIABLE, "CKA_MODIFIABLE", },
        { CKA_COPYABLE, "CKA_COPYABLE", },
        { CKA_DESTROYABLE, "CKA_DESTROYABLE", },
        { CKA_ECDSA_PARAMS, "CKA_ECDSA_PARAMS", },
        { CKA_EC_PARAMS, "CKA_EC_PARAMS", },
        { CKA_EC_POINT, "CKA_EC_POINT", },
        { CKA_SECONDARY_AUTH, "CKA_SECONDARY_AUTH", },
        { CKA_AUTH_PIN_FLAGS, "CKA_AUTH_PIN_FLAGS", },
        { CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE", },
        { CKA_WRAP_WITH_TRUSTED, "CKA_WRAP_WITH_TRUSTED", },
        { CKA_WRAP_TEMPLATE, "CKA_WRAP_TEMPLATE", },
        { CKA_UNWRAP_TEMPLATE, "CKA_UNWRAP_TEMPLATE", },
        { CKA_DERIVE_TEMPLATE, "CKA_DERIVE_TEMPLATE", },
        { CKA_OTP_FORMAT, "CKA_OTP_FORMAT", },
        { CKA_OTP_LENGTH, "CKA_OTP_LENGTH", },
        { CKA_OTP_TIME_INTERVAL, "CKA_OTP_TIME_INTERVAL", },
        { CKA_OTP_USER_FRIENDLY_MODE, "CKA_OTP_USER_FRIENDLY_MODE", },
        { CKA_OTP_CHALLENGE_REQUIREMENT, "CKA_OTP_CHALLENGE_REQUIREMENT", },
        { CKA_OTP_TIME_REQUIREMENT, "CKA_OTP_TIME_REQUIREMENT", },
        { CKA_OTP_COUNTER_REQUIREMENT, "CKA_OTP_COUNTER_REQUIREMENT", },
        { CKA_OTP_PIN_REQUIREMENT, "CKA_OTP_PIN_REQUIREMENT", },
        { CKA_OTP_COUNTER, "CKA_OTP_COUNTER", },
        { CKA_OTP_TIME, "CKA_OTP_TIME", },
        { CKA_OTP_USER_IDENTIFIER, "CKA_OTP_USER_IDENTIFIER", },
        { CKA_OTP_SERVICE_IDENTIFIER, "CKA_OTP_SERVICE_IDENTIFIER", },
        { CKA_OTP_SERVICE_LOGO, "CKA_OTP_SERVICE_LOGO", },
        { CKA_OTP_SERVICE_LOGO_TYPE, "CKA_OTP_SERVICE_LOGO_TYPE", },
        { CKA_GOSTR3410_PARAMS, "CKA_GOSTR3410_PARAMS", },
        { CKA_GOSTR3411_PARAMS, "CKA_GOSTR3411_PARAMS", },
        { CKA_GOST28147_PARAMS, "CKA_GOST28147_PARAMS", },
        { CKA_HW_FEATURE_TYPE, "CKA_HW_FEATURE_TYPE", },
        { CKA_RESET_ON_INIT, "CKA_RESET_ON_INIT", },
        { CKA_HAS_RESET, "CKA_HAS_RESET", },
        { CKA_PIXEL_X, "CKA_PIXEL_X", },
        { CKA_PIXEL_Y, "CKA_PIXEL_Y", },
        { CKA_RESOLUTION, "CKA_RESOLUTION", },
        { CKA_CHAR_ROWS, "CKA_CHAR_ROWS", },
        { CKA_CHAR_COLUMNS, "CKA_CHAR_COLUMNS", },
        { CKA_COLOR, "CKA_COLOR", },
        { CKA_BITS_PER_PIXEL, "CKA_BITS_PER_PIXEL", },
        { CKA_CHAR_SETS, "CKA_CHAR_SETS", },
        { CKA_ENCODING_METHODS, "CKA_ENCODING_METHODS", },
        { CKA_MIME_TYPES, "CKA_MIME_TYPES", },
        { CKA_MECHANISM_TYPE, "CKA_MECHANISM_TYPE", },
        { CKA_REQUIRED_CMS_ATTRIBUTES, "CKA_REQUIRED_CMS_ATTRIBUTES", },
        { CKA_DEFAULT_CMS_ATTRIBUTES, "CKA_DEFAULT_CMS_ATTRIBUTES", },
        { CKA_SUPPORTED_CMS_ATTRIBUTES, "CKA_SUPPORTED_CMS_ATTRIBUTES", },
        { CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS", },
        { CKA_VENDOR_DEFINED, "CKA_VENDOR_DEFINED", },
};

static const size_t attributes_types_len =
        (sizeof(attributes_types)/sizeof(attributes_types[0]));

/**
 * Get single object attribute.
 *
 * @returns CK_RV Value returned by the PKCS#11 library. This will indicate
 *   success or failure.
 */
CK_RV attributes_get(
        /** [in] Valid PKCS11 session. */
        CK_SESSION_HANDLE session,
        /** [in] The object handle. */
        CK_OBJECT_HANDLE object,
        /** [in] The attribute type. */
        CK_ATTRIBUTE_TYPE type,
        /** [out] The output buffer. Set to NULL to get the required buffer
         *    size in buf_len. */
        uint8_t *buf,
        /** [in, out] The size of buf. */
        CK_ULONG_PTR buf_len ) {
    CK_ATTRIBUTE attr[] = { { type, NULL_PTR, (CK_ULONG)0 } };
    CK_RV rv = CKR_OK;

    if (CK_INVALID_HANDLE == session) {
        return CKR_ARGUMENTS_BAD;
    }

    if (CK_INVALID_HANDLE == object) {
        return CKR_ARGUMENTS_BAD;
    }

    if (NULL == buf_len) {
        return CKR_ARGUMENTS_BAD;
    }

    if (buf) {
        /* this assumes that buf_len is sufficiently large,
         * set buf to NULL to get the required size
         */
        attr[0].pValue = (CK_BYTE_PTR)buf;
        attr[0].ulValueLen = (CK_ULONG) *buf_len;
        rv = funcs->C_GetAttributeValue(
            session,
            object,
            (CK_ATTRIBUTE_PTR)&attr[0].type,
            (CK_ULONG)1 );
        if (rv != CKR_OK) {
            goto attributes_get_1;
        }
    } else {
        rv = funcs->C_GetAttributeValue(
                session,
                object,
                (CK_ATTRIBUTE_PTR)&attr[0].type,
                (CK_ULONG)1 );
        if (rv != CKR_OK)
            goto attributes_get_1;

        *buf_len = (size_t)attr[0].ulValueLen;
    }

    attributes_get_1:

    return rv;
}

/**
 * Output attribute value buffer in a formatted fashion.
 *
 * @returns 0 on success, EXIT_FAILURE otherwise.
 */
int attributes_output(
        /** [in] The input buffer. */
        uint8_t *buf,
        /** [in] The size of buf. */
        size_t buf_len,
        /** [in] The output file handle. */
        FILE *f) {
    size_t i = (size_t)0;

    if (NULL == buf)
        return EXIT_FAILURE;

    if (NULL == f)
        return EXIT_FAILURE;

    for (i = (size_t)0; i < buf_len; i++) {
        fprintf(f, "%02x ", buf[i]);
    }

    fprintf(f, "\n");
    return 0;
}

/**
 * Output all attributes belonging to an object.
 *
 * Iterates through all possible attributes of an object, finds the ones that
 *   are valid using attributes_get(), and outputs them using
 *   attributes_output().
 *
 * @returns CK_RV Value returned by the PKCS#11 library. This will indicate
 *   success or failure.
 */
CK_RV attributes_output_all(
        /** [in] Valid PKCS11 session. */
        CK_SESSION_HANDLE session,
        /** [in] The object handle. */
        CK_OBJECT_HANDLE object,
        /** [in] The output file handle. */
        FILE *f ) {

    uint8_t* attr_avail = calloc(attributes_types_len, sizeof(uint8_t));
    if (NULL == attr_avail) {
        fprintf(f, "ERROR: failed to allocate memory\n");
        return CKR_HOST_MEMORY;
    }

    size_t i = (size_t)0;
    CK_RV rv = CKR_OK;

    if (CK_INVALID_HANDLE == session)
        return CKR_ARGUMENTS_BAD;

    if (CK_INVALID_HANDLE == object)
        return CKR_ARGUMENTS_BAD;

    if (NULL == f)
        return CKR_ARGUMENTS_BAD;

    for (i = (size_t)0; i < attributes_types_len; i++) {
        CK_ATTRIBUTE attr[] = {
                { attributes_types[i].type, NULL_PTR, (CK_ULONG)0 } };
        CK_RV rv_local = CKR_OK;

        rv_local = funcs->C_GetAttributeValue(
            session,
            object,
            (CK_ATTRIBUTE_PTR)&attr[0].type,
            (CK_ULONG)1 );
        if (CKR_OK == rv_local) {
            attr_avail[i] = UINT8_C(1);
        }

        if (CKR_OBJECT_HANDLE_INVALID == rv_local) {
            fprintf(f, "ERROR: object [%lu] is not valid\n", object);
            rv = CKR_HOST_MEMORY;
            goto attributes_output_all_1;
        }
    }

    fprintf(f, "Attributes for object %lu:\n", object);

    for (i = (size_t)0; i < attributes_types_len; i++) {
        uint8_t *buf = NULL;
        CK_ULONG buf_len = (CK_ULONG)0;
        CK_RV rv_local = CKR_OK;

        if( UINT8_C(0) == attr_avail[i] )
            continue;

        rv_local = attributes_get(
                session, object, attributes_types[i].type, NULL, &buf_len );
        switch (rv_local)
        {
            case CKR_HOST_MEMORY:
                fprintf(f, "ERROR: failed to allocate memory\n");
                rv = rv_local;
                goto attributes_output_all_1;
                break;
            case CKR_OK:
                break;
            default:
                goto attributes_output_all_1;
                break;
        }

        buf = (uint8_t *)calloc(buf_len, (size_t)1);
        if (NULL == buf) {
            fprintf(f, "ERROR: failed to allocate memory\n");
            rv = CKR_HOST_MEMORY;
            break;
        }

        rv_local = attributes_get(
                session, object, attributes_types[i].type, buf, &buf_len );
        switch (rv_local)
        {
            case CKR_HOST_MEMORY:
                fprintf(f, "ERROR: failed to allocate memory\n");
                rv = rv_local;
                break;
            case CKR_OK:
                fprintf(f,  "INFO : Attribute [0x%010lu] %30s:\n  0x ",
                       attributes_types[i].type, attributes_types[i].name );
                attributes_output(buf, buf_len, f);
                break;
            default:
                break;
        }

        free(buf);

        if (CKR_OK != rv_local)
            break;
    }

    attributes_output_all_1:

    fprintf(f, "\n");
    free(attr_avail);
    return rv;
}
