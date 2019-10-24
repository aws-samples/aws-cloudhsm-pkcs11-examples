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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

#include "aes_wrapping_common.h"

#define AES_GCM_IV_LEN_BYTES 12

/**
 * Wrap a key using the wrapping_key handle.
 * The key being wrapped must have the CKA_EXTRACTABLE flag set to true.
 * @param session
 * @param wrapping_key
 * @param key_to_wrap
 * @param iv_bytes
 * @param iv_bytes_len
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV aes_gcm_wrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key_to_wrap,
        CK_BYTE_PTR iv_bytes,
        CK_ULONG iv_bytes_len,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG_PTR wrapped_bytes_len) {

    CK_GCM_PARAMS gcm_params = { iv_bytes, iv_bytes_len, 0, NULL, 0, 128 };
    CK_MECHANISM mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };

    return funcs->C_WrapKey(
            session,
            &mech,
            wrapping_key,
            key_to_wrap,
            wrapped_bytes,
            wrapped_bytes_len);
}

/**
 * Unwrap a previously wrapped key into the HSM.
 * @param session
 * @param wrapping_key
 * @param wrapped_key_type
 * @param iv_bytes
 * @param iv_bytes_len
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @param unwrapped_key_handle
 * @return
 */
CK_RV aes_gcm_unwrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_KEY_TYPE wrapped_key_type,
        CK_BYTE_PTR iv_bytes,
        CK_ULONG iv_bytes_len,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG wrapped_bytes_len,
        CK_OBJECT_HANDLE_PTR unwrapped_key_handle) {

    CK_GCM_PARAMS gcm_params = { iv_bytes, iv_bytes_len, 0, NULL, 0, 128 };
    CK_MECHANISM mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_ATTRIBUTE *template = NULL;
    CK_ULONG template_count = 0;

    switch (wrapped_key_type) {
        case CKK_DES3:
        case CKK_AES:
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)}
            };
            template_count = 4;
            break;
        case CKK_RSA:
            key_class = CKO_PRIVATE_KEY;
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)},
            };
            template_count = 4;
            break;
        case CKK_EC:
            key_class = CKO_PRIVATE_KEY;
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)},
            };
            template_count = 4;
            break;
    }

    return funcs->C_UnwrapKey(
            session,
            &mech,
            wrapping_key,
            wrapped_bytes,
            wrapped_bytes_len,
            template,
            template_count,
            unwrapped_key_handle);
}

int aes_gcm_wrap(CK_SESSION_HANDLE session) {
    // Generate a wrapping key.
    unsigned char *wrapped_key_iv_hex = NULL;
    unsigned char *wrapped_key_hex = NULL;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_BYTE wrapped_key_iv[AES_GCM_IV_LEN_BYTES] = { 0 };
    CK_ULONG wrapped_key_iv_len = sizeof(wrapped_key_iv);
    int rc = 1;

    CK_OBJECT_HANDLE wrapping_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_wrapping_key(session, 32, &wrapping_key);
    if (rv != CKR_OK) {
        printf("Wrapping key generation failed: %lu\n", rv);
        goto done;
    }

    // Generate keys to be wrapped.
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;
    rv = generate_rsa_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        printf("RSA key generation failed: %lu\n", rv);
        goto done;
    }

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = aes_gcm_wrap_key(session, wrapping_key, rsa_private_key,
                          wrapped_key_iv, wrapped_key_iv_len, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        printf("Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        printf("Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key and display the hex string.
    rv = aes_gcm_wrap_key(session, wrapping_key, rsa_private_key,
                          wrapped_key_iv, wrapped_key_iv_len, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        printf("Could not wrap key: %lu\n", rv);
        goto done;
    }

    bytes_to_new_hexstring(wrapped_key_iv, wrapped_key_iv_len, &wrapped_key_iv_hex);
    if (!wrapped_key_iv_hex) {
        printf("Could not allocate hex array\n");
        goto done;
    }
    bytes_to_new_hexstring(wrapped_key, wrapped_len, &wrapped_key_hex);
    if (!wrapped_key_hex) {
        printf("Could not allocate hex array\n");
        goto done;
    }
    printf("Wrapped Key IV: %s\n", wrapped_key_iv_hex);
    printf("Wrapped Key: %s\n", wrapped_key_hex);

    // Unwrap the key back into the HSM to verify everything worked.
    CK_OBJECT_HANDLE unwrapped_handle = CK_INVALID_HANDLE;
    rv = aes_gcm_unwrap_key(session, wrapping_key, CKK_RSA,
                            wrapped_key_iv, wrapped_key_iv_len,
                            wrapped_key, wrapped_len, &unwrapped_handle);
    if (rv != CKR_OK) {
        printf("Could not unwrap key: %lu\n", rv);
        goto done;
    }

    printf("Unwrapped bytes as object %lu\n", unwrapped_handle);

    rc = 0;

    done:
    if (NULL != wrapped_key) {
        free(wrapped_key);
    }

    if (NULL != wrapped_key_iv_hex) {
        free(wrapped_key_iv_hex);
    }

    if (NULL != wrapped_key_hex) {
        free(wrapped_key_hex);
    }

    // The wrapping key is a token key, so we have to clean it up.
    if (CK_INVALID_HANDLE != wrapping_key) {
        rv = funcs->C_DestroyObject(session, wrapping_key);
        if (CKR_OK != rv) {
            printf("Could not delete wrapping key: %lu\n", rv);
            rc = 1;
        }
    }

    return rc;
}
