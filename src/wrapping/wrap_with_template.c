/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/**
 * Generate an AES key that can be used to wrap and unwrap other keys.
 * The wrapping key must be a token key. We have to manually clean it
 * up at the end of this sample.
 * @param session
 * @param key_length_bytes
 * @param key
 * @return
 */
CK_RV generate_wrapping_key(CK_SESSION_HANDLE session,
                            CK_ULONG key_length_bytes,
                            CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE wrap_template[] = {
            {CKA_ENCRYPT,  &true_val, sizeof(CK_BBOOL)}
    };

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,     &true_val,             sizeof(CK_BBOOL)},
            {CKA_WRAP,      &true_val,             sizeof(CK_BBOOL)},
            {CKA_UNWRAP,    &true_val,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,   &false_val,            sizeof(CK_BBOOL)},
            {CKA_DECRYPT,   &false_val,            sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes, sizeof(key_length_bytes)},
            {CKA_WRAP_TEMPLATE, &wrap_template, sizeof(wrap_template)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

/**
 * Generate an symmetric key suitable for encrypt/decrypt operations.
 * @param session Valid PKCS11 session.
 * @param key_length_bits Bit size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param key Pointer where the key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_symmetric_key(CK_SESSION_HANDLE session,
                            CK_ULONG key_length_bytes,
                            CK_OBJECT_HANDLE_PTR key,
                            CK_BBOOL encrypt_attr_val) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,     &true_val,             sizeof(CK_BBOOL)},
            {CKA_WRAP,      &true_val,             sizeof(CK_BBOOL)},
            {CKA_UNWRAP,    &true_val,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,   &encrypt_attr_val,     sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes, sizeof(key_length_bytes)},
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

/**
 * Get the attribute value for a key.
 * @param session
 * @param key_handle
 * @param attr_type
 * @param attr_value
 * @return
 */
CK_RV get_attribute(
      CK_SESSION_HANDLE session,
      CK_OBJECT_HANDLE key_handle,
      CK_ATTRIBUTE_TYPE attr_type,
      CK_VOID_PTR attr_value
      ) {

    CK_ATTRIBUTE attr = {0};
    attr.type = attr_type;
    attr.ulValueLen = sizeof(attr_value);
    attr.pValue = attr_value;

    return funcs->C_GetAttributeValue(
            session, key_handle, &attr, 1);
}

/**
 * Wrap a key using the wrapping_key handle.
 * @param session
 * @param wrapping_key
 * @param key_to_wrap
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV aes_wrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key_to_wrap,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG_PTR wrapped_bytes_len) {

    CK_MECHANISM mech = {CKM_CLOUDHSM_AES_KEY_WRAP_PKCS5_PAD, NULL, 0};

    return funcs->C_WrapKey(
            session,
            &mech,
            wrapping_key,
            key_to_wrap,
            wrapped_bytes,
            wrapped_bytes_len);
}

/**
 * Generate a symmetric key with specified attribute value to be wrapped.
 * @param session
 * @param wrapping_key
 * @param attr_val
 * @return
 */
CK_RV wrap_key_with_template(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE wrapping_key,
    CK_BBOOL attr_val) {

    // Generate a wrapping key.
    CK_BYTE_PTR wrapped_key = NULL;
    CK_RV rv;

    // Generate key to be wrapped.
    CK_OBJECT_HANDLE key_to_wrap = CK_INVALID_HANDLE;
    rv = generate_symmetric_key(session, 32, &key_to_wrap, attr_val);
    if (rv != CKR_OK) {
        fprintf(stderr, "Symmetric key generation failed: %lu\n", rv);
        goto done;
    }

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = aes_wrap_key(session, wrapping_key, key_to_wrap, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        rv = CKR_FUNCTION_FAILED;
        fprintf(stderr, "Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key
    rv = aes_wrap_key(session, wrapping_key, key_to_wrap, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not wrap key: %lu\n", rv);
        goto done;
    }

done:
    if (NULL != wrapped_key) {
        free(wrapped_key);
    }

    if (CK_INVALID_HANDLE != key_to_wrap) {
        CK_RV destroy_rv = funcs->C_DestroyObject(session, key_to_wrap);
        if (CKR_OK != destroy_rv) {
            fprintf(stderr, "Could not delete symmetric key: %lu\n", destroy_rv);
            rv = destroy_rv;
        }
    }
    return rv;
}

/**
 * Wrap with a wrapping template.
 * @param session
 */
CK_RV aes_wrap_with_wrap_template(CK_SESSION_HANDLE session) {
    
    // Generate a wrapping key.
    CK_OBJECT_HANDLE wrapping_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_wrapping_key(session, 32, &wrapping_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Wrapping key generation failed: %lu\n", rv);
        goto done;
    }

    rv = wrap_key_with_template(session, wrapping_key, false_val);
    if (CKR_OK == rv) {
        fprintf(stderr, "Target key with non matching template failed with rv:%lu.\n", rv);
        goto done;
    }
    printf("Successfully failed to wrap key with non matching attributes.\n");

    rv = wrap_key_with_template(session, wrapping_key, true_val);
    if (rv != CKR_OK) {
        fprintf(stderr, "Target key with matching template failed with rv:%lu.\n", rv);
        goto done;
    }
    printf("Successfully succeeded to wrap key with matching attributes.\n");

done:
    ; // Empty statement to make a declaration after a label

    // The wrapping key is a token key, so we have to clean it up.
    CK_RV cleanup_rv = funcs->C_DestroyObject(session, wrapping_key);
    if (CKR_OK != cleanup_rv) {
        fprintf(stderr, "Failed to delete wrapping key with rv: %lu\n", cleanup_rv);
    }

    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    int rc = EXIT_FAILURE;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return rc;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return rc;
    }

    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return rc;
    }

    rv = aes_wrap_with_wrap_template(session);
    if (CKR_OK != rv) {
        return rc;
    }

    pkcs11_finalize_session(session);
    return EXIT_SUCCESS;
}
