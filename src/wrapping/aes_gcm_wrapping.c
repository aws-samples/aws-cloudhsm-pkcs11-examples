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
#include <stdlib.h>
#include <common.h>

#include "aes_wrapping_common.h"

#define AES_GCM_IV_LEN_BYTES 12

CK_RV aes_gcm_wrapping(CK_SESSION_HANDLE session) {
    // Generate a wrapping key.
    unsigned char *wrapped_key_iv_hex = NULL;
    unsigned char *wrapped_key_hex = NULL;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_BYTE wrapped_key_iv[AES_GCM_IV_LEN_BYTES] = { 0 };
    CK_ULONG wrapped_key_iv_len = sizeof(wrapped_key_iv);

    CK_OBJECT_HANDLE wrapping_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_aes_token_key_for_wrapping(session, 32, &wrapping_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Wrapping key generation failed: %lu\n", rv);
        goto done;
    }

    // Generate keys to be wrapped.
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;
    rv = generate_rsa_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "RSA key generation failed: %lu\n", rv);
        goto done;
    }

    CK_GCM_PARAMS gcm_params = { wrapped_key_iv, wrapped_key_iv_len, 0, NULL, 0, 128 };
    CK_MECHANISM mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = aes_wrap_key(session, &mech, wrapping_key, rsa_private_key, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        fprintf(stderr, "Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key with AES-GCM mechanism
    rv = aes_wrap_key(session, &mech, wrapping_key, rsa_private_key, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not wrap key: %lu\n", rv);
        goto done;
    }

    // Display the hex string.
    bytes_to_new_hexstring(wrapped_key_iv, wrapped_key_iv_len, &wrapped_key_iv_hex);
    if (!wrapped_key_iv_hex) {
        fprintf(stderr, "Could not allocate hex array\n");
        goto done;
    }
    bytes_to_new_hexstring(wrapped_key, wrapped_len, &wrapped_key_hex);
    if (!wrapped_key_hex) {
        fprintf(stderr, "Could not allocate hex array\n");
        goto done;
    }
    printf("Wrapped Key IV: %s\n", wrapped_key_iv_hex);
    printf("Wrapped Key: %s\n", wrapped_key_hex);

    // Unwrap the key back into the HSM to verify everything worked.
    CK_OBJECT_HANDLE unwrapped_handle = CK_INVALID_HANDLE;
    rv = aes_unwrap_key(session, &mech, wrapping_key, CKK_RSA, wrapped_key, wrapped_len, &unwrapped_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not unwrap key: %lu\n", rv);
        goto done;
    }
    printf("Unwrapped bytes as object %lu\n", unwrapped_handle);

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

    printf("Running AES-GCM wrap...\n");
    rv = aes_gcm_wrapping(session);
    if (CKR_OK != rv) {
        return rc;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
