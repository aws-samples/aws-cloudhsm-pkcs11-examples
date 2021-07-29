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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <common.h>

/**
 * Generate an AES key that can be wrapped by an RSA key.
 * @param session
 * @param key_length_bytes
 * @param key
 * @return
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,     &false_val,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,   &true_val,            sizeof(CK_BBOOL)},
            {CKA_DECRYPT,   &true_val,            sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes, sizeof(key_length_bytes)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

/**
 * Generate an RSA key pair that is able to wrap and unwrap an AES key.
 * These keys must be token keys.
 * @param session Valid PKCS11 session.
 * @param key_length_bits Bit size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_wrapping_keypair(CK_SESSION_HANDLE session,
                                CK_ULONG key_length_bits,
                                CK_OBJECT_HANDLE_PTR public_key,
                                CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_RSA_X9_31_KEY_PAIR_GEN, NULL, 0};
    CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_TOKEN,           &true_val,           sizeof(CK_BBOOL)},
            {CKA_WRAP,            &true_val, sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_TOKEN,       &true_val, sizeof(CK_BBOOL)},
            {CKA_UNWRAP,      &true_val, sizeof(CK_BBOOL)},
    };

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    return rv;
}

/**
 * Wrap a key using the RSA OAEP mechanism.
 * The key being wrapped must have the CKA_EXTRACTABLE flag set to true.
 * @param session
 * @param wrapping_key
 * @param key_to_wrap
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV rsa_oaep_wrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key_to_wrap,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG_PTR wrapped_bytes_len) {


    CK_RSA_PKCS_OAEP_PARAMS params = { CKM_SHA256, CKG_MGF1_SHA256  };
    CK_MECHANISM oaep_mech = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

    // First, get the just the length of wrapped key
    return funcs->C_WrapKey(session,
                            &oaep_mech,
                            wrapping_key,
                            key_to_wrap,
                            wrapped_bytes,
                            wrapped_bytes_len);
}

/**
 * Unwrap a previously wrapped key into the HSM.
 * This demonstrates how to use the OAEP unwrap mechanism.
 * @param session
 * @param wrapping_key
 * @param wrapped_key_type
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @param unwrapped_key_handle
 * @return
 */
CK_RV rsa_oaep_unwrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_KEY_TYPE wrapped_key_type,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG wrapped_bytes_len,
        CK_OBJECT_HANDLE_PTR unwrapped_key_handle) {

    CK_RSA_PKCS_OAEP_PARAMS params = { CKM_SHA256, CKG_MGF1_SHA256  };
    CK_MECHANISM oaep_mech = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
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
            &oaep_mech,
            wrapping_key,
            wrapped_bytes,
            wrapped_bytes_len,
            template,
            template_count,
            unwrapped_key_handle);
}

/**
 * Wrap a key using the RSA AES wrapping method.
 * The key being wrapped must have the CKA_EXTRACTABLE flag set to true.
 * The first aes_key_bits (256) will be the RSA OAEP wrapped ephemeral key.
 * The last 40 bytes will be the key_to_wrap, wrapped with the ephemeral key.
 * @param session
 * @param wrapping_key
 * @param key_to_wrap
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV rsa_aes_wrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key_to_wrap,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG_PTR wrapped_bytes_len) {

    CK_ULONG aes_key_bits = 256;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params = { CKM_SHA256, CKG_MGF1_SHA256  };
    CK_RSA_AES_KEY_WRAP_PARAMS params = { aes_key_bits, &oaep_params };
    CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &params, sizeof(params) };

    // First, get the just the length of wrapped key
    return funcs->C_WrapKey(session,
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
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @param unwrapped_key_handle
 * @return
 */
CK_RV rsa_aes_unwrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_KEY_TYPE wrapped_key_type,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG wrapped_bytes_len,
        CK_OBJECT_HANDLE_PTR unwrapped_key_handle) {

    CK_ULONG aes_key_bits = 256;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params = { CKM_SHA256, CKG_MGF1_SHA256  };
    CK_RSA_AES_KEY_WRAP_PARAMS params = { aes_key_bits, &oaep_params };
    CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &params, sizeof(params) };

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

/**
 * Demonstrate how to wrap with RSA OAEP padding.
 * @param session
 * @return
 */
CK_RV rsa_oaep_wrap(CK_SESSION_HANDLE session) {
    unsigned char *hex_array = NULL;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;

    // Generate a wrapping key.
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_aes_key(session, 32, &aes_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Wrapping key generation failed: %lu\n", rv);
        goto done;
    }

    // Generate keys to be wrapped.
    rv = generate_wrapping_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "RSA key generation failed: %lu\n", rv);
        goto done;
    }

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = rsa_oaep_wrap_key(session, rsa_public_key, aes_key, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        fprintf(stderr, "Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key and display the hex string.
    rv = rsa_oaep_wrap_key(session, rsa_public_key, aes_key, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not wrap key: %lu\n", rv);
        goto done;
    }

    bytes_to_new_hexstring(wrapped_key, wrapped_len, &hex_array);
    if (!hex_array) {
        fprintf(stderr, "Could not allocate hex array\n");
        goto done;
    }
    printf("Wrapped key: %s\n", hex_array);

    // Unwrap the key back into the HSM to verify everything worked.
    CK_OBJECT_HANDLE unwrapped_handle = CK_INVALID_HANDLE;
    rv = rsa_oaep_unwrap_key(session, rsa_private_key, CKK_AES, wrapped_key, wrapped_len, &unwrapped_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not unwrap key: %lu\n", rv);
        goto done;
    }
    printf("Unwrapped bytes as object %lu\n", unwrapped_handle);

    done:
    if (NULL != wrapped_key) {
        free(wrapped_key);
    }

    if (NULL != hex_array) {
        free(hex_array);
    }

    // The wrapping keys are token keys, so we have to clean it up.
    CK_RV public_cleanup_rv = funcs->C_DestroyObject(session, rsa_public_key);
    if (CKR_OK != public_cleanup_rv) {
        fprintf(stderr, "Failed to delete public key with rv: %lu\n", public_cleanup_rv);
    }

    CK_RV private_cleanup_rv = funcs->C_DestroyObject(session, rsa_private_key);
    if (CKR_OK != private_cleanup_rv) {
        fprintf(stderr, "Failed to delete private key with rv: %lu\n", private_cleanup_rv);
    }

    return rv;
}

/**
 * Demonstrate RSA AES wrapping.
 * @param session
 * @return
 */
CK_RV rsa_aes_wrap(CK_SESSION_HANDLE session) {
    CK_BYTE_PTR wrapped_key = NULL;
    unsigned char *hex_array = NULL;
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;

    // Generate a wrapping key.
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_RV rv = generate_aes_key(session, 32, &aes_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Wrapping key generation failed: %lu\n", rv);
        goto done;
    }

    // Generate keys to be wrapped.
    rv = generate_wrapping_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "RSA key generation failed: %lu\n", rv);
        goto done;
    }

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = rsa_aes_wrap_key(session, rsa_public_key, aes_key, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        fprintf(stderr, "Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key and display the hex string.
    rv = rsa_aes_wrap_key(session, rsa_public_key, aes_key, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not wrap key: %lu\n", rv);
        goto done;
    }

    bytes_to_new_hexstring(wrapped_key, wrapped_len, &hex_array);
    if (!hex_array) {
        fprintf(stderr, "Could not allocate hex array\n");
        goto done;
    }
    printf("Wrapped key: %s\n", hex_array);

    // Unwrap the key back into the HSM to verify everything worked.
    CK_OBJECT_HANDLE unwrapped_handle = CK_INVALID_HANDLE;
    rv = rsa_aes_unwrap_key(session, rsa_private_key, CKK_AES, wrapped_key, wrapped_len, &unwrapped_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not unwrap key: %lu\n", rv);
        goto done;
    }
    printf("Unwrapped bytes as object %lu\n", unwrapped_handle);

    done:
    if (NULL != wrapped_key) {
        free(wrapped_key);
    }

    if (NULL != hex_array) {
        free(hex_array);
    }

    // The wrapping keys are token keys, so we have to clean it up.
    CK_RV public_cleanup_rv = funcs->C_DestroyObject(session, rsa_public_key);
    if (CKR_OK != public_cleanup_rv) {
        fprintf(stderr, "Failed to delete public key with rv: %lu\n", public_cleanup_rv);
    }

    CK_RV private_cleanup_rv = funcs->C_DestroyObject(session, rsa_private_key);
    if (CKR_OK != private_cleanup_rv) {
        fprintf(stderr, "Failed to delete private key with rv: %lu\n", private_cleanup_rv);
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

    printf("Running RSA wrap with OAEP padding...\n");
    rv = rsa_oaep_wrap(session);
    if (CKR_OK != rv) {
        return rc;
    }

    printf("Running RSA AES wrap...\n");
    rv = rsa_aes_wrap(session);
    if (CKR_OK != rv) {
        return rc;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
