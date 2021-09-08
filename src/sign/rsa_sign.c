/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "sign.h"
#include <string.h>

/**
 * Generate an RSA key pair suitable for signing data and verifying signatures.
 * @param session Valid PKCS11 session.
 * @param key_length_bits Bit size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech;
    CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};

    mech.mechanism = CKM_RSA_X9_31_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,          &true_val,            sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_SIGN, &true_val, sizeof(CK_BBOOL)},
    };

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    return rv;
}

CK_RV rsa_sign_verify(CK_SESSION_HANDLE session) {
    CK_OBJECT_HANDLE signing_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE signing_private_key = CK_INVALID_HANDLE;

    CK_RV rv = generate_rsa_keypair(session, 2048, &signing_public_key, &signing_private_key);
    if (CKR_OK != rv) {
        printf("RSA key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR data = "Here is some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_SHA512_RSA_PKCS;

    rv = generate_signature(session, signing_private_key, mechanism,
                            data, data_length, signature, &signature_length);
    if (CKR_OK == rv) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return EXIT_FAILURE;
        }

        printf("Data: %s\n", data);
        printf("Signature: %s\n", hex_signature);
        free(hex_signature);
        hex_signature = NULL;
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    rv = verify_signature(session, signing_public_key, mechanism,
                          data, data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}

CK_RV multi_part_rsa_sign_verify(CK_SESSION_HANDLE session) {
    CK_OBJECT_HANDLE signing_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE signing_private_key = CK_INVALID_HANDLE;

    CK_RV rv = generate_rsa_keypair(session, 2048, &signing_public_key, &signing_private_key);
    if (CKR_OK != rv) {
        printf("RSA key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR data = "Here is some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type ().
    CK_MECHANISM_TYPE mechanism = CKM_SHA512_RSA_PKCS;

    rv = multi_part_generate_signature(session, signing_private_key, mechanism,
                                       data, data_length, signature, &signature_length);
    if (CKR_OK == rv) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return 1;
        }

        printf("Data: %s\n", data);
        printf("Signature: %s\n", hex_signature);
        free(hex_signature);
        hex_signature = NULL;
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return rv;
    }

    rv = multi_part_verify_signature(session, signing_public_key, mechanism,
                                     data, data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    return CKR_OK;
}
