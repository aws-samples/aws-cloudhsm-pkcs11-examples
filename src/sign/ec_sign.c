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

#define MAX_SIGNATURE_LENGTH 256

/**
 * Generate an EC key pair suitable for signing data and verifying signatures.
 * @param session Valid PKCS11 session.
 * @param named_curve_oid Curve to use when generating key pair. Valid curves are listed here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param named_curve_oid_len Length of the OID
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_ec_keypair(CK_SESSION_HANDLE session,
                          CK_BYTE_PTR named_curve_oid,
                          CK_ULONG named_curve_oid_len,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,    &true_val,           sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, named_curve_oid, named_curve_oid_len}
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

CK_RV ec_sign_verify(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_BYTE_PTR data = "Some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_ECDSA_SHA512;

    /**
     * Curve OIDs generated using OpenSSL on the command line.
     * Visit https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html for a list
     * of supported curves.
     * openssl ecparam -name prime256v1 -outform DER | hexdump -C
     */
    CK_BYTE prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
    rv = generate_ec_keypair(session, prime256v1, sizeof(prime256v1), &pubkey, &privkey);
    if (CKR_OK == rv) {
        printf("prime256v1 key generated. Public key handle: %lu, Private key handle: %lu\n",
            pubkey, privkey);
    } else {
        printf("prime256v1 key generation failed: %lu\n", rv);
        return rv;
    }

    rv = generate_signature(session, privkey, mechanism,
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

    rv = verify_signature(session, pubkey, mechanism, data, data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return 0;
}

CK_RV multi_part_ec_sign_verify(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_BYTE_PTR data = "Some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_ECDSA_SHA512;

    /**
     * Curve OIDs generated using OpenSSL on the command line.
     * Visit https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html for a list
     * of supported curves.
     * openssl ecparam -name prime256v1 -outform DER | hexdump -C
     */
    CK_BYTE prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
    rv = generate_ec_keypair(session, prime256v1, sizeof(prime256v1), &pubkey, &privkey);
    if (CKR_OK == rv) {
        printf("prime256v1 key generated. Public key handle: %lu, Private key handle: %lu\n",
            pubkey, privkey);
    } else {
        printf("prime256v1 key generation failed: %lu\n", rv);
        return rv;
    }

    rv = multi_part_generate_signature(session, privkey, mechanism, data,
                                       data_length, signature, &signature_length);
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

    rv = multi_part_verify_signature(session, pubkey, mechanism, data,
                                     data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    return 0;
}
