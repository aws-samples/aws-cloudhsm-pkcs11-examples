/*
 * Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <string.h>
#include <stdlib.h>

#include <common.h>

#define ED25519_SIGNATURE_LENGTH 64

/**
 * Generate an Ed25519 key pair suitable for signing data and verifying signatures.
 *
 * @param session Valid PKCS11 session.
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
static CK_RV generate_ed25519_keypair(CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE_PTR public_key,
                                      CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;

    CK_BYTE ed25519_oid[] = {0x06, 0x03, 0x2b, 0x65, 0x70};
    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,    &true_val,    sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, ed25519_oid,  sizeof(ed25519_oid)}
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

CK_RV eddsa_sign_verify(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_BYTE_PTR data = "Some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[ED25519_SIGNATURE_LENGTH];
    CK_ULONG signature_length = ED25519_SIGNATURE_LENGTH;

    CK_MECHANISM_TYPE mechanism = CKM_CLOUDHSM_EDDSA;

    CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
    rv = generate_ed25519_keypair(session, &pubkey, &privkey);
    if (CKR_OK == rv) {
        printf("Ed25519 key generated. Public key handle: %lu, Private key handle: %lu\n",
            pubkey, privkey);
    } else {
        printf("Ed25519 key generation failed: %lu\n", rv);
        return rv;
    }

    printf("Signing with PureEdDSA (Ed25519)\n");
    CK_MECHANISM mech;
    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_SignInit(session, &mech, privkey);
    if (CKR_OK != rv) {
        printf("C_SignInit failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_Sign(session, data, data_length, signature, &signature_length);
    if (CKR_OK == rv) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return EXIT_FAILURE;
        }
        printf("Data: %s\n", data);
        printf("Ed25519 Signature: %s\n", hex_signature);
        free(hex_signature);
        hex_signature = NULL;
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    rv = funcs->C_VerifyInit(session, &mech, pubkey);
    if (CKR_OK != rv) {
        printf("C_VerifyInit failed: %lu\n", rv);
        return EXIT_FAILURE;
    }
    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    printf("Signing with HashedEdDSA (Ed25519ph)\n");
    CK_EDDSA_PARAMS eddsa_params = {CK_TRUE, 0, NULL};
    mech.mechanism = mechanism;
    mech.ulParameterLen = sizeof(eddsa_params);
    mech.pParameter = &eddsa_params;
    signature_length = ED25519_SIGNATURE_LENGTH;

    rv = funcs->C_SignInit(session, &mech, privkey);
    if (CKR_OK != rv) {
        printf("C_SignInit failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_Sign(session, data, data_length, signature, &signature_length);
    if (CKR_OK == rv) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return EXIT_FAILURE;
        }
        printf("Data: %s\n", data);
        printf("Ed25519ph Signature: %s\n", hex_signature);
        free(hex_signature);
        hex_signature = NULL;
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    rv = funcs->C_VerifyInit(session, &mech, pubkey);
    if (CKR_OK != rv) {
        printf("C_VerifyInit failed: %lu\n", rv);
        return EXIT_FAILURE;
    }
    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}

CK_RV multi_part_eddsa_sign_verify(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_BYTE_PTR data = "Some data to sign";
    CK_ULONG data_length = (CK_ULONG) strlen(data);

    CK_BYTE signature[ED25519_SIGNATURE_LENGTH];
    CK_ULONG signature_length = ED25519_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_EDDSA_PARAMS eddsa_params = {CK_TRUE, 0, NULL};
    CK_MECHANISM mech = {CKM_CLOUDHSM_EDDSA, &eddsa_params, sizeof(eddsa_params)};

    CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
    rv = generate_ed25519_keypair(session, &pubkey, &privkey);
    if (CKR_OK == rv) {
        printf("Ed25519 key generated. Public key handle: %lu, Private key handle: %lu\n",
            pubkey, privkey);
    } else {
        printf("Ed25519 key generation failed: %lu\n", rv);
        return rv;
    }
    
    printf("Signing with HashedEdDSA (Ed25519ph)\n");
    rv = funcs->C_SignInit(session, &mech, privkey);
    if (CKR_OK != rv) {
        printf("C_SignInit failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_SignUpdate(session, data, data_length);
    if (CKR_OK != rv) {
        printf("C_SignUpdate failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_SignFinal(session, signature, &signature_length);
    if (CKR_OK == rv) {
        unsigned char *hex_signature = NULL;
        bytes_to_new_hexstring(signature, signature_length, &hex_signature);
        if (!hex_signature) {
            printf("Could not allocate hex array\n");
            return CKR_HOST_MEMORY;
        }
        printf("Data: %s\n", data);
        printf("Ed25519ph Signature: %s\n", hex_signature);
        free(hex_signature);
        hex_signature = NULL;
    } else {
        printf("Signature generation failed: %lu\n", rv);
        return rv;
    }

    rv = funcs->C_VerifyInit(session, &mech, pubkey);
    if (CKR_OK != rv) {
        printf("C_VerifyInit failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_VerifyUpdate(session, data, data_length);
    if (CKR_OK != rv) {
        printf("C_VerifyUpdate failed: %lu\n", rv);
        return rv;
    }
    rv = funcs->C_VerifyFinal(session, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv)
        return EXIT_FAILURE;

    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv)
        return EXIT_FAILURE;

    printf("Single-part sign/verify\n");
    rv = eddsa_sign_verify(session);
    if (CKR_OK != rv)
        return EXIT_FAILURE;

    printf("\nMulti-part sign/verify\n");
    rv = multi_part_eddsa_sign_verify(session);
    if (CKR_OK != rv)
        return EXIT_FAILURE;

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
