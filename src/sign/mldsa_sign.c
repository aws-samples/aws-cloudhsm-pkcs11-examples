/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* ML-DSA-87 has the largest signature size at 4627 bytes */
#define MLDSA_MAX_SIGNATURE_LENGTH 4627

/* External mu is always 64 bytes */
#define MLDSA_EXTERNAL_MU_LENGTH 64

/**
 * Generate an ML-DSA key pair suitable for signing data and verifying signatures.
 * @param session Valid PKCS11 session.
 * @param parameter_set ML-DSA parameter set.
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library.
 */
CK_RV generate_mldsa_keypair(CK_SESSION_HANDLE session,
                             CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE parameter_set,
                             CK_OBJECT_HANDLE_PTR public_key,
                             CK_OBJECT_HANDLE_PTR private_key) {
    CK_MECHANISM mech = {CKM_CLOUDHSM_ML_DSA_KEY_PAIR_GEN, NULL, 0};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,                 &true_val,      sizeof(CK_BBOOL)},
            {CKA_TOKEN,                  &false_val,     sizeof(CK_BBOOL)},
            {CKA_CLOUDHSM_PARAMETER_SET, &parameter_set, sizeof(CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_SIGN,                   &true_val,      sizeof(CK_BBOOL)},
            {CKA_TOKEN,                  &false_val,     sizeof(CK_BBOOL)},
            {CKA_CLOUDHSM_PARAMETER_SET, &parameter_set, sizeof(CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE)},
    };

    return funcs->C_GenerateKeyPair(session,
                                    &mech,
                                    public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                    private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                    public_key,
                                    private_key);
}

/**
 * Sign data using ML-DSA and verify the signature.
 * This is a single-part operation using CKM_CLOUDHSM_ML_DSA (pure raw mode).
 *
 * @param session Valid PKCS11 session.
 * @param private_key Private key handle for signing.
 * @param public_key Public key handle for verification.
 * @return CK_RV
 */
CK_RV mldsa_pure_sign_verify(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE private_key,
                              CK_OBJECT_HANDLE public_key) {
    CK_RV rv;
    CK_BYTE data[] = "ML-DSA pure raw sign/verify test data";
    CK_ULONG data_length = (CK_ULONG)(sizeof(data) - 1);
    CK_BYTE signature[MLDSA_MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MLDSA_MAX_SIGNATURE_LENGTH;
    CK_MECHANISM mech = {CKM_CLOUDHSM_ML_DSA, NULL, 0};

    /* Sign */
    rv = funcs->C_SignInit(session, &mech, private_key);
    if (CKR_OK != rv) {
        printf("C_SignInit failed: %lu\n", rv);
        return rv;
    }

    rv = funcs->C_Sign(session, data, data_length, signature, &signature_length);
    if (CKR_OK != rv) {
        printf("C_Sign failed: %lu\n", rv);
        return rv;
    }
    printf("Signature length: %lu bytes\n", signature_length);

    /* Verify */
    rv = funcs->C_VerifyInit(session, &mech, public_key);
    if (CKR_OK != rv) {
        printf("C_VerifyInit failed: %lu\n", rv);
        return rv;
    }

    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    if (CKR_OK != rv) {
        printf("C_Verify failed: %lu\n", rv);
        return rv;
    }

    printf("Pure raw sign/verify successful\n");
    return CKR_OK;
}

/**
 * Sign using ML-DSA external mu mode and verify the signature.
 * In external mu mode, the caller passes a pre-computed 64-byte mu value
 * instead of raw data. The mechanism is CKM_CLOUDHSM_EXT_MU_ML_DSA.
 *
 * @param session Valid PKCS11 session.
 * @param private_key Private key handle for signing.
 * @param public_key Public key handle for verification.
 * @return CK_RV
 */
CK_RV mldsa_external_mu_sign_verify(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE private_key,
                                     CK_OBJECT_HANDLE public_key) {
    CK_RV rv;
    /* Pre-computed mu value (64 bytes). In practice, this is derived by
     * computing the public key and message using a hash function. See 
     * CloudHSM documentation for details on external mu mode. */
    CK_BYTE mu[MLDSA_EXTERNAL_MU_LENGTH] = {
        0x0e, 0x01, 0x5b, 0x91, 0x68, 0x1b, 0xf5, 0xf6, 0xde, 0x8d, 0x05, 0x12,
        0x6c, 0x9d, 0x3d, 0xfc, 0xd9, 0xa9, 0xee, 0x98, 0x5b, 0xef, 0x5e, 0x11,
        0x4e, 0x45, 0x9d, 0x34, 0x0c, 0x10, 0xa9, 0xdf, 0x6e, 0xec, 0xce, 0xd7,
        0x09, 0x66, 0xc8, 0xf0, 0x4a, 0x1a, 0x21, 0xe1, 0x9c, 0x64, 0x25, 0x30,
        0x23, 0x36, 0x86, 0xea, 0x40, 0xda, 0xbd, 0x90, 0xd8, 0xc4, 0x27, 0x1a,
        0x12, 0x27, 0x1b, 0x4f
    };
    CK_BYTE signature[MLDSA_MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MLDSA_MAX_SIGNATURE_LENGTH;
    CK_MECHANISM mech = {CKM_CLOUDHSM_EXT_MU_ML_DSA, NULL, 0};

    /* Sign with external mu */
    rv = funcs->C_SignInit(session, &mech, private_key);
    if (CKR_OK != rv) {
        printf("C_SignInit (external mu) failed: %lu\n", rv);
        return rv;
    }

    rv = funcs->C_Sign(session, mu, MLDSA_EXTERNAL_MU_LENGTH, signature, &signature_length);
    if (CKR_OK != rv) {
        printf("C_Sign (external mu) failed: %lu\n", rv);
        return rv;
    }
    printf("Signature length: %lu bytes\n", signature_length);

    /* Verify with external mu */
    rv = funcs->C_VerifyInit(session, &mech, public_key);
    if (CKR_OK != rv) {
        printf("C_VerifyInit (external mu) failed: %lu\n", rv);
        return rv;
    }

    rv = funcs->C_Verify(session, mu, MLDSA_EXTERNAL_MU_LENGTH, signature, signature_length);
    if (CKR_OK != rv) {
        printf("C_Verify (external mu) failed: %lu\n", rv);
        return rv;
    }

    printf("External mu sign/verify successful\n");
    return CKR_OK;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    int rc = EXIT_FAILURE;
    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    if (CKR_OK != pkcs11_initialize(args.library)) {
        return EXIT_FAILURE;
    }

    if (CKR_OK != pkcs11_open_session(args.pin, &session)) {
        return EXIT_FAILURE;
    }

    CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

    rv = generate_mldsa_keypair(session, CKP_CLOUDHSM_ML_DSA_44, &public_key, &private_key);
    if (CKR_OK != rv) {
        printf("ML-DSA-44 key generation failed: %lu\n", rv);
        goto done;
    }
    printf("ML-DSA-44 key generated. Public key: %lu, Private key: %lu\n", public_key, private_key);

    printf("\n--- ML-DSA Pure Raw Sign/Verify ---\n");
    rv = mldsa_pure_sign_verify(session, private_key, public_key);
    if (CKR_OK != rv)
        goto done;

    printf("\n--- ML-DSA External Mu Sign/Verify ---\n");
    rv = mldsa_external_mu_sign_verify(session, private_key, public_key);
    if (CKR_OK != rv)
        goto done;

    rc = EXIT_SUCCESS;

done:
    pkcs11_finalize_session(session);
    return rc;
}
