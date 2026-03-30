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

/**
 * Generate an ML-DSA key pair suitable for signing data and verifying signatures.
 * ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum
 * digital signature scheme standardized in FIPS 204.
 *
 * @param session Valid PKCS11 session.
 * @param parameter_set ML-DSA parameter set (CKP_CLOUDHSM_ML_DSA_44, CKP_CLOUDHSM_ML_DSA_65, or CKP_CLOUDHSM_ML_DSA_87).
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_mldsa_keypair(CK_SESSION_HANDLE session,
                             CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE parameter_set,
                             CK_OBJECT_HANDLE_PTR public_key,
                             CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_CLOUDHSM_ML_DSA_KEY_PAIR_GEN, NULL, 0};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,                   &true_val,       sizeof(CK_BBOOL)},
            {CKA_TOKEN,                    &false_val,      sizeof(CK_BBOOL)},
            {CKA_CLOUDHSM_PARAMETER_SET,   &parameter_set,  sizeof(CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_SIGN,                     &true_val,       sizeof(CK_BBOOL)},
            {CKA_TOKEN,                    &false_val,      sizeof(CK_BBOOL)},
            {CKA_CLOUDHSM_PARAMETER_SET,   &parameter_set,  sizeof(CK_CLOUDHSM_ML_DSA_PARAMETER_SET_TYPE)},
    };

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    return rv;
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
    printf("ML-DSA-44 key generated. Public key handle: %lu, Private key handle: %lu\n", public_key, private_key);

    rv = generate_mldsa_keypair(session, CKP_CLOUDHSM_ML_DSA_65, &public_key, &private_key);
    if (CKR_OK != rv) {
        printf("ML-DSA-65 key generation failed: %lu\n", rv);
        goto done;
    }
    printf("ML-DSA-65 key generated. Public key handle: %lu, Private key handle: %lu\n", public_key, private_key);

    rv = generate_mldsa_keypair(session, CKP_CLOUDHSM_ML_DSA_87, &public_key, &private_key);
    if (CKR_OK != rv) {
        printf("ML-DSA-87 key generation failed: %lu\n", rv);
        goto done;
    }
    printf("ML-DSA-87 key generated. Public key handle: %lu, Private key handle: %lu\n", public_key, private_key);

    rc = EXIT_SUCCESS;

done:
    pkcs11_finalize_session(session);
    return rc;
}
