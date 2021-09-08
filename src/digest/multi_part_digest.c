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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"

/**
 * Generate a digest of a given message in multiple parts. This function will allocate the required memory to store the digest.
 * Available mechanisms are documented at https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html
 * @param session       PKCS11 session
 * @param mechanism     Mechanism type
 * @param data          Data to generate digest for
 * @param data_length   Length of the previous arg 'data'
 * @param digest        Pointer to where the generated digest will be stored
 * @param digest_length Length of the generated digest
 * @return CK_RV        PKCS11 return code
 */
CK_RV generate_multi_part_digest(CK_SESSION_HANDLE session,
                     CK_MECHANISM_TYPE mechanism,
                     CK_BYTE_PTR data,
                     CK_ULONG data_length,
                     CK_BYTE **digest,
                     CK_ULONG_PTR digest_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_DigestInit(session, &mech);
    if (CKR_OK != rv) {
        return rv;
    }

    rv = funcs->C_DigestUpdate(session, data, data_length);
    if (CKR_OK != rv) {
        return rv;
    }

    // First determine the digest length by passing in a NULL buffer
    // C_DigestFinal won't terminate the session if we just determine digest length.
    rv = funcs->C_DigestFinal(session, NULL, digest_length);
    if (CKR_OK != rv) {
        return rv;
    }

    *digest = malloc(*digest_length);
    if (NULL == *digest) {
        return CKR_HOST_MEMORY;
    }

    rv = funcs->C_DigestFinal(session, *digest, digest_length);
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

    CK_BYTE_PTR data = "Message requiring a digest";
    CK_ULONG data_length = (CK_ULONG) strlen(data);
    CK_BYTE_PTR digest = NULL;
    CK_ULONG digest_length = 0;

    // Set the PKCS11 digest mechanism type.
    // Supported types are kept up to date at https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html
    CK_MECHANISM_TYPE mechanism = CKM_SHA256;

    rv = generate_multi_part_digest(session, mechanism, data, data_length, &digest, &digest_length);
    if (CKR_OK == rv) {
        printf("Data: %s\n", data);
        printf("Digest: ");
        print_bytes_as_hex(digest, digest_length);
        rc = EXIT_SUCCESS;
    } else {
        printf("Digest generation failed: %lu\n", rv);
    }

    if (NULL != digest) {
        free(digest);
    }

    pkcs11_finalize_session(session);

    return rc;
}