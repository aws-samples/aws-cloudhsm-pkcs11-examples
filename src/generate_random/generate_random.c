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
#include <string.h>
#include <stdlib.h>

#include <common.h>

/**
* Generate random data
* @param session  Valid PKCS#11 Session.
* @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
*/
CK_RV generate_random(CK_SESSION_HANDLE session) {
    CK_RV rv;

    CK_ULONG ulRandomLen = 10;
    CK_BYTE_PTR pRandomData = (CK_BYTE_PTR) malloc(ulRandomLen * sizeof(CK_BYTE));
    if (NULL == pRandomData) {
        printf("Failed to allocate pRandomData memory\n");
        return CKR_FUNCTION_FAILED;
    }

    rv = funcs->C_GenerateRandom(session, pRandomData, ulRandomLen);
    if (CKR_OK == rv) {
        printf("Random data generated: ");
        print_bytes_as_hex(pRandomData, ulRandomLen);
    }

    free(pRandomData);
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

    //**********************************************************************************************
    // Generate Random
    //**********************************************************************************************

    printf("Generate Random\n");

    rv = generate_random(session);
    if (CKR_OK != rv) {
        fprintf(stderr, "Random data generation failed with: %lu\n", rv);
        return rc;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
