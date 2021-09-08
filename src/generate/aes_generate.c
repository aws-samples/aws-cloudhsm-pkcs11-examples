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

#include <common.h>

/**
 * Generate an AES key.
 * @param session  Valid PKCS#11 Session.
 * @param key_length_bytes Byte size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param key pointer to hold the resulting key handle.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL, 0};

    CK_ATTRIBUTE template[] = {
            {CKA_SENSITIVE, &true_val,         sizeof(CK_BBOOL)},
            {CKA_TOKEN,     &false_val,        sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes, sizeof(CK_ULONG)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    rv = pkcs11_open_session(args.pin, &session);

    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;

    rv = generate_aes_key(session, 32, &aes_key);
    if (CKR_OK == rv) {
        printf("AES key generated. Key handle: %lu\n", aes_key);
    } else {
        printf("AES key generation failed: %lu\n", rv);
        return rv;
    }

    pkcs11_finalize_session(session);
    return 0;
}
