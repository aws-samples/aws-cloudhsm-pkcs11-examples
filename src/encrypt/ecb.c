/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "encrypt.h"

/**
 * Encrypt data using an AES key and the ECB mechanism.
 * @param session Active PKCS#11 sessions
 * @param key Handle of encryption key
 * @param plaintext
 * @param plaintext_length
 * @param ciphertext
 * @param ciphertext_length
 * @return CK_RV
 */
CK_RV encrypt_aes_ecb(CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR plaintext,
                  CK_ULONG plaintext_length,
                  CK_BYTE_PTR ciphertext,
                  CK_ULONG_PTR ciphertext_length) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};

    rv = funcs->C_EncryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, ciphertext_length);

    return rv;
}

/**
 * Decrypt data using an AES key and the ECB mechanism.
 * @param session
 * @param key
 * @param ciphertext
 * @param ciphertext_length
 * @param plaintext
 * @param plaintext_length
 * @return CK_RV
 */
CK_RV decrypt_aes_ecb(CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR ciphertext,
                  CK_ULONG ciphertext_length,
                  CK_BYTE_PTR plaintext,
                  CK_ULONG_PTR plaintext_length) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_AES_ECB, NULL, 0};

    rv = funcs->C_DecryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, plaintext, plaintext_length);

    return rv;
}

