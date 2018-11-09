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
 * Encrypt the plaintext with additional authentication data.
 * The ciphertext will be prepended with the HSM generated IV.
 * @param session
 * @param key
 * @param plaintext
 * @param plaintext_length
 * @param aad
 * @param aad_length
 * @param ciphertext
 * @param ciphertext_length
 * @return
 */
CK_RV encrypt_aes_gcm(CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE key,
                      CK_BYTE_PTR plaintext,
                      CK_ULONG plaintext_length,
                      CK_BYTE_PTR aad,
                      CK_ULONG aad_length,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG_PTR ciphertext_length) {
    CK_RV rv;
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;

    // Allocate memory to hold the HSM generated IV.
    CK_BYTE_PTR iv = malloc(AES_GCM_IV_SIZE);
    if (NULL==iv) {
        return CKR_HOST_MEMORY;
    }
    memset(iv, 0, AES_GCM_IV_SIZE);

    // Setup the mechanism with the IV location and AAD information.
    params.pIv = iv;
    params.ulIvLen = AES_GCM_IV_SIZE;
    params.pAAD = aad;
    params.ulAADLen = aad_length;
    params.ulTagBits = AES_GCM_TAG_SIZE * 8;

    mech.mechanism = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter = &params;

    rv = funcs->C_EncryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        free(iv);
        return !CKR_OK;
    }

    if (NULL == ciphertext) {
        rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, ciphertext_length);
        // We return the IV with the ciphertext, so the length must also include the IV.
        *ciphertext_length += AES_GCM_IV_SIZE;
        free(iv);
        return rv;
    }

    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext + AES_GCM_IV_SIZE, ciphertext_length);

    // Prepend HSM generated IV to ciphertext buffer
    memcpy(ciphertext, iv, AES_GCM_IV_SIZE);
    *ciphertext_length += AES_GCM_IV_SIZE;

    free(iv);
    return rv;
}

/**
 * Decrypt the ciphertext with additional authentication data.
 * The ciphertext must have the IV prepended.
 * @param session
 * @param key
 * @param ciphertext
 * @param ciphertext_length
 * @param aad
 * @param aad_length
 * @param decrypted_ciphertext
 * @param decrypted_ciphertext_length
 * @return
 */
CK_RV decrypt_aes_gcm(CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE key,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG ciphertext_length,
                      CK_BYTE_PTR aad,
                      CK_ULONG aad_length,
                      CK_BYTE_PTR decrypted_ciphertext,
                      CK_ULONG_PTR decrypted_ciphertext_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    CK_GCM_PARAMS params;

    // The IV must be the first AES_GCM_IV_SIZE bytes of the ciphertext.
    params.pIv = ciphertext;
    params.ulIvLen = AES_GCM_IV_SIZE;
    params.pAAD = aad;
    params.ulAADLen = aad_length;
    params.ulTagBits = AES_GCM_TAG_SIZE * 8;

    mech.mechanism = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter = &params;

    rv = funcs->C_DecryptInit(session, &mech, key);
    if (rv != CKR_OK) {
        return !CKR_OK;
    }

    rv = funcs->C_Decrypt(session, ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE,
                          decrypted_ciphertext, decrypted_ciphertext_length);
    return rv;
}