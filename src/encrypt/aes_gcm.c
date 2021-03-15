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

#include <stdio.h>
#include "aes.h"

/**
 * Encrypt and decrypt a string using AES GCM.
 * @param session Active PKCS#11 session.
 */
CK_RV aes_gcm_sample(CK_SESSION_HANDLE session) {
    CK_RV rv;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    rv = generate_aes_key(session, 32, &aes_key);
    if (CKR_OK != rv) {
        printf("AES key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = (CK_ULONG) strlen(plaintext);
    CK_ULONG ciphertext_length = 0;
    CK_BYTE_PTR aad = "plaintext aad";
    CK_ULONG aad_length = (CK_ULONG) strlen(aad);

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    printf("AAD: %s\n", aad);
    printf("AAD length: %lu\n", aad_length);

    // Prepare the mechanism
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;

    // Allocate memory to hold the HSM generated IV.
    CK_BYTE_PTR iv = malloc(AES_GCM_IV_SIZE);
    if (NULL == iv) {
        printf("Failed to allocate IV memory\n");
        return rv;
    }
    memset(iv, 0, AES_GCM_IV_SIZE);

    // Setup the mechanism with the IV location and AAD information.
    params.pIv = iv;
    params.ulIvLen = AES_GCM_IV_SIZE;
    params.ulIvBits = 0;
    params.pAAD = aad;
    params.ulAADLen = aad_length;
    params.ulTagBits = AES_GCM_TAG_SIZE * 8;

    mech.mechanism = CKM_AES_GCM;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter = &params;

    //**********************************************************************************************
    // Encrypt
    //********************************************************************************************** 

    rv = funcs->C_EncryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Encryption Init failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR decrypted_ciphertext = NULL;
    CK_BYTE_PTR ciphertext = NULL;

    // Determine how much memory is required to store the ciphertext.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);

    // The ciphertext will be prepended with the HSM generated IV
    // so the length must include the IV
    ciphertext_length += AES_GCM_IV_SIZE;
    if (CKR_OK != rv) {
        printf("Failed to find GCM ciphertext length\n");
        goto done;
    }

    // Allocate memory to store the ciphertext.
    ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        rv = 1;
        printf("Failed to allocate ciphertext memory\n");
        goto done;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext + AES_GCM_IV_SIZE, &ciphertext_length);

    // Prepend HSM generated IV to ciphertext buffer
    memcpy(ciphertext, iv, AES_GCM_IV_SIZE);
    ciphertext_length += AES_GCM_IV_SIZE;
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Ciphertext buffer = IV || ciphertext || TAG
    // Print the HSM generated IV
    printf("IV: ");
    print_bytes_as_hex(ciphertext, AES_GCM_IV_SIZE);
    printf("IV length: %d\n", AES_GCM_IV_SIZE);

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);
    printf("Ciphertext length: %lu\n", ciphertext_length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);

    // Print TAG in hex format
    printf("Tag: ");
    print_bytes_as_hex(ciphertext + AES_GCM_IV_SIZE + plaintext_length, ciphertext_length - AES_GCM_IV_SIZE - plaintext_length);
    printf("Tag length: %lu\n", ciphertext_length - AES_GCM_IV_SIZE - plaintext_length);

    //**********************************************************************************************
    // Decrypt
    //**********************************************************************************************  

    // Use the IV that was prepended -- The first AES_GCM_IV_SIZE bytes of the ciphertext.
    params.pIv = ciphertext;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter = &params;

    rv = funcs->C_DecryptInit(session, &mech, aes_key);
    if (rv != CKR_OK) {
        printf("Decryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine the length of decrypted ciphertext.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE,
                          NULL, &decrypted_ciphertext_length);

    if (rv != CKR_OK) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted cipher text.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length + 1); //We want to null terminate the raw chars later
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        printf("Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = funcs->C_Decrypt(session, ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE,
                          decrypted_ciphertext, &decrypted_ciphertext_length);
    if (rv != CKR_OK) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }
    decrypted_ciphertext[decrypted_ciphertext_length] = 0; // Turn the chars into a C-String via null termination

    printf("Decrypted ciphertext: %s\n",  decrypted_ciphertext);
    printf("Decrypted ciphertext length: %lu\n", decrypted_ciphertext_length);

done:
    if (NULL != iv) {
        free(iv);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
    }

    if (NULL != decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }
    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {0};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    printf("\nEncrypt/Decrypt with AES GCM\n");
    aes_gcm_sample(session);

    pkcs11_finalize_session(session);

    return 0;
}
