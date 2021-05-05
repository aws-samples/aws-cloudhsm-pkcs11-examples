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
 * Encrypt and decrypt a string using AES CBC.
 * @param session Active PKCS#11 session
 */
CK_RV aes_cbc_sample(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_BYTE_PTR decrypted_ciphertext = NULL;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key;
    rv = generate_aes_key(session, 32, &aes_key);
    if (CKR_OK != rv) {
        printf("AES key generation failed: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = (CK_ULONG) strlen(plaintext);

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    // Prepare the mechanism 
    // The IV is hardcoded to all 0x01 bytes for this example.
    CK_BYTE iv[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, 16};

    //**********************************************************************************************
    // Encrypt
    //**********************************************************************************************    

    rv = funcs->C_EncryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Encryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory will be required to hold the ciphertext.
    CK_ULONG ciphertext_length = 0;
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        return rv;
    }

    // Allocate the required memory.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        printf("Could not allocate memory for ciphertext\n");
        return rv;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext, &ciphertext_length);
    if (CKR_OK != rv) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    printf("Ciphertext: ");
    print_bytes_as_hex(ciphertext, ciphertext_length);
    printf("Ciphertext length: %lu\n", ciphertext_length);

    //**********************************************************************************************
    // Decrypt
    //**********************************************************************************************    

    rv = funcs->C_DecryptInit(session, &mech, aes_key);
    if (CKR_OK != rv) {
        printf("Decryption Init failed: %lu\n", rv);
        return rv;
    }

    // Determine how much memory is required to hold the decrypted text.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, NULL, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted ciphertext.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length + 1); //We want to null terminate the raw chars later
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        printf("Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = funcs->C_Decrypt(session, ciphertext, ciphertext_length, decrypted_ciphertext, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }
    decrypted_ciphertext[decrypted_ciphertext_length] = 0; // Turn the chars into a C-String via null termination

    printf("Decrypted ciphertext: %s\n", decrypted_ciphertext);
    printf("Decrypted ciphertext length: %lu\n", decrypted_ciphertext_length);

done:
    if (NULL != decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }

    if (NULL != ciphertext) {
        free(ciphertext);
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

    printf("\nEncrypt/Decrypt with AES CBC Pad\n");
    rv = aes_cbc_sample(session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return 0;
}
