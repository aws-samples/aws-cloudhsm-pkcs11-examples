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
#include "encrypt.h"

/**
 * Generate an AES key with a template suitable for encrypting data.
 * The key is a Session key, and will be deleted once the HSM Session is closed.
 * @param session Active PKCS#11 session
 * @param key_length 16, 24, or 32 bytes
 * @param key Location where the key's handle will be written
 * @return CK_RV
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,       &false,            sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &true,             sizeof(CK_BBOOL)},
            {CKA_ENCRYPT,     &true,             sizeof(CK_BBOOL)},
            {CKA_DECRYPT,     &true,             sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN,   &key_length_bytes, sizeof(CK_ULONG)},
    };

    return funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
}

/**
 * Encrypt and decrypt a string using AES CBC.
 * @param session Active PKCS#11 session
 */
void aes_cbc_sample(CK_SESSION_HANDLE session) {
    CK_RV rv;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key;
    rv = generate_aes_key(session, 32, &aes_key);
    if (rv != CKR_OK) {
        printf("AES key generation failed: %lu\n", rv);
        return;
    }

    CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = strlen(plaintext);
    CK_ULONG ciphertext_length = 0;

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    // Determine how much memory will be required to hold the ciphertext.
    rv = encrypt_aes(session, aes_key,
                     plaintext, plaintext_length,
                     NULL, &ciphertext_length);
    if (rv != CKR_OK) {
        printf("Encryption failed: %lu\n", rv);
        return;
    }

    // Allocate the required memory.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL==ciphertext) {
        printf("Could not allocate memory for ciphertext\n");
        return;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = encrypt_aes(session, aes_key,
                     plaintext, plaintext_length,
                     ciphertext, &ciphertext_length);
    if (rv != CKR_OK) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Print just the ciphertext in hex format
    unsigned char *hex_array = NULL;
    bytes_to_new_hexstring(ciphertext, ciphertext_length, &hex_array);
    if (!hex_array) {
        printf("Could not allocate memory for hex array\n");
        goto done;
    }
    printf("Ciphertext: %s\n", hex_array);
    printf("Ciphertext length: %lu\n", ciphertext_length);

    // Determine how much memory is required to hold the decrypted text.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = decrypt_aes(session, aes_key,
                     ciphertext, ciphertext_length,
                     NULL, &decrypted_ciphertext_length);
    if (rv != CKR_OK) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted ciphertext.
    CK_BYTE_PTR decrypted_ciphertext = malloc(decrypted_ciphertext_length);
    if (NULL==decrypted_ciphertext) {
        printf("Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = decrypt_aes(session, aes_key,
                     ciphertext, ciphertext_length,
                     decrypted_ciphertext, &decrypted_ciphertext_length);
    if (CKR_OK!=rv) {
        printf("Decryption failed: %lu\n", rv);
    }

    printf("Decrypted text: %s\n", decrypted_ciphertext);

done:
    if (NULL!=decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }

    if (NULL!=hex_array) {
        free(hex_array);
    }

    if (NULL!=ciphertext) {
        free(ciphertext);
    }
}

/**
 * Encrypt and decrypt a string using AES GCM.
 * @param session Active PKCS#11 session.
 */
void aes_gcm_sample(CK_SESSION_HANDLE session) {
    CK_RV rv;

    // Generate a 256 bit AES key.
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    rv = generate_aes_key(session, 32, &aes_key);
    if (rv != CKR_OK) {
        printf("AES key generation failed: %lu\n", rv);
        return;
    }

    CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = strlen(plaintext);
    CK_ULONG ciphertext_length = 0;
    CK_BYTE_PTR aad = "plaintext aad";
    CK_ULONG aad_length = strlen(aad);

    // Determine how much memory is required to store the ciphertext.
    rv = encrypt_aes_gcm(session, aes_key,
                         plaintext, plaintext_length,
                         aad, aad_length,
                         NULL, &ciphertext_length);
    if (rv != CKR_OK) {
        printf("Failed to find GCM ciphertext length\n");
        goto done;
    }

    // Allocate memory to store the ciphertext.
    CK_BYTE_PTR ciphertext = malloc(ciphertext_length);
    if (NULL==ciphertext) {
        printf("Failed to allocate ciphertext memory\n");
        goto done;
    }
    memset(ciphertext, 0, ciphertext_length);

    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    printf("AAD: %s\n", aad);
    printf("AAD length: %lu\n", aad_length);

    // Encrypt the data.
    rv = encrypt_aes_gcm(session, aes_key,
                         plaintext, plaintext_length,
                         aad, aad_length,
                         ciphertext, &ciphertext_length);
    if (rv != CKR_OK) {
        printf("Encryption failed: %lu\n", rv);
        goto done;
    }

    // Ciphertext buffer = IV || ciphertext || TAG
    // Print the HSM generated IV
    unsigned char *hex_array = NULL;
    bytes_to_new_hexstring(ciphertext, AES_GCM_IV_SIZE, &hex_array);
    if (!hex_array) {
        printf("Could not allocate hex array\n");
        goto done;
    }
    printf("IV: %s\n", hex_array);
    printf("IV length: %d\n", AES_GCM_IV_SIZE);

    // Print just the ciphertext in hex format
    bytes_to_new_hexstring(ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE,
                           &hex_array);
    if (!hex_array) {
        printf("Could not allocate hex array\n");
        goto done;
    }
    printf("Ciphertext: %s\n", hex_array);
    printf("Ciphertext length: %lu\n", ciphertext_length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);

    // Print TAG in hex format
    bytes_to_new_hexstring(ciphertext + AES_GCM_IV_SIZE + plaintext_length,
                           ciphertext_length - AES_GCM_IV_SIZE - plaintext_length, &hex_array);
    if (!hex_array) {
        printf("Could not allocate hex array\n");
        goto done;
    }
    printf("Tag: %s\n", hex_array);
    printf("Tag length: %lu\n", ciphertext_length - AES_GCM_IV_SIZE - plaintext_length);

    // Determine the length of decrypted ciphertext.
    CK_BYTE_PTR decrypted_ciphertext = NULL;
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = decrypt_aes_gcm(session, aes_key,
                         ciphertext, ciphertext_length,
                         aad, aad_length,
                         NULL, &decrypted_ciphertext_length);

    // Allocate memory for the decrypted cipher text.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length);
    if (NULL==decrypted_ciphertext) {
        printf("Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = decrypt_aes_gcm(session, aes_key,
                         ciphertext, ciphertext_length,
                         aad, aad_length,
                         decrypted_ciphertext, &decrypted_ciphertext_length);
    if (rv != CKR_OK) {
        printf("Decryption failed: %lu\n", rv);
        goto done;
    }
    printf("Decrypted ciphertext: %s\n", decrypted_ciphertext);

done:
    if (NULL!=hex_array) {
        free(hex_array);
    }

    if (NULL!=ciphertext) {
        free(ciphertext);
    }

    if (NULL!=decrypted_ciphertext) {
        free(decrypted_ciphertext);
    }
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    if (CKR_OK != rv) {
        return 1;
    }
    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        return 1;
    }

    printf("\nEncrypt/Decrypt with AES CBC\n");
    aes_cbc_sample(session);
    printf("\nEncrypt/Decrypt with AES GCM\n");
    aes_gcm_sample(session);

    pkcs11_finalize_session(session);

    return 0;
}
