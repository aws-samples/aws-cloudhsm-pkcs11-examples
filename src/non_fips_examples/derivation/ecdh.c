/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16



/**
 * Generate an EC key pair suitable for signing data and verifying signatures.
 * @param session Valid PKCS11 session.
 * @param named_curve_oid Curve to use when generating key pair. Valid curves are listed here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param named_curve_oid_len Length of the OID
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_ec_keypair(CK_SESSION_HANDLE session,
                          CK_BYTE_PTR named_curve_oid,
                          CK_ULONG named_curve_oid_len,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY, &true_val, sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, named_curve_oid, named_curve_oid_len},
            {CKA_TOKEN, &false_val, sizeof(CK_BBOOL)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_SIGN, &true_val, sizeof(CK_BBOOL)},
            {CKA_TOKEN, &false_val, sizeof(CK_BBOOL)},
            {CKA_DERIVE, &true_val, sizeof(CK_BBOOL)},
    };

    rv = funcs->C_GenerateKeyPair(session,
                                  &mech,
                                  public_key_template, sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                  private_key_template, sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                  public_key,
                                  private_key);
    return rv;
}

/**
 * Generate AES Derive key using CKM_ECDH1_DERIVE mechanism
 * @param session Active PKCS#11 session
 * @param private_key Handle to the private key for derivation
 * @param peer_public_key Handle to the peer's public key for derivation
 * @param derived_key Pointer where the derived key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_ecdh_derive_key(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE private_key,
                               CK_OBJECT_HANDLE peer_public_key,
                               CK_OBJECT_HANDLE_PTR derived_key){
    CK_RV rv;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG aesKeyLen = 32;
    CK_BYTE_PTR ec_point_value = NULL;
    CK_ULONG ec_point_size = 0;

    // First call to get the length
    CK_ATTRIBUTE point_template[] = {
        {CKA_EC_POINT, NULL, 0}
    };

    rv = funcs->C_GetAttributeValue(session, peer_public_key, point_template,
                                  sizeof(point_template) / sizeof(CK_ATTRIBUTE));
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to get EC point length: %lu\n", rv);
        return rv;
    }

    // Allocate memory based on the returned length
    ec_point_size = point_template[0].ulValueLen;
    ec_point_value = malloc(ec_point_size);
    if (NULL == ec_point_value) {
        fprintf(stderr, "Failed to allocate memory for EC point\n");
        return CKR_HOST_MEMORY;
    }

    // Second call to get the actual value
    point_template[0].pValue = ec_point_value;
    rv = funcs->C_GetAttributeValue(session, peer_public_key, point_template,
                                  sizeof(point_template) / sizeof(CK_ATTRIBUTE));
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to get EC point value: %lu\n", rv);
        free(ec_point_value);
        return rv;
    }

    // To enable ECDH derive key without KDF, use the `configure-pkcs11 --enable-ecdh-without-kdf` command.
    CK_ECDH1_DERIVE_PARAMS params = {
        CKD_NULL,
        0,
        NULL,
        ec_point_size,
        ec_point_value
    };

    CK_MECHANISM derive_mechanism = { CKM_ECDH1_DERIVE, &params, sizeof(params) };

    CK_ATTRIBUTE derivekey_template[] = {
          { CKA_CLASS, &keyClass, sizeof(keyClass) },
          { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
          { CKA_ENCRYPT, &true_val, sizeof(CK_BBOOL) },
          { CKA_DECRYPT, &true_val, sizeof(CK_BBOOL) },
          { CKA_VALUE_LEN, &aesKeyLen, sizeof(aesKeyLen) },
          { CKA_TOKEN, &false_val, sizeof(CK_BBOOL) },
    };

    rv = funcs->C_DeriveKey(session,
                            &derive_mechanism,
                            private_key,
                            derivekey_template,
                            sizeof(derivekey_template) / sizeof(CK_ATTRIBUTE),
                            derived_key);
    free(ec_point_value);
    return rv;
}




/**
 * Encrypt using Party A's derived key in AES GCM mode.
 * Decrypt using Party B's derived key in AES GCM mode.
 * @param session Active PKCS#11 session
 * @param aes_key Pointer where the derived AES key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */

CK_RV aes_gcm_sample(CK_SESSION_HANDLE session, 
                     CK_OBJECT_HANDLE encrypt_key, 
                     CK_OBJECT_HANDLE decrypt_key) {
    CK_RV rv;
    CK_BYTE_PTR plaintext = "plaintext payload to encrypt";
    CK_ULONG plaintext_length = (CK_ULONG) strlen(plaintext);
    CK_ULONG ciphertext_length = 0;
    CK_BYTE_PTR aad = "plaintext aad";
    CK_ULONG aad_length = (CK_ULONG) strlen(aad);
    CK_BYTE_PTR decrypted_ciphertext = NULL;
    CK_BYTE_PTR ciphertext = NULL;

    printf("\nDemonstrating ECDH key agreement:\n");
    printf("Party A encrypting payload: %s\n", plaintext);
    printf("Plaintext length: %lu\n", plaintext_length);

    printf("\nAAD: %s\n", aad);
    printf("AAD length: %lu\n", aad_length);

    // Prepare the mechanism
    CK_MECHANISM mech;
    CK_GCM_PARAMS params;

    // Allocate memory to hold the HSM generated IV.
    CK_BYTE_PTR iv = malloc(AES_GCM_IV_SIZE);
    rv = 1;
    if (NULL == iv) {
        fprintf(stderr, "Failed to allocate IV memory\n");
        goto done;
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

    printf("\nParty A encrypting with their derived key\n");
    rv = funcs->C_EncryptInit(session, &mech, encrypt_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Encryption Init failed: %lu\n", rv);
        goto done;
    }

    // Determine how much memory is required to store the ciphertext.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, NULL, &ciphertext_length);

    // The ciphertext will be prepended with the HSM generated IV
    // so the length must include the IV
    ciphertext_length += AES_GCM_IV_SIZE;
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to find GCM ciphertext length\n");
        goto done;
    }

    // Allocate memory to store the ciphertext.
    ciphertext = malloc(ciphertext_length);
    if (NULL == ciphertext) {
        rv = 1;
        fprintf(stderr, "Failed to allocate ciphertext memory\n");
        goto done;
    }
    memset(ciphertext, 0, ciphertext_length);

    // Encrypt the data.
    rv = funcs->C_Encrypt(session, plaintext, plaintext_length, ciphertext + AES_GCM_IV_SIZE, &ciphertext_length);

    // Prepend HSM generated IV to ciphertext buffer
    memcpy(ciphertext, iv, AES_GCM_IV_SIZE);
    ciphertext_length += AES_GCM_IV_SIZE;
    if (CKR_OK != rv) {
        fprintf(stderr, "Encryption failed: %lu\n", rv);
        goto done;
    }

    // Ciphertext buffer = IV || ciphertext || TAG
    // Print the HSM generated IV
    printf("\nIV: ");
    print_bytes_as_hex(ciphertext, AES_GCM_IV_SIZE);
    printf("IV length: %d\n", AES_GCM_IV_SIZE);

    // Print just the ciphertext in hex format
    printf("\nEncrypted Ciphertext: ");
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
    printf("\nParty B decrypting with their derived key\n");
    params.pIv = ciphertext;
    mech.ulParameterLen = sizeof(params);
    mech.pParameter = &params;

    rv = funcs->C_DecryptInit(session, &mech, decrypt_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption Init failed: %lu\n", rv);
        goto done;
    }

    // Determine the length of decrypted ciphertext.
    CK_ULONG decrypted_ciphertext_length = 0;
    rv = funcs->C_Decrypt(session, ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE,
                          NULL, &decrypted_ciphertext_length);

    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption failed: %lu\n", rv);
        goto done;
    }

    // Allocate memory for the decrypted cipher text.
    decrypted_ciphertext = malloc(decrypted_ciphertext_length);
    if (NULL == decrypted_ciphertext) {
        rv = 1;
        fprintf(stderr, "Could not allocate memory for decrypted ciphertext\n");
        goto done;
    }

    // Decrypt the ciphertext.
    rv = funcs->C_Decrypt(session, ciphertext + AES_GCM_IV_SIZE, ciphertext_length - AES_GCM_IV_SIZE,
                          decrypted_ciphertext, &decrypted_ciphertext_length);
    if (CKR_OK != rv) {
        fprintf(stderr, "Decryption failed: %lu\n", rv);
        goto done;
    }
 
    CK_ULONG decrypted_plaintext_length = (CK_ULONG) strlen((char*)decrypted_ciphertext);
    printf("\nDecrypted: %s\n", decrypted_ciphertext);
    printf("Decrypted text length: %lu\n", decrypted_plaintext_length);
    printf("\nKey Derivation %s\n", (memcmp(plaintext, decrypted_ciphertext, plaintext_length) == 0) ? 
           "successful - encrypted payload with Party A's derived key and decrypted with Party B's derived key to get back same payload" : "failed - Keys do not match!");

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

    if (CKR_OK != pkcs11_initialize(args.library)) {
        return EXIT_FAILURE;
    }

    if (CKR_OK != pkcs11_open_session(args.pin, &session)) {
        return EXIT_FAILURE;
    }

// Generate key pairs for both parties
    CK_OBJECT_HANDLE party_a_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE party_a_private_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE party_b_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE party_b_private_key = CK_INVALID_HANDLE;

    /**
    * Curve OIDs generated using OpenSSL on the command line.
    * Visit https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html for a list
    * of supported curves.
    * openssl ecparam -name prime256v1 -outform DER | hexdump -C
    */
    CK_BYTE prime256v1_derive[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
 
    // Generate Party A's key pair
    rv = generate_ec_keypair(session, prime256v1_derive, sizeof(prime256v1_derive),
                            &party_a_public_key, &party_a_private_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Party A key generation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }
 
    // Generate Party B's key pair
    rv = generate_ec_keypair(session, prime256v1_derive, sizeof(prime256v1_derive),
                            &party_b_public_key, &party_b_private_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "prime256v1 key generation failed for Party B: %lu\n", rv);
        return EXIT_FAILURE;
    }

    // Derive shared secrets
    CK_OBJECT_HANDLE party_a_derived_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE party_b_derived_key = CK_INVALID_HANDLE;
 
    // Party A derives key using B's public key
    rv = generate_ecdh_derive_key(session, party_a_private_key, party_b_public_key, &party_a_derived_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Party A key derivation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    // Party B derives key using A's public key
    rv = generate_ecdh_derive_key(session, party_b_private_key, party_a_public_key, &party_b_derived_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "Party B key derivation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }
 
    // Test encryption with Party A's key and decryption with Party B's key
    rv = aes_gcm_sample(session, party_a_derived_key, party_b_derived_key);
    if (CKR_OK != rv) {
        fprintf(stderr, "ECDH key agreement test failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}