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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common.h"

/**
 * Find keys that match a passed CK_ATTRIBUTE template.
 * Memory will be allocated in a passed pointer, and reallocated as more keys
 * are found. The number of found keys is returned through the count parameter.
 * @param hSession
 * @param template
 * @param hObject
 * @param count
 * @return
 */
CK_RV find_by_attr(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *template, CK_ULONG attr_count, CK_ULONG *count,
                   CK_OBJECT_HANDLE_PTR *hObject) {
    CK_RV rv;

    if (NULL == hObject || NULL == template || NULL == count) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = funcs->C_FindObjectsInit(hSession, template, attr_count);
    if (rv != CKR_OK) {
        fprintf(stderr, "Can't initialize search\n");
        return rv;
    }

    CK_ULONG max_objects = 25;
    bool searching = 1;
    *count = 0;
    while (searching) {
        CK_ULONG found = 0;
        *hObject = realloc(*hObject, (*count + max_objects) * sizeof(CK_OBJECT_HANDLE));
        if (NULL == *hObject) {
            fprintf(stderr, "Could not allocate memory for objects\n");
            return CKR_HOST_MEMORY;
        }

        CK_OBJECT_HANDLE_PTR loc = *hObject;
        rv = funcs->C_FindObjects(hSession, &loc[*count], max_objects, &found);
        if (rv != CKR_OK) {
            fprintf(stderr, "Can't run search\n");
            funcs->C_FindObjectsFinal(hSession);
            return rv;
        }

        (*count) += found;

        if (0 == found)
            searching = 0;
    }

    rv = funcs->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "Can't finalize search\n");
        return rv;
    }

    if (0 == *count) {
        fprintf(stderr, "Didn't find requested key\n");
        return rv;
    }

    return CKR_OK;
}


/**
 * Generate an AES key.
 * @param session  Valid PKCS#11 Session.
 * @param key_length_bytes Byte size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param key pointer to hold the resulting key handle.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_aes_key(CK_SESSION_HANDLE session,
                       CK_ULONG key_length_bytes,
                       CK_BYTE_PTR label,
                       CK_ULONG label_length,
                       CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL, 0};

    CK_ATTRIBUTE template[] = {
            {CKA_SENSITIVE, &true_val,         sizeof(CK_BBOOL)},
            {CKA_TOKEN,     &false_val,        sizeof(CK_BBOOL)},
            {CKA_LABEL,     label,             label_length},
            {CKA_VALUE_LEN, &key_length_bytes, sizeof(CK_ULONG)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

/**
 * Generate an RSA key pair suitable for signing data and verifying signatures.
 * @param session Valid PKCS11 session.
 * @param key_length_bits Bit size of key. Supported sizes are here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html
 * @param public_key Pointer where the public key handle will be stored.
 * @param private_key Pointer where the private key handle will be stored.
 * @return CK_RV Value returned by the PKCS#11 library. This will indicate success or failure.
 */
CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key) {
    CK_RV rv;
    CK_MECHANISM mech = {CKM_RSA_X9_31_KEY_PAIR_GEN, NULL, 0};
    CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_VERIFY,          &true_val,        sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_SIGN, &true_val, sizeof(CK_BBOOL)},
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
 * Create two AES keys and find them with their labels.
 * @param session
 */
CK_RV find_keys_with_label_example(CK_SESSION_HANDLE session) {
    CK_BYTE_PTR label1 = "First Label";
    CK_OBJECT_HANDLE aes_key_handle1 = CK_INVALID_HANDLE;
    CK_RV rv = generate_aes_key(session, 32, label1, (CK_ULONG) strlen(label1), &aes_key_handle1);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to generate an AES key: %lu\n", rv);
        return rv;
    }

    CK_BYTE_PTR label2 = "Second Label";
    CK_OBJECT_HANDLE aes_key_handle2 = CK_INVALID_HANDLE;
    rv = generate_aes_key(session, 32, label2, (CK_ULONG) strlen(label2), &aes_key_handle2);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to generate an AES key: %lu\n", rv);
        return rv;
    }

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE *found_objects = NULL;
    CK_ATTRIBUTE attr[] = {
            {CKA_LABEL, label1, (CK_ULONG) strlen(label1)},
    };

    rv = find_by_attr(session, attr, 1, &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find label 1\n");
        return rv;
    }

    printf("Found label1 with handle %lu\n", found_objects[0]);
    free(found_objects);
    found_objects = NULL;

    attr->type = CKA_LABEL;
    attr->pValue = label2;
    attr->ulValueLen = (CK_ULONG) strlen(label2);

    rv = find_by_attr(session, attr, 1, &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find label 2\n");
        return rv;
    }

    printf("Found label2 with handle %lu\n", found_objects[0]);
    free(found_objects);
    found_objects = NULL;
    return CKR_OK;
}

/**
 * Generate an RSA key pair, then search for the generated public key by
 * the modulus value.
 * @param session
 */
CK_RV find_keys_by_search_template(CK_SESSION_HANDLE session) {
    /*
     * Create a key pair that we can search for.
     */
    CK_OBJECT_HANDLE rsa_pub_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_priv_key_handle = CK_INVALID_HANDLE;
    CK_RV rv = generate_rsa_keypair(session, 2048, &rsa_pub_key_handle, &rsa_priv_key_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to generate an AES key: %lu\n", rv);
        return rv;
    }

    printf("Generated %lu/%lu\n", rsa_pub_key_handle, rsa_priv_key_handle);

    /*
     * We need to get the modulus value so we
     * know what data to search for later.
     */
    CK_ATTRIBUTE template[] = {
            {CKA_MODULUS, NULL_PTR, 0},
    };

    rv = funcs->C_GetAttributeValue(session, rsa_pub_key_handle, template, 1);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not read attributes from key: %lu\n", rsa_pub_key_handle);
        return rv;
    }

    CK_BYTE_PTR modulus = NULL;
    modulus = malloc(template[0].ulValueLen);
    template[0].pValue = modulus;

    rv = funcs->C_GetAttributeValue(session, rsa_pub_key_handle, template, 1);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not read attributes from key: %lu\n", rsa_pub_key_handle);
        return rv;
    }

    /*
     * Now we know the modulus. We can create a search template
     * to find the matching key. We also set CKO_PUBLIC_KEY to
     * only return the public handle, not the private handle.
     */
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE search_template[] = {
            {CKA_CLASS,   &class,  sizeof(CK_OBJECT_CLASS)},
            {CKA_MODULUS, modulus, template[0].ulValueLen},
    };

    CK_ULONG count = 0;
    CK_OBJECT_HANDLE_PTR found_objects = NULL;
    rv = find_by_attr(session, search_template, 2, &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find label 1\n");
        return rv;
    }

    printf("Found %lu public key with modulus\n", count);
    for (CK_ULONG i = 0; i < count; i++) {
        printf("Found key handle %lu\n", found_objects[i]);
    }

    free(found_objects);
    found_objects = NULL;
    free(modulus);
    modulus = NULL;
    return CKR_OK;
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

    printf("Searching for keys by label\n");
    rv = find_keys_with_label_example(session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    printf("\n\nSearching for keys by modulus\n");
    rv = find_keys_by_search_template(session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
