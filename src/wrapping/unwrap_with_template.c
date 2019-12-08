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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

enum TEMPLATE_TYPE {
   VALID,
   INCONSISTENT,
   INCOMPLETE
};

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
            {CKA_TOKEN,           &true_val,           sizeof(CK_BBOOL)},
            {CKA_VERIFY,          &true_val,            sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_TOKEN,       &true_val, sizeof(CK_BBOOL)},
            {CKA_SIGN,        &true_val,  sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &true_val,  sizeof(CK_BBOOL)},
            {CKA_WRAP_WITH_TRUSTED, &true_val, sizeof(CK_BBOOL)},
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
 * Wrap a key using the wrapping_key handle.
 * The key being wrapped must have the CKA_EXTRACTABLE flag set to true.
 * @param session
 * @param wrapping_key
 * @param key_to_wrap
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV aes_wrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_OBJECT_HANDLE key_to_wrap,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG_PTR wrapped_bytes_len) {

    CK_MECHANISM mech = {CKM_AES_KEY_WRAP, NULL, 0};

    return funcs->C_WrapKey(
            session,
            &mech,
            wrapping_key,
            key_to_wrap,
            wrapped_bytes,
            wrapped_bytes_len);
}

/**
 * Unwrap a previously wrapped key into the HSM.
 * @param session
 * @param wrapping_key
 * @param wrapped_key_type
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @param unwrapped_key_handle
 * @return
 */
CK_RV aes_unwrap_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key,
        CK_BYTE_PTR wrapped_bytes,
        CK_ULONG wrapped_bytes_len,
        CK_OBJECT_HANDLE_PTR unwrapped_key_handle,
        enum TEMPLATE_TYPE template_type) {

    CK_MECHANISM mech = {CKM_AES_KEY_WRAP, NULL, 0};
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE *template = NULL;
    CK_ULONG template_count = 0;
    CK_KEY_TYPE wrapped_key_type = CKK_RSA;

    switch (template_type) {
    case VALID:
        template = (CK_ATTRIBUTE[]) {
                 {CKA_CLASS,       &key_class,        sizeof(key_class)},
                 {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                 {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
                 {CKA_EXTRACTABLE, &true_val,             sizeof(CK_BBOOL)},
        };
        template_count = 4;
        break;
    case INCONSISTENT:
        template = (CK_ATTRIBUTE[]) {
                 {CKA_CLASS,       &key_class,        sizeof(key_class)},
                 {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                 {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
                 {CKA_EXTRACTABLE, &false_val,             sizeof(CK_BBOOL)},
        };
        template_count = 4;
        break;
    case INCOMPLETE:
        template = (CK_ATTRIBUTE[]) {
                 {CKA_CLASS,       &key_class,        sizeof(key_class)},
                 {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                 {CKA_TOKEN,       &false_val,            sizeof(CK_BBOOL)},
        };
        template_count = 3;
        break;
    }

    return funcs->C_UnwrapKey(
            session,
            &mech,
            wrapping_key,
            wrapped_bytes,
            wrapped_bytes_len,
            template,
            template_count,
            unwrapped_key_handle);
}

/**
 * Get attribute for a given key handle.
 * @param session
 * @param key_handle
 * @param attr_type
 * @param attr_value
 * @return
 */
CK_RV get_attribute(
      CK_SESSION_HANDLE session,
      CK_OBJECT_HANDLE key_handle,
      CK_ATTRIBUTE_TYPE attr_type,
      CK_VOID_PTR attr_value
      ) {

    CK_ATTRIBUTE attr = { };
    attr.type = attr_type;
    attr.ulValueLen = sizeof(attr_value);
    attr.pValue = attr_value;

    return funcs->C_GetAttributeValue(
            session, key_handle, &attr, 1);
}

/**
 * Unwrap the wrapped bytes with a specific template.
 * @param session
 * @param wrapping_key
 * @param wrapped_key
 * @param wrapped_len
 * @return
 */
CK_RV aes_template_unwrap(
      CK_SESSION_HANDLE session,
      CK_OBJECT_HANDLE wrapping_key,
      CK_BYTE_PTR wrapped_key,
      CK_ULONG wrapped_len) {

    CK_RV rv;
    CK_BBOOL val;

    // Unwrap the key back into the HSM using a valid template
    CK_OBJECT_HANDLE unwrapped_handle = CK_INVALID_HANDLE;
    rv = aes_unwrap_key(session, wrapping_key, wrapped_key, wrapped_len, &unwrapped_handle, VALID);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not unwrap key: %lu\n", rv);
        return rv;
    }
    printf("Unwrapped bytes as object %lu\n", unwrapped_handle);
    // validate the CKA_EXTRACTABLE attribute
    val = false_val;
    rv = get_attribute(session, unwrapped_handle, CKA_EXTRACTABLE, &val);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get attribute value for CKA_EXTRACTABLE");
        return rv;
    }
    printf("CKA_EXTRACTABLE value for unwrapped key: %d\n", val);

    CK_OBJECT_HANDLE invalid_unwrapped_handle = CK_INVALID_HANDLE;
    rv = aes_unwrap_key(session, wrapping_key, wrapped_key, wrapped_len, &invalid_unwrapped_handle, INCONSISTENT);
    if (rv != CKR_TEMPLATE_INCONSISTENT) {
       fprintf(stderr, "\nInvalid rv received when using inconsistent wrapping template, rv: %lu\n", rv);
    }
    printf("Unwrap failed when using an invalid template with rv: %lu\n", rv);

    CK_OBJECT_HANDLE incomplete_unwrapped_handle = CK_INVALID_HANDLE;
    rv = aes_unwrap_key(session, wrapping_key, wrapped_key, wrapped_len, &incomplete_unwrapped_handle, INCOMPLETE);
    if (rv != CKR_OK) {
        fprintf(stderr, "\nInvalid rv received when using incomplete wrapping template, rv: %lu\n", rv);
        return rv;
    }
    printf("\nUnwrap passed when using an incomplete template with rv: %lu\n", rv);
    // validate the CKA_EXTRACTABLE attribute
    val = false_val;
    rv = get_attribute(session, unwrapped_handle, CKA_EXTRACTABLE, &val);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get attribute value for CKA_EXTRACTABLE");
        return rv;
    }
    printf("CKA_EXTRACTABLE value for unwrapped key: %d\n", val);
    return rv;
}

/**
 * Wrap an RSA key with a trusted wrapping key and then unwrap it.
 * @param session
 * @param wrapping_key
 * @return
 */
CK_RV aes_wrap_unwrap_with_trusted(CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE wrapping_key) {

    CK_RV rv;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;

    // validate the wrapping key is marked as trusted
    CK_BBOOL cka_trusted_val = false_val;
    rv = get_attribute(session, wrapping_key, CKA_TRUSTED, &cka_trusted_val);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get CKA_TRUSTED attribute on the wrapping key: %lu\n", rv);
        goto done;
    }
    if (cka_trusted_val != true_val) {
        fprintf(stderr, "Invalid wrapping key specified. Please specify wrapping key with CKA_TRUSTED set to true\n");
        fprintf(stderr, "The CKA_TRUSTED attribute for the wrapping key can be set by using the cloudhsm_mgmt_util:\n\n");
        fprintf(stderr, "aws-cloudhsm> loginHSM CO <co-username> <co-password>\n");
        fprintf(stderr, "aws-cloudhsm> setAttribute %lu 134 1\n\n", wrapping_key);
        rv = CKR_GENERAL_ERROR;
        goto done;
    }

    // Generate keys to be wrapped.
    rv = generate_rsa_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "RSA key generation failed: %lu\n", rv);
        goto done;
    }

    printf("rsa_private_key: %lu\n", rsa_private_key);

    // Determine how much space needs to be allocated for the wrapped key.
    CK_ULONG wrapped_len = 0;
    rv = aes_wrap_key(session, wrapping_key, rsa_private_key, NULL, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not determine size of wrapped key: %lu\n", rv);
        goto done;
    }

    wrapped_key = malloc(wrapped_len);
    if (NULL == wrapped_key) {
        fprintf(stderr, "Could not allocate memory to hold wrapped key\n");
        goto done;
    }

    // Wrap the key
    rv = aes_wrap_key(session, wrapping_key, rsa_private_key, wrapped_key, &wrapped_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Could not wrap key: %lu\n", rv);
        goto done;
    }

    rv = aes_template_unwrap(session, wrapping_key, wrapped_key, wrapped_len);
    if (CKR_OK != rv) {
       goto done;
    }

done:
    if (NULL != wrapped_key) {
        free(wrapped_key);
    }

    if (CK_INVALID_HANDLE != rsa_public_key) {
        rv = funcs->C_DestroyObject(session, rsa_public_key);
        if (CKR_OK != rv) {
            fprintf(stderr, "Could not delete public key: %lu\n", rv);
        }
    }

    if (CK_INVALID_HANDLE != rsa_private_key) {
        rv = funcs->C_DestroyObject(session, rsa_private_key);
        if (CKR_OK != rv) {
            fprintf(stderr, "Could not delete private key: %lu\n", rv);
        }
    }

    return rv;
}

int main(int argc, char **argv) {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    int rc = EXIT_FAILURE;

    struct pkcs_arguments args = {};
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

    rv = aes_wrap_unwrap_with_trusted(session, args.wrapping_key_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to unwrap with trusted wrapping key.\n");
        return rc;
    }

    pkcs11_finalize_session(session);
    return EXIT_SUCCESS;
}