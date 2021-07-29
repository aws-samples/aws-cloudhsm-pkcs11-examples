#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

/**
 * Generate an AES key that can be used to wrap and unwrap other keys.
 * The wrapping key should be a token key. We have to manually clean it
 * up at the end of this sample.
 * @param session
 * @param key_length_bytes
 * @param key
 * @return
 */
CK_RV generate_aes_token_key_for_wrapping(CK_SESSION_HANDLE session,
                                          CK_ULONG key_length_bytes,
                                          CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,     &true_val,          sizeof(CK_BBOOL)},
            {CKA_WRAP,      &true_val,          sizeof(CK_BBOOL)},
            {CKA_UNWRAP,    &true_val,          sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes,  sizeof(key_length_bytes)}
    };

    rv = funcs->C_GenerateKey(session, &mech, template, sizeof(template) / sizeof(CK_ATTRIBUTE), key);
    return rv;
}

/**
 * Generate an AES key.
 * @param session
 * @param key_length_bytes
 * @param key
 * @return
 */
CK_RV generate_aes_session_key(CK_SESSION_HANDLE session,
                               CK_ULONG key_length_bytes,
                               CK_OBJECT_HANDLE_PTR key) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    CK_ATTRIBUTE template[] = {
            {CKA_TOKEN,     &false_val,         sizeof(CK_BBOOL)},
            {CKA_VALUE_LEN, &key_length_bytes,  sizeof(key_length_bytes)}
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
            {CKA_TOKEN,           &false_val,           sizeof(CK_BBOOL)},
            {CKA_VERIFY,          &true_val,            sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits, sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, &public_exponent, sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_TOKEN,       &false_val, sizeof(CK_BBOOL)},
            {CKA_SIGN,        &true_val,  sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &true_val,  sizeof(CK_BBOOL)}
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
 * Wrap a key using the wrapping_key handle with given mechanism.
 * The key being wrapped must have the CKA_EXTRACTABLE flag set to true.
 * @param session
 * @param mech
 * @param wrapping_key
 * @param key_to_wrap
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @return
 */
CK_RV aes_wrap_key(CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mech,
                   CK_OBJECT_HANDLE wrapping_key,
                   CK_OBJECT_HANDLE key_to_wrap,
                   CK_BYTE_PTR wrapped_bytes,
                   CK_ULONG_PTR wrapped_bytes_len) {
    return funcs->C_WrapKey(
            session,
            mech,
            wrapping_key,
            key_to_wrap,
            wrapped_bytes,
            wrapped_bytes_len);
}

/**
 * Unwrap a previously wrapped key into the HSM with given mechanism.
 * @param session
 * @param mech
 * @param wrapping_key
 * @param wrapped_key_type
 * @param wrapped_bytes
 * @param wrapped_bytes_len
 * @param unwrapped_key_handle
 * @return
 */
CK_RV aes_unwrap_key(CK_SESSION_HANDLE session,
                     CK_MECHANISM_PTR mech,
                     CK_OBJECT_HANDLE wrapping_key,
                     CK_KEY_TYPE wrapped_key_type,
                     CK_BYTE_PTR wrapped_bytes,
                     CK_ULONG wrapped_bytes_len,
                     CK_OBJECT_HANDLE_PTR unwrapped_key_handle) {
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_ATTRIBUTE *template = NULL;
    CK_ULONG template_count = 0;

    switch (wrapped_key_type) {
        case CKK_DES3:
        case CKK_AES:
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,        sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,         sizeof(CK_BBOOL)}
            };
            template_count = 4;
            break;
        case CKK_RSA:
            key_class = CKO_PRIVATE_KEY;
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,        sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,         sizeof(CK_BBOOL)},
            };
            template_count = 4;
            break;
        case CKK_EC:
            key_class = CKO_PRIVATE_KEY;
            template = (CK_ATTRIBUTE[]) {
                    {CKA_CLASS,       &key_class,        sizeof(key_class)},
                    {CKA_KEY_TYPE,    &wrapped_key_type, sizeof(wrapped_key_type)},
                    {CKA_TOKEN,       &false_val,        sizeof(CK_BBOOL)},
                    {CKA_EXTRACTABLE, &true_val,         sizeof(CK_BBOOL)},
            };
            template_count = 4;
            break;
    }

    return funcs->C_UnwrapKey(
            session,
            mech,
            wrapping_key,
            wrapped_bytes,
            wrapped_bytes_len,
            template,
            template_count,
            unwrapped_key_handle);
}