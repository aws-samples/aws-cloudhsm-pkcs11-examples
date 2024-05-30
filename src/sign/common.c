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
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "sign.h"

#define MAX_BUF_SIZE 4096

CK_RV generate_signature(CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE key,
                         CK_MECHANISM_TYPE mechanism,
                         CK_BYTE_PTR data,
                         CK_ULONG data_length,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_SignInit(session, &mech, key);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_Sign(session, data, data_length, signature, signature_length);
    return rv;
}

CK_RV multi_part_generate_signature(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE key,
                                    CK_MECHANISM_TYPE mechanism,
                                    CK_BYTE_PTR data,
                                    CK_ULONG data_length,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG_PTR signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_SignInit(session, &mech, key);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_SignUpdate(session, data, data_length);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_SignFinal(session, signature, signature_length);
    return rv;
}

CK_RV verify_signature(CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE key,
                       CK_MECHANISM_TYPE mechanism,
                       CK_BYTE_PTR data,
                       CK_ULONG data_length,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_VerifyInit(session, &mech, key);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
    return rv;
}

CK_RV multi_part_verify_signature(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key,
                                  CK_MECHANISM_TYPE mechanism,
                                  CK_BYTE_PTR data,
                                  CK_ULONG data_length,
                                  CK_BYTE_PTR signature,
                                  CK_ULONG signature_length) {
    CK_RV rv;
    CK_MECHANISM mech;

    mech.mechanism = mechanism;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_VerifyInit(session, &mech, key);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_VerifyUpdate(session, data, data_length);
    if (CKR_OK != rv) {
        return !CKR_OK;
    }

    rv = funcs->C_VerifyFinal(session, signature, signature_length);    
    return rv;
}
CK_RV generate_x509cert(CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE private_key,
                    CK_OBJECT_HANDLE public_key,
                    CK_MECHANISM_TYPE mechanism)
{
    // Create a new X509 certificate
    char *subject_name = "CN=example.com,O=Example Corp.,C=US";
    X509 *x509 = X509_new();
    X509_set_version(x509, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for 1 year
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)subject_name, -1, -1, 0);
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);

    // Assume `session` is an active PKCS#11 session and `key` is the handle to the HSM key
    CK_RV rv;
    CK_ATTRIBUTE key_template[] = {
        {CKA_PUBLIC_EXPONENT, NULL, 0},
        {CKA_MODULUS, NULL, 0}};
    CK_ULONG key_template_len = sizeof(key_template) / sizeof(CK_ATTRIBUTE);

    // Get the public key attributes
    rv = funcs->C_GetAttributeValue(session, public_key, key_template, key_template_len);
    if (rv != CKR_OK)
    {
        printf("Error: C_GetAttributeValue() failed\n");
        return rv;
    }

    // Create an RSA public key from the key attributes
    BIGNUM *modulus = BN_bin2bn(key_template[1].pValue, key_template[1].ulValueLen, NULL);
    BIGNUM *exponent = BN_bin2bn(key_template[0].pValue, key_template[0].ulValueLen, NULL);
    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, modulus, exponent, NULL);

    // Create an EVP_PKEY object from the RSA key
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);

    // Set the public key of the X.509 certificate
    X509_set_pubkey(x509, pkey);

    // Sign the certificate using the HSM
    BIO *bio_mem;
    unsigned char buf[MAX_BUF_SIZE];
    int len;
    bio_mem = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio_mem, x509);
    len = BIO_read(bio_mem, buf, MAX_BUF_SIZE);
    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;
    rv = generate_signature(session, private_key, mechanism, buf, len, signature, &signature_length);
    if (rv != CKR_OK) {
        printf("Error generating signature: %ld\n", rv);
        return rv;
    }
    
    rv = verify_signature(session, public_key, mechanism,
                          buf, len, signature, signature_length);
    if (CKR_OK == rv) {
        printf("Verification successful\n");
    } else {
        printf("Verification failed: %lu\n", rv);
        return rv;
    }

    return CKR_OK;
}