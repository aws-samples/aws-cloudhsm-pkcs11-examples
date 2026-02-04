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

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "common.h"

const char* EXAMPLE_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----\n"
"MIIDPzCCAiegAwIBAgIJAN5ZU/3X7yoDMA0GCSqGSIb3DQEBCwUAMDYxGTAXBgNV\n"
"BAMMEENsb3VkSFNNIEV4YW1wbGUxDDAKBgNVBAoMA0FXUzELMAkGA1UEBhMCVVMw\n"
"HhcNMjUwNzExMjAxOTIyWhcNMjYwNzExMjAxOTIyWjA2MRkwFwYDVQQDDBBDbG91\n"
"ZEhTTSBFeGFtcGxlMQwwCgYDVQQKDANBV1MxCzAJBgNVBAYTAlVTMIIBIjANBgkq\n"
"hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAywA5EIPaS81ph2feix3v784ryyhp9tFj\n"
"AdMxjW3xakycpzOjadqxYNgSd4NIsmrR6NxC9MvDPb84fao5MmlYKye+61THllAu\n"
"6YxYKUZze75wlRuSVeJZCyaP/G//tbEo94CnpeUlot0zE5Sup5aVFSRx5pENwAMQ\n"
"x21tgSKcOU+jXNQN7LaJ5N8LvC9dPhhexT6XODxHeZyYuHAPrTdsJMrDq2Eiw7Yd\n"
"hIkNFlPQ53itwxZ63wg4JdFMFX9fjydMPxBAt8lBB5Pnzv/+xVBunO7MX+pM1Yf1\n"
"FcO3BOqrn9AGtsZ6PeYaJL+rVNBTLfzFD6pUs9rPFQ3h0yshCF5RWwIDAQABo1Aw\n"
"TjAdBgNVHQ4EFgQUXjwXmf9CwMH8E51PUsb8FOTa2DwwHwYDVR0jBBgwFoAUXjwX\n"
"mf9CwMH8E51PUsb8FOTa2DwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
"AQEARkTeTtRncINfbUWbatIaBWnwW626hifin8bxSpYvGGs6w3nCGviXcFklhucW\n"
"iPevxLHvNTQbTbsKgzw5tq33lfsm6PdGu/zSAJ91nFXMq7F/DLvLvOpu5K5Qetn+\n"
"ERfSYTd84QDYP8ZtYn3hzTsu+lk6VtqHdIeU/BDNmS2CKXCsy8ZVkaVp6jlQeuK6\n"
"28iWQxXO5NU02VnuLgPvUq4ua/sz6+Od/2lqtLtFQjF6ryvwax4pSquv+KpFU8nt\n"
"RfKz+973l2On5D2fhwDviEoq6K/OyIp7jAJJCvk2XSmaUoZHBWrPyN6HSN2Itn9R\n"
"SM9mTCdWVyhv7gpCWIJ+POzcVw==\n"
"-----END CERTIFICATE-----";

/**
 * Find certificates that match a passed CK_ATTRIBUTE template.
 * 
 * Memory will be allocated in a passed pointer, and reallocated as more certificates
 * are found. The number of found certificates is returned through the count parameter.
 * 
 * @param session         Valid PKCS#11 session handle
 * @param attr_template   Pointer to an array of CK_ATTRIBUTE structures defining the search criteria
 * @param attr_count      Number of attributes in the template array
 * @param count           Pointer to receive the number of objects found
 * @param object_handles  Pointer to receive dynamically allocated array of object handles
 * @return CK_RV          Return value from the PKCS#11 library
 */
CK_RV find_by_attr(CK_SESSION_HANDLE session, CK_ATTRIBUTE *attr_template, CK_ULONG attr_count, CK_ULONG *count,
                   CK_OBJECT_HANDLE_PTR *object_handles) {
    CK_RV rv;

    if (NULL == object_handles || NULL == attr_template || NULL == count) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = funcs->C_FindObjectsInit(session, attr_template, attr_count);
    if (CKR_OK != rv) {
        fprintf(stderr, "Can't initialize search\n");
        return rv;
    }

    CK_ULONG max_objects = 25;
    bool searching = 1;
    *count = 0;
    while (searching) {
        CK_ULONG found = 0;
        CK_OBJECT_HANDLE_PTR temp = realloc(*object_handles, (*count + max_objects) * sizeof(CK_OBJECT_HANDLE));
        if (NULL == temp) {
            fprintf(stderr, "Could not allocate memory for objects\n");
            funcs->C_FindObjectsFinal(session);
            return CKR_HOST_MEMORY;
        }
        *object_handles = temp;

        CK_OBJECT_HANDLE_PTR loc = *object_handles;
        rv = funcs->C_FindObjects(session, &loc[*count], max_objects, &found);
        if (CKR_OK != rv) {
            fprintf(stderr, "Can't run search\n");
            funcs->C_FindObjectsFinal(session);
            return rv;
        }

        (*count) += found;

        if (0 == found)
            searching = 0;
    }

    rv = funcs->C_FindObjectsFinal(session);
    if (CKR_OK != rv) {
        fprintf(stderr, "Can't finalize search\n");
        return rv;
    }

    if (0 == *count) {
        fprintf(stderr, "Didn't find requested certificate\n");
        return rv;
    }

    return CKR_OK;
}

/**
 * Parse a PEM certificate into an X509 object
 *
 * @param pem_data  Pointer to the PEM certificate data
 * @param cert      Pointer to receive the X509 certificate object
 * @return CK_RV    CKR_OK on success, CKR_GENERAL_ERROR on failure
 */
CK_RV parse_pem_to_x509(const char *pem_data, X509 **cert) {
    BIO *bio = NULL;
    
    if (!pem_data || !cert) {
        fprintf(stderr, "Invalid arguments to parse_pem_to_x509\n");
        return CKR_ARGUMENTS_BAD;
    }
    
    // Create a BIO from the PEM data
    bio = BIO_new_mem_buf(pem_data, -1); // -1 means calculate length
    if (!bio) {
        fprintf(stderr, "Failed to create BIO\n");
        return CKR_GENERAL_ERROR;
    }
    
    // Read the certificate from the BIO
    *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!*cert) {
        fprintf(stderr, "Failed to parse PEM certificate\n");
        BIO_free(bio);
        return CKR_GENERAL_ERROR;
    }
    
    // Clean up
    BIO_free(bio);
    
    return CKR_OK;
}

/**
 * Helper function to encode an X.509 certificate to DER format
 *
 * @param cert            Pointer to the X509 certificate
 * @param out_der_data    Pointer to receive the DER encoded data
 * @param out_der_length  Pointer to receive the length of the DER data
 * @return CK_RV          CKR_OK on success, CKR_GENERAL_ERROR on failure
 */
CK_RV convert_x509_to_der(
    X509 *cert,
    CK_BYTE_PTR *out_der_data,
    CK_ULONG *out_der_length
) {
    if (!cert || !out_der_data || !out_der_length) {
        fprintf(stderr, "Invalid arguments to convert_x509_to_der\n");
        return CKR_ARGUMENTS_BAD;
    }
    
    // Calculate the DER size
    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to calculate DER size for X.509 certificate\n");
        return CKR_GENERAL_ERROR;
    }
    
    *out_der_length = (CK_ULONG)der_len;
    
    // Allocate memory for the DER data
    *out_der_data = (CK_BYTE_PTR)malloc(*out_der_length);
    if (!*out_der_data) {
        fprintf(stderr, "Failed to allocate memory for DER data\n");
        return CKR_HOST_MEMORY;
    }
    
    // Convert to DER format
    CK_BYTE_PTR p = *out_der_data;
    if (i2d_X509(cert, (unsigned char **)&p) <= 0) {
        fprintf(stderr, "Failed to encode X.509 certificate to DER format\n");
        free(*out_der_data);
        *out_der_data = NULL;
        return CKR_GENERAL_ERROR;
    }
    
    return CKR_OK;
}

/**
 * Extract the subject from an X509 certificate
 *
 * @param cert                Pointer to the X509 certificate
 * @param out_subject_data    Pointer to receive the DER encoded subject data
 * @param out_subject_length  Pointer to receive the length of the subject data
 * @return CK_RV              CKR_OK on success, CKR_GENERAL_ERROR on failure
 */
CK_RV extract_subject_from_x509(
    X509 *cert,
    CK_BYTE_PTR *out_subject_data,
    CK_ULONG *out_subject_length
) {
    X509_NAME *subject = NULL;
    
    if (!cert || !out_subject_data || !out_subject_length) {
        fprintf(stderr, "Invalid arguments to extract_subject_from_x509\n");
        return CKR_ARGUMENTS_BAD;
    }
    
    // Get the subject from the certificate
    subject = X509_get_subject_name(cert);
    if (!subject) {
        fprintf(stderr, "Failed to get subject from certificate\n");
        return CKR_GENERAL_ERROR;
    }
    
    // Calculate the DER size
    int der_len = i2d_X509_NAME(subject, NULL);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to calculate DER size for subject\n");
        return CKR_GENERAL_ERROR;
    }
    
    *out_subject_length = (CK_ULONG)der_len;
    
    // Allocate memory for the DER data
    *out_subject_data = (CK_BYTE_PTR)malloc(*out_subject_length);
    if (!*out_subject_data) {
        fprintf(stderr, "Failed to allocate memory for subject DER data\n");
        return CKR_HOST_MEMORY;
    }
    
    // Convert to DER format
    CK_BYTE_PTR p = *out_subject_data;
    if (i2d_X509_NAME(subject, (unsigned char **)&p) <= 0) {
        fprintf(stderr, "Failed to encode subject to DER format\n");
        free(*out_subject_data);
        *out_subject_data = NULL;
        return CKR_GENERAL_ERROR;
    }
    
    return CKR_OK;
}

/**
 * Store a certificate in the HSM with a specified label
 *
 * @param session          Valid PKCS#11 session handle
 * @param label            Label to assign to the certificate
 * @param label_length     Length of the label
 * @param cert             Pointer to the X509 certificate
 * @param out_cert_handle  Pointer to receive the object handle of the stored certificate
 * @return CK_RV           Return value from the PKCS#11 library
 */
CK_RV store_certificate(
    CK_SESSION_HANDLE session,
    CK_BYTE_PTR label,
    CK_ULONG label_length,
    X509 *cert,
    CK_OBJECT_HANDLE_PTR out_cert_handle
) {
    CK_RV rv;
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_CERTIFICATE_CATEGORY cert_category = CK_CERTIFICATE_CATEGORY_UNSPECIFIED;
    CK_BYTE_PTR der_data = NULL;
    CK_ULONG der_length = 0;
    CK_BYTE_PTR subject_data = NULL;
    CK_ULONG subject_len = 0;
    
    if (!label || !cert || !out_cert_handle) {
        return CKR_ARGUMENTS_BAD;
    }
    
    // Extract subject from certificate
    rv = extract_subject_from_x509(
        cert,
        &subject_data,
        &subject_len
    );
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to extract subject from certificate\n");
        free(der_data);
        return rv;
    }

    // Convert certificate to DER format
    rv = convert_x509_to_der(
        cert,
        &der_data,
        &der_length
    );
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to convert certificate to DER format\n");
        return rv;
    }
    
    /**
     * To enable certificate storage, use the `configure-pkcs11 --enable-certificate-storage` command.
     * See the list of supported attributes: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-certificate-storage-attributes.html
     */
    CK_ATTRIBUTE certificate_template[] = {
        {CKA_CLASS, &cert_class, sizeof(cert_class)},
        {CKA_TOKEN, &true_val, sizeof(CK_BBOOL)},
        {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type)},
        {CKA_CERTIFICATE_CATEGORY, &cert_category, sizeof(cert_category)},
        {CKA_SUBJECT, subject_data, subject_len},
        {CKA_VALUE, der_data, der_length},
        {CKA_LABEL, label, label_length},
    };
    
    // Create the certificate object on the HSM
    rv = funcs->C_CreateObject(
        session,
        certificate_template,
        sizeof(certificate_template) / sizeof(CK_ATTRIBUTE),
        out_cert_handle
    );
    
    if (CKR_OK == rv && CK_INVALID_HANDLE != *out_cert_handle) {
        printf("Certificate stored successfully with handle: %lu\n", *out_cert_handle);
    } else {
        fprintf(stderr, "Failed to store certificate. Error: 0x%lx\n", rv);
    }
    
    // Clean up
    free(subject_data);
    free(der_data);
    
    return rv;
}

/**
 * Delete a certificate in the HSM with object handle
 * 
 * @param session      Valid PKCS#11 session handle
 * @param cert_handle  Valid object handle of the stored certificate
 * @returns CK_RV      Return value from the PKCS#11 library
 */
CK_RV delete_certificate(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE cert_handle
) {
    CK_RV rv;

    if (CK_INVALID_HANDLE == session)
        return CKR_ARGUMENTS_BAD;

    if (CK_INVALID_HANDLE == cert_handle)
        return CKR_ARGUMENTS_BAD;

    // Delete the certificate object from the HSM
    rv = funcs->C_DestroyObject(
            session,
            cert_handle);
    
    if (CKR_OK == rv) {
        printf("Certificate deleted successfully with handle: %lu\n", cert_handle);
    } else {
        fprintf(stderr, "Failed to delete certificate. Error: 0x%lx\n", rv);
    }

    return rv;
}

CK_RV find_certificate_by_label_example(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_BYTE_PTR label = "example_certificate_1";
    CK_ULONG label_len = (CK_ULONG)strlen(label);
    X509 *cert = NULL;
    CK_OBJECT_HANDLE_PTR found_objects = NULL;
    CK_ULONG count = 0;

    // Parse PEM to X509
    rv = parse_pem_to_x509(EXAMPLE_CERTIFICATE_PEM, &cert);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to parse PEM certificate\n");
        return rv;
    }

    // Create certificate in the HSM with label
    rv = store_certificate(session, label, label_len, cert, &cert_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not create certificates\n");
        X509_free(cert);
        return rv;
    }

    // Create search template with label
    CK_ATTRIBUTE search_template[] = {
            {CKA_CLASS, &cert_class, sizeof(cert_class)},
            {CKA_LABEL, label, label_len},
    };

    // Find certificates with search template
    rv = find_by_attr(session, search_template, 2, &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find certificates\n");
        X509_free(cert);
        return rv;
    }

    printf("Found %lu certificates\n", count);
    for (CK_ULONG i = 0; i < count; i++) {
        printf("Found certificate handle %lu\n", found_objects[i]);
    }

    free(found_objects);

    // Delete certificate in the HSM with object handle
    rv = delete_certificate(session, cert_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not delete certificates\n");
        X509_free(cert);
        return rv;
    }

    // Clean up
    X509_free(cert);

    return CKR_OK;
}

CK_RV find_certificate_by_search_template(CK_SESSION_HANDLE session) {
    CK_RV rv;
    CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_BYTE_PTR label = "example_certificate_2";
    CK_ULONG label_len = (CK_ULONG)strlen(label);
    X509 *cert = NULL;
    CK_BYTE_PTR subject_data = NULL;
    CK_ULONG subject_len = 0;
    CK_OBJECT_HANDLE_PTR found_objects = NULL;
    CK_ULONG count = 0;

    // Parse PEM to X509
    rv = parse_pem_to_x509(EXAMPLE_CERTIFICATE_PEM, &cert);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to parse PEM certificate\n");
        return rv;
    }

    // Extract subject from X509 certificate
    rv = extract_subject_from_x509(cert, &subject_data, &subject_len);
    if (CKR_OK != rv) {
        fprintf(stderr, "Failed to extract subject from certificate\n");
        X509_free(cert);
        return rv;
    }

    // Create certificate in the HSM with label
    rv = store_certificate(session, label, label_len, cert, &cert_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not create certificates\n");
        free(subject_data);
        X509_free(cert);
        return rv;
    }

    // Create Search template with subject
    CK_ATTRIBUTE search_template[] = {
            {CKA_CLASS, &cert_class, sizeof(cert_class)},
            {CKA_SUBJECT, subject_data, subject_len},
    };

    // Find certificates with search template
    rv = find_by_attr(session, search_template, 2, &count, &found_objects);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not find certificates\n");
        free(subject_data);
        X509_free(cert);
        return rv;
    }

    printf("Found %lu certificates\n", count);
    for (CK_ULONG i = 0; i < count; i++) {
        printf("Found certificate handle %lu\n", found_objects[i]);
    }

    free(found_objects);

    // Delete certificate in the HSM with object handle
    rv = delete_certificate(session, cert_handle);
    if (CKR_OK != rv) {
        fprintf(stderr, "Could not delete certificates\n");
        free(subject_data);
        X509_free(cert);
        return rv;
    }

    // Clean up
    free(subject_data);
    X509_free(cert);

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
        
    printf("Searching for certificates by label\n");
    rv = find_certificate_by_label_example(session);
    if (CKR_OK != rv) {
        pkcs11_finalize_session(session);
        return EXIT_FAILURE;
    }

    printf("Searching for certificates by subject\n");
    rv = find_certificate_by_search_template(session);
    if (CKR_OK != rv) {
        pkcs11_finalize_session(session);
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return EXIT_SUCCESS;
}
