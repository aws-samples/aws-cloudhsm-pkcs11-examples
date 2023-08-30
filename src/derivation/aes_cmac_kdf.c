/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <inttypes.h>
#include <stdint.h>

#include "common.h"

CK_RV aes_cmac_kdf_sample(CK_SESSION_HANDLE session) {

    CK_RV rv;

    /* CKM_CLOUDHSM_SP800_108_COUNTER_KDF is a vendor defined mechanism in CloudHSM.
     * It implements key derivation using the Counter mode construction
     * specified in Section 5.1 of NIST Special Publication 800-108 at
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf.
     */
    
    /* Generate the Key Derivation Key aka the base key. This key will be
     * used as an input to the derivation function, along with other input data.
     */
    CK_OBJECT_HANDLE base_key;
    CK_MECHANISM base_key_mech = {CKM_AES_KEY_GEN, NULL, 0};
    CK_OBJECT_CLASS base_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE base_key_type = CKK_AES;
    CK_ULONG base_key_len = 32;

    CK_ATTRIBUTE base_key_template[] = {
        {CKA_CLASS,           &base_key_class,    sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,        &base_key_type,     sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN,       &base_key_len,      sizeof(CKA_VALUE_LEN)},
        {CKA_DERIVE,          &true_val,          sizeof(CK_BBOOL)},
        {CKA_TOKEN,           &false_val,         sizeof(CK_BBOOL)}
    };
    rv = funcs->C_GenerateKey(session,
                              &base_key_mech,
                              base_key_template,
                              sizeof(base_key_template) / sizeof(CK_ATTRIBUTE),
                              &base_key);
    if (CKR_OK != rv) {
        printf("Failed to generate base key\n");
        return rv;
    }

    printf("Generated base AES key of size 32 bytes. Handle: %lu\n", base_key);
   
    /*
     * Create a template for the derived key.
     * For more information about the type of keys which may be derived, take a look at
     * https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html.
     */
    CK_OBJECT_HANDLE derived_key;
    CK_OBJECT_CLASS derived_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE derived_key_type = CKK_AES;
    CK_ULONG derived_key_len = 32;

    char * derived_key_label = "derived_aes_cmac_key";

    CK_ATTRIBUTE derived_key_template[] = {
        {CKA_CLASS,           &derived_key_class,        sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,        &derived_key_type,         sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN,       &derived_key_len,          sizeof(CKA_VALUE_LEN)},
        {CKA_LABEL,           derived_key_label,		 (unsigned int)strlen(derived_key_label)},
        {CKA_TOKEN,           &false_val,                sizeof(CK_BBOOL)}
    };

    /* 
     * The KDF uses a counter variable and a string of fixed data as inputs
     * to a pseudo-random function.
     */

    /* 
     * Input 1: Counter format
     * Format of the iteration counter represented as a binary string.
     * Only supported counter widths are 16 and 32
     */
    CK_SP800_108_COUNTER_FORMAT counter_format;
    counter_format.ulWidthInBits = 32;

    /* 
     * Input 2: DKM format
     * Format of the derived keying material. It has two fields -
     *
     * ulWidthInBits: Only supported DKM widths are 8, 16, 32 and 64
     * dkmLengthMethod: Only supported method is SP800_108_DKM_LENGTH_SUM_OF_KEYS
     */
    CK_SP800_108_DKM_LENGTH_FORMAT dkm_format;
    dkm_format.dkmLengthMethod = SP800_108_DKM_LENGTH_SUM_OF_KEYS;
    dkm_format.ulWidthInBits = 32;

    /*
     * Input 3: encoded_input_data
     * This data is represented as 2 arrays. One is called prefix and other one suffix.

     * The prefix array will be prepended to the counter and the suffix array will be appended
     * to the counter. The prefix and suffix arrays may include any combination of Label, Context,
     * a concatenation of both, or an empty array. In this example, the Label is included in the
     * prefix and the Context is included in the suffix.

     * Label:
     * The label is a string that identifies the purpose for the derived keying
     * material. It is encoded as a binary string.
     * For more information, refer to the NIST Special Publication 800-108.
     * for example: CK_BYTE label[] = {0x1, 0xab, 0xe1}; has been used as encoded_input_data_prefix in this example.

     * Context:
     * The context is a binary string containing information related to the
     * derived keying material.
     * For more information, refer to the NIST Special Publication 800-108.
     * for example: CK_BYTE context[] = {0xc, 0x09, 0x7e, 0x7}; has been used as encoded_input_data_suffix.
     */

    CK_BYTE encoded_input_data_prefix[] = {0x1, 0xab, 0xe1};
    CK_BYTE encoded_input_data_suffix[] = {0xc, 0x09, 0x7e, 0x7};

    /*
    * When specifying the KDF parameters, the ordering of the inputs determine the derived key material.
    * Different orders will result in a different derived key.
    *
    * In this example, we specify the ordering: Label (prefix), Counter, Context (suffix), followed by
    * the DKM Length. It is important to maintain this order in any application that expects to derive
    * this same key.
    */
    CK_PRF_DATA_PARAM kdf_data_params[] = {
        {CK_SP800_108_BYTE_ARRAY,            &encoded_input_data_prefix,         sizeof(encoded_input_data_prefix)},
        {CK_SP800_108_ITERATION_VARIABLE,    &counter_format,                    sizeof(CK_SP800_108_COUNTER_FORMAT)},
        {CK_SP800_108_BYTE_ARRAY,            &encoded_input_data_suffix,         sizeof(encoded_input_data_suffix)},
        {CK_SP800_108_DKM_LENGTH,            &dkm_format,                        sizeof(CK_SP800_108_DKM_LENGTH_FORMAT)}
    };

    CK_SP800_108_KDF_PARAMS kdf_params;    
    kdf_params.prftype = CKM_AES_CMAC;
    kdf_params.pDataParams = kdf_data_params;
    kdf_params.ulNumberOfDataParams = 4;

    /* Populate the derivation mechanism */       
    CK_MECHANISM derive_mech = {CKM_CLOUDHSM_SP800_108_COUNTER_KDF /* CloudHSM defined KDF mechanism */,
                                &kdf_params, 
                                sizeof(CK_SP800_108_KDF_PARAMS)};
 
    /* Perform the derivation operation */
    rv = funcs->C_DeriveKey(session, 
                            &derive_mech, 
                            base_key, 
                            derived_key_template, 
                            sizeof(derived_key_template) / sizeof(CK_ATTRIBUTE), 
                            &derived_key);
    if (CKR_OK != rv) {
        printf("Failed to derive key\n");
        return rv;
    }

    printf("Derived AES key of size 32 bytes. Handle: %lu\n", derived_key);
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
        printf("Pkcs11 initialization failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    rv = pkcs11_open_session(args.pin, &session);
    if (CKR_OK != rv) {
        printf("Pkcs11 session open failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    printf("Key derivation using AES CMAC KDF in Counter mode. Defined in NIST SP 800-108.\n");
    rv = aes_cmac_kdf_sample(session);
    if (CKR_OK != rv) {
        printf("AES CMAC KDF derivation failed: %lu\n", rv);
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return 0;
}
