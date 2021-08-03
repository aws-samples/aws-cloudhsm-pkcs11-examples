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
#include <inttypes.h>
#include <stdint.h>

#include "common.h"

CK_RV hmac_kdf_sample(CK_SESSION_HANDLE session) {

    CK_RV rv;
    
    /* CKM_SP800_108_KDF is a vendor defined mechanism in CloudHSM.
     * It implements key derivation using the Counter mode construction
     * specified in Section 5.1 of NIST Special Publication 800-108.  
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
        {CKA_DERIVE,          &true_val,          sizeof(CK_BBOOL)}
    };
    rv = funcs->C_GenerateKey(session,
                              &base_key_mech,
                              base_key_template,
                              sizeof(base_key_template) / sizeof(CK_ATTRIBUTE),
                              &base_key);
    if (CKR_OK != rv) {
        printf("Failed to generate base key\n");
        return EXIT_FAILURE;
    } else {
        printf("Generated base AES key of size 32 bytes. Handle: %lu\n", base_key);
    }
   
    /*
     * Create a template for the derived key. Any supported secret key
     * type may be derived.
     */ 
    CK_OBJECT_HANDLE derived_key;
    CK_OBJECT_CLASS derived_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE derived_key_type = CKK_AES;
    CK_ULONG derived_key_len = 32;

    char * derived_key_label = "derived_aes_key";

    CK_ATTRIBUTE derived_key_template[] = {
        {CKA_CLASS,           &derived_key_class,        sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,        &derived_key_type,         sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN,       &derived_key_len,          sizeof(CKA_VALUE_LEN)},
        {CKA_LABEL,           derived_key_label,		 sizeof(derived_key_label)}
    };

    /* 
     * The KDF uses a counter variable and a string of fixed data as inputs
     * to a pseudo-random function.
     *
     * Counter || Label || 0x00 || Context || Length of derived keying material
     *
     * Consequently, the mechanism expects four input parameters. 
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
     * 
     * dkmLengthMethod: Will be applicable in the future for derivation
     * of multiple keys. For now, use the value below.
     */
    CK_SP800_108_DKM_LENGTH_FORMAT dkm_format;
    dkm_format.dkmLengthMethod = SP800_108_DKM_LENGTH_SUM_OF_KEYS;
    dkm_format.ulWidthInBits = 32;

    /*
     * Input 3: Label
     * The label is a string that identifies the purpose for the derived keying
     * material. It is encoded as a binary string.
     */
    CK_BYTE label[] = {0x1, 0xab, 0xe1};

    /* 
     * Input 4: Context
     * The context is a binary string containing information related to the
     * derived keying material.
     */
    CK_BYTE context[] = {0xc, 0x09, 0x7e, 0x7};

    /* Populate the kdf parameters */
    CK_PRF_DATA_PARAM kdf_data_params[] = {
        {SP800_108_COUNTER_FORMAT,    &counter_format,     sizeof(CK_SP800_108_COUNTER_FORMAT)},
        {SP800_108_DKM_FORMAT,        &dkm_format,         sizeof(CK_SP800_108_DKM_LENGTH_FORMAT)},
        {SP800_108_PRF_LABEL,         label,               sizeof(label)},
        {SP800_108_PRF_CONTEXT,       context,             sizeof(context)}
    };

    CK_SP800_108_KDF_PARAMS kdf_params;    
    kdf_params.prftype = CKM_SHA512_HMAC;
    kdf_params.pDataParams = kdf_data_params;
    kdf_params.ulNumberOfDataParams = 4;

    /* Populate the derivation mechanism */       
    CK_MECHANISM derive_mech = {CKM_SP800_108_COUNTER_KDF,
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
    } else {
        printf("Derived AES key of size 32 bytes. Handle: %lu\n", derived_key);
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

    printf("Key derivation using HMAC KDF in Counter mode. Defined in NIST SP 800-108.\n");
    rv = hmac_kdf_sample(session);
    if (CKR_OK != rv) {
        return EXIT_FAILURE;
    }

    pkcs11_finalize_session(session);

    return 0;
}
