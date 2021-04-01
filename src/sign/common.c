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
#include "sign.h"

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
