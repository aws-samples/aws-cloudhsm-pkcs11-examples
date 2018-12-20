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

/**
 * @file
 *
 * @author Nabil S. Al-Ramli
 */

#include "common.h"
#include "destroy.h"

/**
 * Destroy object.
 *
 * @returns CK_RV Value returned by the PKCS#11 library. This will indicate
 *   success or failure.
 */
CK_RV destroy_object(
        /** [in] Valid PKCS11 session. */
        CK_SESSION_HANDLE session,
        /** [in] The object handle. */
        CK_OBJECT_HANDLE object ) {
    CK_RV rv = CKR_OK;

    if (CK_INVALID_HANDLE == session)
        return CKR_ARGUMENTS_BAD;

    if (CK_INVALID_HANDLE == object)
        return CKR_ARGUMENTS_BAD;

    rv = funcs->C_DestroyObject(
            session,
            object );

    return rv;
}
