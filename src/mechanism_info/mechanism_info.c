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

#include "mechanism_info.h"

/**
 * Convert a mechanism code to a human readable string.
 * @param mechanism
 * @return
 */
const char *get_mechanism_name(CK_ULONG mechanism) {
    for (int i=0; i<sizeof(entries) / sizeof(mech_entry); i++) {
        if (entries[i].mechanism == mechanism) {
            return entries[i].mechanism_name;
        }
    }

    printf("Failed to find mechanism name for %lu\n", mechanism);
    return NULL;
}

/**
 * Dump the mechanism list.
 * @param session
 * @param slot_id
 * @return
 */
CK_RV mechanisms(CK_SESSION_HANDLE session, CK_SLOT_ID slot_id) {
    CK_ULONG count;
    CK_MECHANISM_TYPE_PTR mech_list;
    CK_RV rv = funcs->C_GetMechanismList(slot_id, NULL, &count);
    if (CKR_OK != rv)
        return rv;
    
    if (count > 0){
        mech_list = calloc(count, sizeof(CK_MECHANISM_TYPE));
        if (NULL == mech_list) {
            return -1;
        }

        rv = funcs->C_GetMechanismList(slot_id, mech_list, &count);
        if (CKR_OK == rv) {
            for (CK_ULONG i = 0; i < count; i++) {
                CK_MECHANISM_INFO mech;
                rv = funcs->C_GetMechanismInfo(slot_id, mech_list[i], &mech);
                if (CKR_OK == rv) {
                    printf("Mechanism: %s\n\tFlags: %lu\n\tMin Key Size: %lu\n\tMax keysize: %lu\n", get_mechanism_name(mech_list[i]), mech.flags, mech.ulMinKeySize, mech.ulMaxKeySize);
                }
            }
        }

        free(mech_list);
    }

    return 0;
}

int main(int argc, char **argv)
{
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

    CK_SLOT_ID slot_id;
    CK_RV rv = pkcs11_get_slot(&slot_id);
    if (rv != CKR_OK) {
        printf("Could not find token in slot\n");
        return EXIT_FAILURE;
    }

    rv = mechanisms(session, slot_id);
    if (CKR_OK != rv)
        return EXIT_FAILURE;

    pkcs11_finalize_session(session);

    return 0;
}
