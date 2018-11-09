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
#include <dlfcn.h>
#include <string.h>

#include "common.h"

CK_FUNCTION_LIST *funcs;

/**
 * Load the available PKCS#11 functions into our global function list.
 * @param library_path
 * @return
 */
CK_RV pkcs11_load_functions(char *library_path) {
    CK_RV rv;
    CK_RV(*pFunc)();
    void *d;

    d = dlopen(library_path, RTLD_NOW | RTLD_GLOBAL);
    if (d == NULL) {
        printf("%s not found in linklist of LD_LIBRARY_PATH\n", library_path);
        return CKR_GENERAL_ERROR;
    }

    pFunc = (CK_RV (*)()) dlsym(d, "C_GetFunctionList");
    if (pFunc == NULL) {
        printf("C_GetFunctionList() not found in module %s\n", library_path);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rv = pFunc(&funcs);
    if (rv != CKR_OK) {
        printf("C_GetFunctionList() did not initialize correctly\n");
        return rv;
    }

    return CKR_OK;
}

/**
 * Initialize the PKCS#11 library.
 * This loads the function list and initializes PKCS#11 with our flags.
 * @param library_path
 * @return
 */
CK_RV pkcs11_initialize(char *library_path) {
    CK_RV rv;

    if (!library_path) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_load_functions(library_path);
    if (rv != CKR_OK) {
        printf("Getting PKCS11 function list failed!\n");
        return rv;
    }

    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcs->C_Initialize(&args);
    if (rv != CKR_OK) {
        printf("Failed to initialize\n");
        return rv;
    }

    return CKR_OK;
}

/**
 * Find a slot with an available token.
 * At this time CloudHSM only provides a token on Slot 0. So slot_id
 * only needs space for a single slot and we only call C_GetSlotList once.
 * @param id
 * @param slot_id
 * @return
 */
CK_RV pkcs11_get_slot(CK_SLOT_ID *slot_id) {
    CK_RV rv;
    CK_ULONG slot_count;

    if (!slot_id) {
        return CKR_ARGUMENTS_BAD;
    }

    slot_count = 1;
    rv = funcs->C_GetSlotList(CK_TRUE, slot_id, &slot_count);
    if (rv != CKR_OK) {
        printf("C_GetSlotList failed with %lu", rv);
        return rv;
    }

    return rv;
}

/**
 * Open and login to a session using a given pin.
 * @param pin
 * @param session
 * @return
 */
CK_RV pkcs11_open_session(const CK_UTF8CHAR_PTR pin, CK_SESSION_HANDLE_PTR session) {
    CK_RV rv;
    CK_SLOT_ID slot_id;

    if (!pin || !session) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_get_slot(&slot_id);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL, NULL, session);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = funcs->C_Login(*session, CKU_USER, pin, strlen(pin));

    return rv;
}

/**
 * Logout and finalize the PKCS#11 session.
 * @param session
 */
void pkcs11_finalize_session(CK_SESSION_HANDLE session) {
    funcs->C_Logout(session);
    funcs->C_CloseSession(session);
    funcs->C_Finalize(NULL);
}
