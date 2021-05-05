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
#ifndef __C_SAMPLES_H__
#define __C_SAMPLES_H__

#include <sys/types.h>
#include <cryptoki.h>
#include <cloudhsm_pkcs11_vendor_defs.h>

#define MAX_SIGNATURE_LENGTH 256

extern CK_FUNCTION_LIST *funcs;
extern CK_BBOOL true_val;
extern CK_BBOOL false_val;

CK_RV pkcs11_initialize(char *library_path);

CK_RV pkcs11_open_session(const CK_UTF8CHAR_PTR pin, CK_SESSION_HANDLE_PTR session);
CK_RV pkcs11_get_slot(CK_SLOT_ID *slot_id);

void pkcs11_finalize_session(CK_SESSION_HANDLE session);

struct pkcs_arguments {
    char *pin;
    char *library;
    CK_OBJECT_HANDLE wrapping_key_handle;
    CK_OBJECT_HANDLE object_handle;
};

int get_pkcs_args(int argc, char **argv, struct pkcs_arguments *args);

int bytes_to_new_hexstring(char *bytes, size_t bytes_len, unsigned char **hex);

int print_bytes_as_hex(char *bytes, size_t bytes_len);

#endif
