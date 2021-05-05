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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "common.h"
#include "destroy.h"

void show_help()
{
    fprintf(stdout, "\t--object-id <object_id>\n");
}

int main(int argc, char **argv)
{
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session;
    struct pkcs_arguments args = {0};

    if (get_pkcs_args(argc, argv, &args) < 0 || args.object_handle == CK_INVALID_HANDLE) {
        show_help();
        return CKR_ARGUMENTS_BAD;
    }

    if (pkcs11_initialize(args.library) != CKR_OK) {
        return EXIT_FAILURE;
    }

    if (pkcs11_open_session(args.pin, &session) != CKR_OK) {
        return EXIT_FAILURE;
    }

    rv = destroy_object(session, args.object_handle);
    if (rv != CKR_OK) {
        fprintf(stdout, "ERROR: Failed to destroy Object: %lu\n", rv);
    }

    return rv;
}
