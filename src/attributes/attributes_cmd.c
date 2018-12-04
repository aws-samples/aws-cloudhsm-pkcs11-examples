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
#include <getopt.h>

#include "common.h"
#include "attributes.h"

void show_help()
{
    fprintf(stdout, "\n\t--object-id <object_id>\n\n");
}

int main(int argc, char **argv)
{
    int c = 0;
    char **argv_copy = NULL;
    size_t i = (size_t)0;
    size_t j = (size_t)0;
    const char *object_id = "";
    CK_OBJECT_HANDLE object_id_val = CK_INVALID_HANDLE;
    CK_RV rv = CKR_OK;
    CK_SESSION_HANDLE session;
    struct pkcs_arguments args = {};

    while (1)
    {
        int option_index = 0;
        static struct option long_options[] =
        {
            {"object-id", required_argument, 0, 0},
            {"pin",     required_argument, 0, 0},
            {"library", required_argument, 0, 0},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;

        switch (option_index)
        {
            case 0:
                object_id = optarg;
                break;
            default:
                break;
        }
    }
    optind = 0;

    argv_copy = (char **)calloc((size_t)argc, sizeof(char *));
    if( NULL == argv_copy )
    {
        fprintf(stdout, "Error: Failed to allocate memory\n");
        return CKR_HOST_MEMORY;
    }

    for(i = (size_t)0; i < (size_t)argc; i++) {
        if(0 == strcmp(argv[i], "--object-id")) {
          i++;
          continue;
        }

        argv_copy[j++] = argv[i];
    }

    if (get_pkcs_args(argc - 2, argv_copy, &args) < 0) {
        free(argv_copy);
        show_help();
        return CKR_ARGUMENTS_BAD;
    }

    free(argv_copy);
    sscanf(object_id, "%lu", &object_id_val);

    rv = pkcs11_initialize(args.library);
    rv = pkcs11_open_session(args.pin, &session);

    rv = attributes_output_all(session, object_id_val, stdout);
    if (rv != CKR_OK) {
        fprintf(stdout, "ERROR: Failed to enumerate Object attributes: %lu\n", rv);
    }

    return rv;
}
