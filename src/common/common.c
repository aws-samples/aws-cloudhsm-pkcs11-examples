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
#include <memory.h>
#include <getopt.h>
#include <stdlib.h>

#include "common.h"

CK_BBOOL true_val = TRUE;
CK_BBOOL false_val = FALSE;

static void show_help() {
    printf("\n\t--pin <user:password>\n\t[--library <path/to/pkcs11>]\n\n");
}

int get_pkcs_args(int argc, char **argv, struct pkcs_arguments *args) {
    if (!args || !argv) {
        return -1;
    }

    int c;
    char *pin = NULL;
    char *library = NULL;

    while (1) {
        static struct option long_options[] =
                {
                        {"pin",     required_argument, 0, 0},
                        {"library", required_argument, 0, 0},
                        {0, 0,                         0, 0}
                };

        int option_index = 0;

        c = getopt_long(argc, argv, "",
                        long_options, &option_index);

        if (c == -1)
            break;

        switch (option_index) {
            case 0:
                pin = optarg;
                break;

            case 1:
                library = optarg;
                break;

            default:
                printf("Unknown arguments");
                show_help();
                return -1;
        }
    }

    if (!pin) {
        show_help();
        return -1;
    }

    args->pin = pin;
    args->library = library;

    // Default to the standard CloudHSM PKCS#11 library location.
    if (!args->library) {
        args->library = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so";
    }

    return 0;
}

/**
 * Converts a byte array to a hex string.
 * This function will allocate the appropriate memory for the hex string.
 * If a valid pointer is passed, that pointer will be reallocated. This
 * allows the caller to reuse the same pointer through multiple calls.
 * @param bytes
 * @param bytes_len
 * @param hex
 * @return
 */
int bytes_to_new_hexstring(char *bytes, size_t bytes_len, unsigned char **hex_array) {
    if (!bytes || !hex_array) {
        return -1;
    }

    unsigned char *tmp = realloc(*hex_array, bytes_len * 2 + 1);
    if (!tmp) {
        if (*hex_array) {
            free(*hex_array);
        }
        return -1;
    }
    *hex_array = tmp;
    memset(*hex_array, 0, bytes_len * 2 + 1);

    char values[16] = "0123456789ABCDEF";
    for (int i = 0, j = 0; i < bytes_len; i++, j += 2) {
        *((*hex_array) + j) = values[bytes[i] >> 4 & 0x0f];
        *((*hex_array) + j + 1) = values[bytes[i] & 0x0f];
    }

    return 0;
}

/**
 * Prints a byte array as a hex string.
 * @param bytes
 * @param bytes_len
 * @return
 */
int print_bytes_as_hex(char *bytes, size_t bytes_len) {
    if (!bytes || bytes_len < 1) {
        return -1;
    }

    for (int i = 0; i < bytes_len; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");

    return 0;
}
