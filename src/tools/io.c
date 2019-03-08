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

#include "io.h"

/**
 * Write bytes to a file.
 * @param path
 * @param bytes
 * @param len
 * @return Number of bytes written, or -1 on error.
 */
size_t write_wrapped_key(char *path, char *bytes, size_t len) {
    struct stat s = {};

    if (0 == stat(path, &s)) {
        fprintf(stderr, "Path already exists, will not overwrite\n");
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("opening output file");
        return -1;
    }

    size_t n = write(fd, bytes, len);
    if (-1 == n) {
        perror("writing key bytes");
        return -1;
    }

    return n;
}

/**
 * Read an RSA public key into an RSA structure.
 * @param path
 * @return
 */
RSA *read_RSA_PUBKEY(char *path)
{
    /* Read RSA Pub Key */
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        fprintf(stderr, "Failed to allocate RSA struct.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO *pubin = BIO_new_file(path, "r");
    if (pubin == NULL) {
        fprintf(stderr, "Failed to open RSA Pub Key, %s\n%s\n", path, ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if (!PEM_read_bio_RSA_PUBKEY(pubin, &rsa, NULL, NULL)) {
        fprintf(stderr, "Failed to read RSA pub key.\n%s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    BIO_free(pubin);

    return rsa;
}