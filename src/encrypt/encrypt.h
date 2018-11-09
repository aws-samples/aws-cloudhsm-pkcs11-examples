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
#ifndef PKCS11_EXAMPLES_ENCRYPT_H
#define PKCS11_EXAMPLES_ENCRYPT_H

#include <stdlib.h>
#include <string.h>

#include <common.h>

#define MAX_ENCRYPTED_DATA_LENGTH 1024
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

CK_RV encrypt_aes(CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR plaintext,
                  CK_ULONG plaintext_length,
                  CK_BYTE_PTR ciphertext,
                  CK_ULONG_PTR ciphertext_length);

CK_RV decrypt_aes(CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR ciphertext,
                  CK_ULONG ciphertext_length,
                  CK_BYTE_PTR plaintext,
                  CK_ULONG_PTR plaintext_length);

CK_RV encrypt_aes_gcm(CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE key,
                      CK_BYTE_PTR plaintext,
                      CK_ULONG plaintext_length,
                      CK_BYTE_PTR aad,
                      CK_ULONG aad_length,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG_PTR ciphertext_length);

CK_RV decrypt_aes_gcm(CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE key,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG ciphertext_length,
                      CK_BYTE_PTR aad,
                      CK_ULONG aad_length,
                      CK_BYTE_PTR decrypted_ciphertext,
                      CK_ULONG_PTR decrypted_ciphertext_length);

#endif //PKCS11_EXAMPLES_ENCRYPT_H
