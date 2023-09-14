/*
 * Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "common.h"
#include <cryptoki.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

CK_RV open_sessions(CK_SESSION_HANDLE *const, CK_SESSION_HANDLE *const,
                    CK_SESSION_HANDLE *const);
CK_RV generate_ec_keypair(CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key);
CK_RV sign_hello_world(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                       CK_BYTE *const signature, CK_ULONG_PTR signature_length);
CK_RV verify_hello_world(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                         CK_BYTE_PTR signature, CK_ULONG signature_length);

int main(int argc, char **argv) {
  CK_SESSION_HANDLE session1 = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session2 = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session3 = CK_INVALID_HANDLE;
  struct pkcs_arguments args = {0};

  if (get_pkcs_args(argc, argv, &args) < 0) {
    return EXIT_FAILURE;
  }

  if (pkcs11_initialize(args.library) != CKR_OK) {
    return EXIT_FAILURE;
  }

  open_sessions(&session1, &session2, &session3);

  printf("session1: Logging in to slot via session1.\n");
  CK_RV rv =
      funcs->C_Login(session1, CKU_USER, args.pin, (CK_ULONG)strlen(args.pin));
  if (rv != CKR_OK) {
    fprintf(stderr, "session1: Failed to login.\n");
    return rv;
  }

  printf("session1: Creating a session EC key pair that will share the "
         "lifetime of session1.\n");
  CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
  rv = generate_ec_keypair(session1, &public_key, &private_key);
  if (CKR_OK != rv) {
    fprintf(stderr, "session1: Failed to create ec key pair on session1.\n");
    return rv;
  }
  printf("session1: EC key pair's public key handle id: %lu\n", public_key);
  printf("session1: EC key pair's private key handle id: %lu\n\n", private_key);

  printf("session2: Signing 'hello world' with session1's private on "
         "session2: using key handle id: %lu\n",
         private_key);
  CK_BYTE signature[MAX_SIGNATURE_LENGTH];
  CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;
  rv = sign_hello_world(session2, private_key, signature, &signature_length);
  if (CKR_OK != rv) {
    fprintf(stderr, "session2: Failed to sign.\n");
    return rv;
  }
  printf("session2: Successfully signed 'hello world'.\n\n");

  printf("session3: Verify signature on session3 with session1's public "
         "key handle id: %lu\n",
         public_key);
  rv = verify_hello_world(session3, public_key, signature, signature_length);
  if (CKR_OK != rv) {
    fprintf(stderr, "session3: Failed to verify.\n");
    return rv;
  }
  printf("session3: successfully verified.\n\n");

  printf("session1: Closing session1.\n");
  rv = funcs->C_CloseSession(session1);
  if (CKR_OK != rv) {
    printf("session1: Failed to close session1.\n");
    return rv;
  }
  printf("session1: now that session1 is closed, the session key is now "
         "destroyed.\n\n");

  printf("session2: Trying to sign 'hello world' with session1's private key "
         "handle id: "
         "%lu\n",
         private_key);
  rv = sign_hello_world(session2, private_key, signature, &signature_length);
  if (CKR_KEY_HANDLE_INVALID != rv) {
    fprintf(stderr, "session2: Failed to get CKR_KEY_HANDLE_INVALID when "
                    "signing with session 1's session key.\n");
    return rv;
  } else {
    printf("session2: Failed to sign with session 1's session key "
           "because the key handle was invalid after session 1 was closed.\n");
  }
}

CK_RV open_sessions(CK_SESSION_HANDLE *const session1,
                    CK_SESSION_HANDLE *const session2,
                    CK_SESSION_HANDLE *const session3) {
  // get the slot id to open a session on
  CK_SLOT_ID slot_id;
  CK_RV rv = pkcs11_get_slot(&slot_id);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to get first slot.\n");
    return rv;
  }

  // session 1
  rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, session1);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session1.\n");
    return rv;
  }

  // session 2
  rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, session2);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session2.\n");
    return rv;
  }

  // session 3
  rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, session3);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session3.\n");
    return rv;
  }

  return CKR_OK;
}

// To learn more about key generation, please see the generate examples.
CK_RV generate_ec_keypair(CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE_PTR public_key,
                          CK_OBJECT_HANDLE_PTR private_key) {
  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
  CK_BYTE prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                          0xce, 0x3d, 0x03, 0x01, 0x07};

  CK_ATTRIBUTE public_key_template[] = {
      {CKA_VERIFY, &true_val, sizeof(CK_BBOOL)},
      {CKA_EC_PARAMS, prime256v1, sizeof(prime256v1)},
      {CKA_TOKEN, &false_val, sizeof(CK_BBOOL)},
  };

  CK_ATTRIBUTE private_key_template[] = {
      {CKA_SIGN, &true_val, sizeof(CK_BBOOL)},
      {CKA_TOKEN, &false_val, sizeof(CK_BBOOL)},
      {CKA_DERIVE, &true_val, sizeof(CK_BBOOL)},
  };

  CK_RV rv = funcs->C_GenerateKeyPair(
      session, &mech, public_key_template,
      sizeof(public_key_template) / sizeof(CK_ATTRIBUTE), private_key_template,
      sizeof(private_key_template) / sizeof(CK_ATTRIBUTE), public_key,
      private_key);
  return rv;
}

// To learn more about sign/verify, please see the sign examples.
CK_RV sign_hello_world(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                       CK_BYTE *const signature,
                       CK_ULONG_PTR signature_length) {
  CK_MECHANISM mech;
  CK_BYTE_PTR data = "hello world";
  CK_ULONG data_length = (CK_ULONG)strlen(data);

  mech.mechanism = CKM_ECDSA_SHA512;
  mech.ulParameterLen = 0;
  mech.pParameter = NULL;

  CK_RV rv = funcs->C_SignInit(session, &mech, key);
  if (CKR_OK != rv) {
    return rv;
  }

  rv = funcs->C_Sign(session, data, data_length, signature, signature_length);
  return rv;
}

// To learn more about sign/verify, please see the sign examples.
CK_RV verify_hello_world(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                         CK_BYTE_PTR signature, CK_ULONG signature_length) {
  CK_MECHANISM mech;
  CK_BYTE_PTR data = "hello world";
  CK_ULONG data_length = (CK_ULONG)strlen(data);

  mech.mechanism = CKM_ECDSA_SHA512;
  mech.ulParameterLen = 0;
  mech.pParameter = NULL;

  CK_RV rv = funcs->C_VerifyInit(session, &mech, key);
  if (CKR_OK != rv) {
    return rv;
  }

  rv = funcs->C_Verify(session, data, data_length, signature, signature_length);
  return rv;
}