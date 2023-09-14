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

CK_RV get_slot(CK_SLOT_ID *const);
CK_RV open_sessions(CK_SLOT_ID, CK_SESSION_HANDLE *const,
                    CK_SESSION_HANDLE *const, CK_SESSION_HANDLE *const);
void display_session_state(const char *, CK_SESSION_HANDLE);
void display_session_states(CK_SESSION_HANDLE, CK_SESSION_HANDLE,
                            CK_SESSION_HANDLE);

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

  CK_SLOT_ID slot_id;
  CK_RV rv = get_slot(&slot_id);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to get first slot.\n");
    return rv;
  }

  printf("Opening three sessions on the first slot.\n");
  rv = open_sessions(slot_id, &session1, &session2, &session3);
  if (CKR_OK != rv) {
    return rv;
  }
  display_session_states(session1, session2, session3);

  printf("Calling C_Login(session1, CU, pin, pin_length) on session 1 to "
         "authenticate the slot.\n");
  rv = funcs->C_Login(session1, CKU_USER, args.pin, (CK_ULONG)strlen(args.pin));
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to login on the slot via session1.\n");
    return rv;
  }
  printf(
      "Successfully logged in to the slot via session1.\nAll sessions on the "
      "slot should now be authenticated with the single C_Login call,\n");
  display_session_states(session1, session2, session3);

  printf("Calling C_Login(session2, CU, pin, pin_length) on session 2 to "
         "authenticate the slot.\n");
  rv = funcs->C_Login(session2, CKU_USER, args.pin, (CK_ULONG)strlen(args.pin));
  if (rv != CKR_USER_ALREADY_LOGGED_IN) {
    fprintf(stderr, "Failure: did not get CKR_USER_ALREADY_LOGGED_IN on login "
                    "on the slot via session2.\n");
    return rv;
  }
  printf("Expected: Failed to log in on session2 because the slot is already "
         "logged in.\n");
  display_session_states(session1, session2, session3);

  printf("Closing session1 via C_CloseSession(session1).\n");
  rv = funcs->C_CloseSession(session1);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to close session1.\n");
    return rv;
  }
  session1 = CK_INVALID_HANDLE;
  printf("Even with session1 closed, we still expect session2 and session3 to "
         "be logged into the slot.\n");
  display_session_states(session1, session2, session3);

  printf("Calling C_Logout(session2) to log out of the slot.\n");
  rv = funcs->C_Logout(session2);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to log out of the slot via session2.\n");
    return rv;
  }
  printf("Now we expect all open sessions on the slot to be logged out.\n");
  display_session_states(session1, session2, session3);
}

CK_RV get_slot(CK_SLOT_ID *const slot_id) {
  if (!slot_id) {
    return CKR_ARGUMENTS_BAD;
  }

  CK_ULONG slot_count = 1;
  CK_RV rv = funcs->C_GetSlotList(CK_TRUE, slot_id, &slot_count);
  if (rv != CKR_OK) {
    printf("C_GetSlotList failed with %lu", rv);
    return rv;
  } else {
    printf("Got the first slot which corresponds to your CloudHSM cluster, "
           "slot id = %lu\n",
           *slot_id);
  }

  return rv;
}

CK_RV open_sessions(CK_SLOT_ID slot_id, CK_SESSION_HANDLE *const session1,
                    CK_SESSION_HANDLE *const session2,
                    CK_SESSION_HANDLE *const session3) {
  // session 1
  CK_RV rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL, NULL, session1);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session1.\n");
    return rv;
  } else {
    printf("Opened session1 on slot %lu\n", slot_id);
  }

  // session 2
  rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, session2);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session2.\n");
    return rv;
  } else {
    printf("Opened session2 on slot %lu\n", slot_id);
  }

  // session 3
  rv = funcs->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, session3);
  if (rv != CKR_OK) {
    fprintf(stderr, "Failed to open session3.\n");
    return rv;
  } else {
    printf("Opened session3 on slot %lu\n", slot_id);
  }

  return CKR_OK;
}

void display_session_state(const char *name, CK_SESSION_HANDLE session_handle) {
  char *state;

  if (session_handle == CK_INVALID_HANDLE) {
    state = "Disconnected from cluster";
  } else {
    CK_SESSION_INFO session_info;
    funcs->C_GetSessionInfo(session_handle, &session_info);
    if (session_info.state == CKS_RW_PUBLIC_SESSION) {
      state = "Connected to cluster: Not logged in";
    } else if (session_info.state == CKS_RW_USER_FUNCTIONS) {
      state = "Connected to cluster: Authenticated";
    } else {
      state = "Connected to cluster: Unexpected state";
    }
  }

  printf("%s: %s\n", name, state);
}

void display_session_states(CK_SESSION_HANDLE session1,
                            CK_SESSION_HANDLE session2,
                            CK_SESSION_HANDLE session3) {
  // all sessions on the slot share the same state. Using session 3 to help
  // illustrate this.
  printf("\n");
  display_session_state("Slot state", session3);
  display_session_state("  * session1", session1);
  display_session_state("  * session2", session2);
  display_session_state("  * session3", session3);
  printf("\n");
}
