/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdint.h>
#include <getopt.h>

#include "common.h"
#include "hmac_kdf.h"

void show_help() {
  size_t _i = (size_t)0;

  fprintf(stderr, "\n");
  fprintf(stderr, "\tRequired parameter:\n");
  fprintf(stderr, "\t  --object-id <object_id>\n");
  fprintf(stderr, "\t      object_id: The input key handle (KDK).\n");
  fprintf(stderr, "\t  --object-val-len <object_val_len>\n");
  fprintf( stderr, "\t      object_val_len: The size of the key referred to "
      "by object_id.\n" );
  fprintf(stderr, "\t  --prf-type <prf_type>\n");
  fprintf(stderr, "\t      prf_type: The PRF type. Could be one of\n");

  for ( _i = HMAC_KDF_PRF_TYPE_FIRST; _i < HMAC_KDF_PRF_TYPE_COUNT; _i++ )
    fprintf(stderr, "\t        %s\n",
        hmac_kdf_get_prf_name_by_type((HMAC_KDF_PRF_TYPE)_i));

  fprintf(stderr, "\t  --key-type <key_type>\n");
  fprintf(stderr, "\t      key_type: The derived key type. Could be one of\n");

  for ( _i = HMAC_KDF_KEY_TYPE_FIRST; _i < HMAC_KDF_KEY_TYPE_COUNT; _i++ )
    fprintf(stderr, "\t        %s\n",
        hmac_kdf_get_key_name_by_type((HMAC_KDF_KEY_TYPE)_i));

  fprintf(stderr, "\t  --counter-format <counter_format>\n");
  fprintf( stderr, "\t      counter_format: The counter format. Could be one "
      "of\n" );

  for ( _i = HMAC_KDF_COUNTER_FORMAT_FIRST;
        _i < HMAC_KDF_COUNTER_FORMAT_COUNT; _i++ )
    fprintf(stderr, "\t        %zu\n",
        hmac_kdf_get_counter_format_value((HMAC_KDF_COUNTER_FORMAT)_i) );

  fprintf(stderr, "\t  --dkm-width <dkm_width>\n");
  fprintf(stderr, "\t      dkm_width: The DKM width. Could be one of\n");

  for ( _i = HMAC_KDF_DKM_WIDTH_FIRST;
        _i < HMAC_KDF_DKM_WIDTH_COUNT; _i++ )
    fprintf(stderr, "\t        %zu\n",
        hmac_kdf_get_dkm_width_value((HMAC_KDF_DKM_WIDTH)_i) );

  fprintf(stderr, "\t  --context <context>\n");
  fprintf(stderr, "\t      context: The input context.\n");
  fprintf(stderr, "\t  --label <label>\n");
  fprintf(stderr, "\t      label: The input label.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\tOptional parameter:\n");
  fprintf(stderr, "\t  --is-token\n");
  fprintf(stderr, "\t      Is the derived key a token key.\n");
  fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
  int c = 0;
  char **argv_copy = NULL;
  size_t argc_copy = (size_t)0;
  size_t i = (size_t)0;
  size_t j = (size_t)0;
  CK_OBJECT_HANDLE _object_id = CK_INVALID_HANDLE;
  size_t _object_val_len = (size_t)0;
  HMAC_KDF_PRF_TYPE _prf_type = HMAC_KDF_PRF_TYPE_NONE;
  HMAC_KDF_KEY_TYPE _key_type = HMAC_KDF_KEY_TYPE_NONE;
  size_t _counter_format_val = (size_t)0;
  HMAC_KDF_COUNTER_FORMAT _counter_format = HMAC_KDF_COUNTER_FORMAT_NONE;
  HMAC_KDF_DKM_METHOD _dkm_method = HMAC_KDF_DKM_METHOD_SUM_OF_KEYS;
  size_t _dkm_width_val = (size_t)0;
  HMAC_KDF_DKM_WIDTH _dkm_width = HMAC_KDF_DKM_WIDTH_NONE;
  const char *_context = NULL;
  size_t _context_len = (size_t)0;
  const char *_label = NULL;
  size_t _label_len = (size_t)0;
  uint8_t _is_token = UINT8_C(0);
  CK_OBJECT_HANDLE _key_out = CK_INVALID_HANDLE;
  CK_RV rv = CKR_OK;
  CK_SESSION_HANDLE session;
  struct pkcs_arguments args = {};

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"object-id", required_argument, 0, 0},
      {"object-val-len", required_argument, 0, 0},
      {"prf-type", required_argument, 0, 0},
      {"key-type", required_argument, 0, 0},
      {"counter-format", required_argument, 0, 0},
      {"dkm-width", required_argument, 0, 0},
      {"context", required_argument, 0, 0},
      {"label", required_argument, 0, 0},
      {"is-token", no_argument, 0, 0},
      {"pin",   required_argument, 0, 0},
      {"library", required_argument, 0, 0},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "", long_options, &option_index);

    if (c == -1)
      break;

    switch ( option_index ) {
      case 0:
        sscanf(optarg, "%lu", &_object_id);
        break;
      case 1:
        sscanf(optarg, "%zu", &_object_val_len);
        break;
      case 2:
        _prf_type = hmac_kdf_get_prf_type_by_name(optarg);
        break;
      case 3:
        _key_type = hmac_kdf_get_key_type_by_name(optarg);
        break;
      case 4:
        sscanf(optarg, "%zu", &_counter_format_val);
        _counter_format = hmac_kdf_get_counter_format_by_value(_counter_format_val);
        break;
      case 5:
        sscanf(optarg, "%zu", &_dkm_width_val);
        _dkm_width = hmac_kdf_get_dkm_width_by_value(_dkm_width_val);
        break;
      case 6:
        _context = optarg;
        _context_len = strlen(_context);
        break;
      case 7:
        _label = optarg;
        _label_len = strlen(_label);
        break;
      case 8:
        _is_token = UINT8_C(1);
        break;
      default:
        break;
    }
  }
  optind = 0;

  argv_copy = (char **)calloc((size_t)argc, sizeof(char *));
  if( NULL == argv_copy ) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    return CKR_HOST_MEMORY;
  }

  for ( i = (size_t)0; i < (size_t)argc; i++ ) {
    if (
            ( 0 == strcmp(argv[i], "--object-id") )
        ||  ( 0 == strcmp(argv[i], "--object-val-len") )
        ||  ( 0 == strcmp(argv[i], "--prf-type") )
        ||  ( 0 == strcmp(argv[i], "--key-type") )
        ||  ( 0 == strcmp(argv[i], "--counter-format") )
        ||  ( 0 == strcmp(argv[i], "--dkm-width") )
        ||  ( 0 == strcmp(argv[i], "--context") )
        ||  ( 0 == strcmp(argv[i], "--label") )
    ) {
      i++;
      continue;
    }
    else if (
            ( 0 == strcmp(argv[i], "--is-token") )
    ) {
      continue;
    }

    argv_copy[j++] = argv[i];
    argc_copy++;
  }

  if ( get_pkcs_args(argc_copy, argv_copy, &args) < 0 ) {
    free(argv_copy);
    show_help();
    return CKR_ARGUMENTS_BAD;
  }

  free(argv_copy);

  rv = pkcs11_initialize(args.library);
  if ( rv != CKR_OK ) {
    fprintf(stderr, "ERROR: Failed to initialize PKCS11: %lu\n", rv);
    goto main_1;
  }

  rv = pkcs11_open_session(args.pin, &session);
  if ( rv != CKR_OK ) {
    fprintf(stderr, "ERROR: Failed to open session: %lu\n", rv);
    goto main_1;
  }

  fprintf( stderr,
      "INFO:  \n"
      "  original key handle = %lu\n"
      "  original key size = %zu bits\n"
      "  prf_type = %s\n"
      "  key_type = %s\n"
      "  counter_format = %02zu\n"
      "  dkm_method = %02zu\n"
      "  dkm_width = %02zu\n"
      "  context = %s (%zu bytes)\n"
      "  label = %s (%zu bytes)\n"
      "  is_token = %hhu\n",
      _object_id,
      _object_val_len * (size_t)8,
      hmac_kdf_get_prf_name_by_type(_prf_type),
      hmac_kdf_get_key_name_by_type(_key_type),
      hmac_kdf_get_counter_format_value(_counter_format),
      hmac_kdf_get_dkm_method_value(_dkm_method),
      hmac_kdf_get_dkm_width_value(_dkm_width),
      (char *)_context ? _context : "",
      _context_len,
      (char *)_label ? _label : "",
      _label_len,
      _is_token );

  rv = hmac_kdf_do(
      session,
      _object_id,
      _object_val_len,
      _prf_type,
      _key_type,
      _context,
      _context_len,
      _label,
      _label_len,
      _counter_format,
      _dkm_method,
      _dkm_width,
      _is_token,
      &_key_out );
  if ( rv != CKR_OK ) {
    fprintf(stderr, "ERROR: Failed to derive key hmac_kdf_do(): %lu\n", rv);
    goto main_1;
  }

  fprintf(stderr, "INFO:  hmac_kdf_do() returned key handle: %lu\n", _key_out);

  main_1:

  return rv;
}
