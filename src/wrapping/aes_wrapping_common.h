#ifndef _AES_WRAPPING_COMMON_H_
#define _AES_WRAPPING_COMMON_H_

CK_RV generate_aes_token_key_for_wrapping(CK_SESSION_HANDLE session,
                                          CK_ULONG key_length_bytes,
                                          CK_OBJECT_HANDLE_PTR key);

CK_RV generate_aes_session_key(CK_SESSION_HANDLE session,
                               CK_ULONG key_length_bytes,
                               CK_OBJECT_HANDLE_PTR key);

CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key);

CK_RV aes_wrap_key(CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mech,
                   CK_OBJECT_HANDLE wrapping_key,
                   CK_OBJECT_HANDLE key_to_wrap,
                   CK_BYTE_PTR wrapped_bytes,
                   CK_ULONG_PTR wrapped_bytes_len);

CK_RV aes_unwrap_key(CK_SESSION_HANDLE session,
                     CK_MECHANISM_PTR mech,
                     CK_OBJECT_HANDLE wrapping_key,
                     CK_KEY_TYPE wrapped_key_type,
                     CK_BYTE_PTR wrapped_bytes,
                     CK_ULONG wrapped_bytes_len,
                     CK_OBJECT_HANDLE_PTR unwrapped_key_handle);

#endif  /* _AES_WRAPPING_COMMON_H_ */
