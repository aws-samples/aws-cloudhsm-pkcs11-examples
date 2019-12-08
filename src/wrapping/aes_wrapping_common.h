#ifndef _AES_WRAPPING_COMMON_H_
#define _AES_WRAPPING_COMMON_H_

CK_RV generate_wrapping_key(CK_SESSION_HANDLE session,
                            CK_ULONG key_length_bytes,
                            CK_OBJECT_HANDLE_PTR key);

CK_RV generate_rsa_keypair(CK_SESSION_HANDLE session,
                           CK_ULONG key_length_bits,
                           CK_OBJECT_HANDLE_PTR public_key,
                           CK_OBJECT_HANDLE_PTR private_key);

#endif  /* _AES_WRAPPING_COMMON_H_ */