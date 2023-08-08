cmake_minimum_required(VERSION 2.8)
project(derivation)

find_library(cloudhsmpkcs11 STATIC)

add_executable(ecdh ecdh.c)
add_executable(hmac_kdf hmac_kdf.c)
add_executable(aes_cmac_kdf aes_cmac_kdf.c)

target_link_libraries(ecdh cloudhsmpkcs11)
target_link_libraries(hmac_kdf cloudhsmpkcs11)
target_link_libraries(aes_cmac_kdf cloudhsmpkcs11)

add_test(ecdh ecdh --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(hmac_kdf hmac_kdf --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(aes_cmac_kdf aes_cmac_kdf --pin ${HSM_USER}:${HSM_PASSWORD})
