cmake_minimum_required(VERSION 2.8)
project(hmac_kdf)

find_library(cloudhsmpkcs11 STATIC)

add_executable(hmac_kdf hmac_kdf.c)

target_link_libraries(hmac_kdf cloudhsmpkcs11)

add_test(hmac_kdf hmac_kdf --pin ${HSM_USER}:${HSM_PASSWORD})
