cmake_minimum_required(VERSION 2.8)
project(derivation)

find_library(cloudhsmpkcs11 STATIC)

add_executable(ecdh ecdh.c)
add_executable(counter_kdf counter_kdf.c)

target_link_libraries(ecdh cloudhsmpkcs11)
target_link_libraries(counter_kdf cloudhsmpkcs11)

add_test(ecdh ecdh --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(counter_kdf counter_kdf --pin ${HSM_USER}:${HSM_PASSWORD})
