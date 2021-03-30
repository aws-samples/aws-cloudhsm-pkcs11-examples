cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

add_executable(aes_generate aes_generate.c)
add_executable(rsa_generate rsa_generate.c)
add_executable(ec_generate ec_generate.c)
target_link_libraries(aes_generate cloudhsmpkcs11)
target_link_libraries(rsa_generate cloudhsmpkcs11)
target_link_libraries(ec_generate cloudhsmpkcs11)
add_test(aes_generate aes_generate --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(rsa_generate rsa_generate --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(ec_generate ec_generate --pin ${HSM_USER}:${HSM_PASSWORD})
