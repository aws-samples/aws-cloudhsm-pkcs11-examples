cmake_minimum_required(VERSION 2.8)
project(sign)

find_library(cloudhsmpkcs11 STATIC)

add_executable(sign ec_sign.c rsa_sign.c sign.c common.c sign.h)
target_link_libraries(sign cloudhsmpkcs11)

add_test(sign sign --pin ${HSM_USER}:${HSM_PASSWORD})
