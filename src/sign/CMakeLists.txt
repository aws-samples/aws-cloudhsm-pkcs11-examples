cmake_minimum_required(VERSION 2.8)
project(sign)

find_library(cloudhsmpkcs11 STATIC)

add_executable(sign ec_sign.c rsa_sign.c sign.c common.c sign.h)
add_executable(multi_part_sign ec_sign.c rsa_sign.c multi_part_sign.c common.c sign.h)
target_link_libraries(sign cloudhsmpkcs11)
target_link_libraries(multi_part_sign cloudhsmpkcs11)

add_test(sign sign --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(multi_part_sign multi_part_sign --pin ${HSM_USER}:${HSM_PASSWORD})
