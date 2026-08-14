cmake_minimum_required(VERSION 2.8)
project(sign)

find_library(cloudhsmpkcs11 STATIC)

add_executable(eddsa_sign eddsa_sign.c)

target_link_libraries(eddsa_sign cloudhsmpkcs11)

# We do not add this file for testing as the tests currently assume
# a FIPS-mode CloudHSM cluster.

# add_test(eddsa_sign eddsa_sign --pin ${HSM_USER}:${HSM_PASSWORD})
