cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

add_executable(ecdh ecdh.c)

target_link_libraries(ecdh cloudhsmpkcs11)

# We do not add this file for testing as the tests currently assume
# of a FIPS-mode CloudHSM cluster.

# add_test(ecdh ecdh --pin ${HSM_USER}:${HSM_PASSWORD})
