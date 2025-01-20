cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

add_executable(tdes_generate tdes_generate.c)

target_link_libraries(tdes_generate cloudhsmpkcs11)

# We do not add this file for testing as the tests currently assume
# of a FIPS-mode CloudHSM cluster.

# add_test(tdes_generate tdes_generate --pin ${HSM_USER}:${HSM_PASSWORD})
