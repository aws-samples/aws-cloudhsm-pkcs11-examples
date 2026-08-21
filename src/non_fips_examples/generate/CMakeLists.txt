cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

add_executable(tdes_generate tdes_generate.c)
add_executable(ed25519_generate ed25519_generate.c)

target_link_libraries(tdes_generate cloudhsmpkcs11)
target_link_libraries(ed25519_generate cloudhsmpkcs11)

# We do not add these files for testing as the tests currently assume
# a FIPS-mode CloudHSM cluster.

# add_test(tdes_generate tdes_generate --pin ${HSM_USER}:${HSM_PASSWORD})
# add_test(ed25519_generate ed25519_generate --pin ${HSM_USER}:${HSM_PASSWORD})
