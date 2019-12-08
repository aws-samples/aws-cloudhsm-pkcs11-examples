cmake_minimum_required(VERSION 2.8)
project(wrapping)

find_library(cloudhsmpkcs11 STATIC)

add_executable(wrapping aes_wrapping_common.c aes_wrapping.c aes_gcm_wrapping.c rsa_wrapping.c wrap.c wrap.h)
target_link_libraries(wrapping cloudhsmpkcs11 ssl crypto)
add_executable(wrap_with_template wrap_with_template.c)
target_link_libraries(wrap_with_template cloudhsmpkcs11 ssl crypto)
add_executable(unwrap_with_template unwrap_with_template.c)
target_link_libraries(unwrap_with_template cloudhsmpkcs11 ssl crypto)

add_test(wrapping wrapping --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(wrap_with_template wrap_with_template --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(unwrap_with_template unwrap_with_template --pin ${HSM_USER}:${HSM_PASSWORD} --wp_key ${TRUSTED_WRAPPING_KEY_HANDLE})