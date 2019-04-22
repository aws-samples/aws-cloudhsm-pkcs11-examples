cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

add_executable(generate generate.c)
target_link_libraries(generate cloudhsmpkcs11)
add_test(generate generate --pin ${HSM_USER}:${HSM_PASSWORD})
