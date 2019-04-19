cmake_minimum_required(VERSION 2.8)
project(digest)

find_library(cloudhsmpkcs11 STATIC)

add_executable(digest digest.c)
target_link_libraries(digest cloudhsmpkcs11)

add_test(digest digest --pin ${HSM_USER}:${HSM_PASSWORD})
