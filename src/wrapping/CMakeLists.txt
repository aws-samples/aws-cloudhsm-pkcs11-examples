cmake_minimum_required(VERSION 2.8)
project(wrapping)

find_library(cloudhsmpkcs11 STATIC)

add_executable(wrapping aes_wrapping.c rsa_wrapping.c wrap.c wrap.h)
target_link_libraries(wrapping cloudhsmpkcs11 ssl crypto)
