cmake_minimum_required(VERSION 2.8)
project(cloudhsmpkcs11)

add_library(cloudhsmpkcs11 common.c pkcs11.c common.h)
target_link_libraries(cloudhsmpkcs11 dl)
