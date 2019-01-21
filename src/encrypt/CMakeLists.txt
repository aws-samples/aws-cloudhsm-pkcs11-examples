cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(cloudhsmpkcs11 STATIC)

include_directories("../common")
include_directories("../pkcs11_headers")

add_executable(encrypt encrypt.c ecb.c cbc.c gcm.c)
target_link_libraries(encrypt cloudhsmpkcs11)
