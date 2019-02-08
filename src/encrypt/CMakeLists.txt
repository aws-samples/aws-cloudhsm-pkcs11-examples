cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(cloudhsmpkcs11 STATIC)

include_directories("../common")
include_directories("../pkcs11_headers")

add_executable(aes_cbc aes_cbc.c aes.c)
add_executable(aes_ecb aes_ecb.c aes.c)
add_executable(aes_gcm aes_gcm.c aes.c)

target_link_libraries(aes_cbc cloudhsmpkcs11)
target_link_libraries(aes_ecb cloudhsmpkcs11)
target_link_libraries(aes_gcm cloudhsmpkcs11)