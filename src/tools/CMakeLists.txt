cmake_minimum_required(VERSION 2.8)
project(tools)

find_library(cloudhsmpkcs11 STATIC)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(import_pub_key import_pub_key.c io.c)
target_link_libraries(import_pub_key cloudhsmpkcs11 ssl crypto)
