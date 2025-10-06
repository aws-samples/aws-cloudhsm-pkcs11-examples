cmake_minimum_required(VERSION 2.8)
project(certificate_storage)

find_library(cloudhsmpkcs11 STATIC)

find_package(OpenSSL REQUIRED)

add_executable(certificate_storage certificate_storage.c)

target_include_directories(certificate_storage PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(certificate_storage cloudhsmpkcs11 ${OPENSSL_LIBRARIES})
