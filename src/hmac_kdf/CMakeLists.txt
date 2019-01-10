cmake_minimum_required(VERSION 2.8)
project(hmac_kdf)

find_library(cloudhsmpkcs11 STATIC)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../common")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_library(hmac_kdf hmac_kdf.c hmac_kdf.h)

add_executable(hmac_kdf_cmd hmac_kdf_cmd.c)
target_link_libraries(hmac_kdf_cmd cloudhsmpkcs11 hmac_kdf)
