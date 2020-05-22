cmake_minimum_required(VERSION 2.8)
project(aws-cloudhsm-pkcs11-examples)

SET(ORGANIZATION_NAME "Amazon.com, Inc.")
SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -std=c99")

ENABLE_TESTING()

include_directories(include/pkcs11/v2.40)
include_directories(src/common)

add_subdirectory(src/common)
add_subdirectory(src/digest)
add_subdirectory(src/generate)
add_subdirectory(src/sign)
add_subdirectory(src/encrypt)
add_subdirectory(src/wrapping)
add_subdirectory(src/hsm_info)
add_subdirectory(src/attributes)
add_subdirectory(src/destroy)
add_subdirectory(src/tools)
add_subdirectory(src/find_objects)
add_subdirectory(src/derivation)
