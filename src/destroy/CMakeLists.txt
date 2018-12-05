cmake_minimum_required(VERSION 2.8)
project(destroy)

find_library(cloudhsmpkcs11 STATIC)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../common")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_library(destroy destroy.c destroy.h)

add_executable(destroy_cmd destroy_cmd.c)
target_link_libraries(destroy_cmd cloudhsmpkcs11 destroy)
