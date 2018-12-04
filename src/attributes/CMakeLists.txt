cmake_minimum_required(VERSION 2.8)
project(attributes)

find_library(cloudhsmpkcs11 STATIC)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../common")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_library(attributes attributes.c attributes.h)

add_executable(attributes_cmd attributes_cmd.c)
target_link_libraries(attributes_cmd cloudhsmpkcs11 attributes)
