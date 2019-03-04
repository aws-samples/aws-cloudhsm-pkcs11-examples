cmake_minimum_required(VERSION 2.8)
project(attributes)

find_library(cloudhsmpkcs11 STATIC)

add_library(attributes attributes.c attributes.h)

add_executable(attributes_cmd attributes_cmd.c)
target_link_libraries(attributes_cmd cloudhsmpkcs11 attributes)
