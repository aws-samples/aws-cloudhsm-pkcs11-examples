cmake_minimum_required(VERSION 2.8)
project(generate)

find_library(cloudhsmpkcs11 STATIC)

include_directories("../common")

add_executable(generate generate.c ${COMMON_SOURCE})
target_link_libraries(generate cloudhsmpkcs11)
