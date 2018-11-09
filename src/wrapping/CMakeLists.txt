cmake_minimum_required(VERSION 2.8)
project(wrapping)

find_library(cloudhsmpkcs11 STATIC)

include_directories("../common")

add_executable(wrapping wrapping.c)
target_link_libraries(wrapping cloudhsmpkcs11 ssl crypto)
