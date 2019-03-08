cmake_minimum_required(VERSION 2.8)
project(destroy)

find_library(cloudhsmpkcs11 STATIC)

add_library(destroy destroy.c destroy.h)

add_executable(destroy_cmd destroy_cmd.c)
target_link_libraries(destroy_cmd cloudhsmpkcs11 destroy)
