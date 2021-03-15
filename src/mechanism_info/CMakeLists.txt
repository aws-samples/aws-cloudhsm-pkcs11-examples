cmake_minimum_required(VERSION 2.8)
project(mechanism_info)

find_library(cloudhsmpkcs11 STATIC)

add_executable(mechanism_info mechanism_info.c mechanism_info.h)
target_link_libraries(mechanism_info cloudhsmpkcs11)

add_test(mechanism_info mechanism_info --pin ${HSM_USER}:${HSM_PASSWORD})
