cmake_minimum_required(VERSION 2.8)
project(find_objects)

find_library(cloudhsmpkcs11 STATIC)

add_executable(find_objects find_objects.c)
target_link_libraries(find_objects cloudhsmpkcs11)

add_test(find_objects find_objects --pin ${HSM_USER}:${HSM_PASSWORD})
