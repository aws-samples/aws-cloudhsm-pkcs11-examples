cmake_minimum_required(VERSION 2.8)
project(generate_random)

find_library(cloudhsmpkcs11 STATIC)

add_executable(generate_random generate_random.c)
target_link_libraries(generate_random cloudhsmpkcs11)
add_test(generate_random generate_random --pin ${HSM_USER}:${HSM_PASSWORD})
