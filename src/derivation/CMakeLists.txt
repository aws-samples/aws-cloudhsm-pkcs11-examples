cmake_minimum_required(VERSION 2.8)
project(derivation)

find_library(cloudhsmpkcs11 STATIC)

add_executable(derivation derivation.c)
target_link_libraries(derivation cloudhsmpkcs11)
