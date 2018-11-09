cmake_minimum_required(VERSION 2.8)
project(cloudhsmexamples)

SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -std=c99")

add_subdirectory(common)
add_subdirectory(digest)
add_subdirectory(generate)
add_subdirectory(sign)
add_subdirectory(encrypt)
add_subdirectory(wrapping)
add_subdirectory(hsm_info)