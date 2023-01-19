cmake_minimum_required(VERSION 2.8)
project(session)

find_library(cloudhsmpkcs11 STATIC)

add_executable(login_state login_state.c)
add_executable(session_keys session_keys.c)
target_link_libraries(login_state cloudhsmpkcs11)
target_link_libraries(session_keys cloudhsmpkcs11)

add_test(login_state login_state --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(session_keys login_state --pin ${HSM_USER}:${HSM_PASSWORD})
