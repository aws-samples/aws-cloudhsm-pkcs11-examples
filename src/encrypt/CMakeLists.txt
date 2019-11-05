cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(cloudhsmpkcs11 STATIC)

add_executable(aes_cbc aes_cbc.c aes.c)
add_executable(aes_ecb aes_ecb.c aes.c)
add_executable(aes_gcm aes_gcm.c aes.c)
add_executable(aes_ctr aes_ctr.c aes.c)
add_executable(des_ecb des_ecb.c)

target_link_libraries(aes_cbc cloudhsmpkcs11)
target_link_libraries(aes_ecb cloudhsmpkcs11)
target_link_libraries(aes_gcm cloudhsmpkcs11)
target_link_libraries(aes_ctr cloudhsmpkcs11)
target_link_libraries(des_ecb cloudhsmpkcs11)

add_test(aes_cbc aes_cbc --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(aes_ecb aes_ecb --pin ${HSM_USER}:${HSM_PASSWORD}) 
add_test(aes_gcm aes_gcm --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(aes_ctr aes_ctr --pin ${HSM_USER}:${HSM_PASSWORD})
add_test(des_ecb des_ecb --pin ${HSM_USER}:${HSM_PASSWORD}) 
