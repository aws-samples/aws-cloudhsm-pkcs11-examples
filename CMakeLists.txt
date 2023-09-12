cmake_minimum_required(VERSION 2.8)
project(aws-cloudhsm-pkcs11-examples)

SET(ORGANIZATION_NAME "Amazon.com, Inc.")
IF (MSVC)
  SET(CMAKE_C_FLAGS "/W3 /WX /J /std:c11 /Wv:18")
ELSE()
  SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -std=c99")
ENDIF()

# If the file does not exist, a wrong path is provided, or the file does not
# have the expected definitions, the make will fail when the user provides
# CLOUDHSM_PKCS11_VENDOR_DEFS_PATH as -D option to cmake.

IF (NOT DEFINED CLOUDHSM_PKCS11_VENDOR_DEFS_PATH)
  # The path to the custom pkcs11 header file contained in CLOUDHSM_PKCS11_VENDOR_DEFS_PATH is passed
  # to the compiler which is used with -I option by the compiler and adds the directories to the
  # search path.
  IF (WIN32)
    SET(CLOUDHSM_PKCS11_VENDOR_DEFS_PATH "C:\\Program Files\\Amazon\\CloudHSM\\include\\pkcs11")
  ELSE()
    SET(CLOUDHSM_PKCS11_VENDOR_DEFS_PATH /opt/cloudhsm/include/pkcs11)
  ENDIF()
ENDIF()
include_directories(${CLOUDHSM_PKCS11_VENDOR_DEFS_PATH})

ENABLE_TESTING()

include_directories(include/pkcs11/v2.40)
include_directories(include/gopt)
include_directories(src/common)

add_subdirectory(src/common)
add_subdirectory(src/digest)
add_subdirectory(src/generate)
add_subdirectory(src/sign)
add_subdirectory(src/encrypt)
add_subdirectory(src/wrapping)
add_subdirectory(src/mechanism_info)
add_subdirectory(src/attributes)
add_subdirectory(src/destroy)
add_subdirectory(src/find_objects)
add_subdirectory(src/derivation)
add_subdirectory(src/generate_random)
add_subdirectory(src/session)

IF(LINUX)
  add_subdirectory(src/tools)
ENDIF()