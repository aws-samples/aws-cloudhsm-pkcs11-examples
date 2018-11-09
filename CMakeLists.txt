cmake_minimum_required(VERSION 2.8)

SET(ORGANIZATION_NAME "Amazon.com, Inc.")

project(aws-cloudhsm-pkcs11-examples)

# Version 1.0
SET(PROJECT_VERSION_MAJOR 1)
SET(PROJECT_VERSION_MINOR 0)
SET(PROJECT_VERSION_PATCH 0)

include_directories(include/pkcs11/v2.40)

add_subdirectory(c)
