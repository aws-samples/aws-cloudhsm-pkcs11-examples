cmake_minimum_required(VERSION 2.8)
project(attributes)

include_directories("../common")

add_library(attributes attributes.c attributes.h)
