#!/bin/sh

# Verify all examples build
mkdir -p build
cd build
cmake ..
make
