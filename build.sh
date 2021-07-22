#!/bin/bash

# Clear down and re-create output directories
rm -rf build
mkdir build
mkdir build/darwin
mkdir build/linux

# Copy header file
cp src/processor/bugsnag_stackwalk_wrapper.h build

# Generate the SO file locally (darwin)
./generate-so.sh

# Generate the SO file in docker (linux)
docker build -t breakpad-builder .
docker run -v `pwd`/build/linux:/breakpad/build/linux breakpad-builder
