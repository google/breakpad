#!/bin/bash

# Determine machine type
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=linux;;
    Darwin*)    machine=darwin;;
    *)          machine="unknown"
esac

# Create a temp diretory to build within
rm -rf tmp
mkdir tmp
cd tmp

# Generate the shared object file
../configure
make 'src/processor/libbugsnag_stackwalk_wrapper.a'
g++ -shared -o ../build/${machine}/libbugsnag_stackwalk_wrapper.so `find . -iname "*.o"`

# Cleanup the temp directory
rm -rf tmp
