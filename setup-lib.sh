#!/bin/bash

# Check if lib directory exists, if not create it
if [ ! -d "lib" ]; then
    mkdir lib
fi

# Check if base image exists
echo "Checking for zig_builder image..."
if ! docker images zig_builder --quiet; then
    echo "Warning: zig_builder base image not found"
    exit 1
fi

# Build uBPF image
echo -e "\nBuilding uBPF Docker image..."
docker build -f zig-external-libs/ubpf.dockerfile -t ubpf-builder .

# Extract library from container
echo -e "\nExtracting libubpf.so from container..."
docker create --name ubpf-temp ubpf-builder
docker cp ubpf-temp:/opt/ubpf/lib/libubpf.so ./lib/
docker rm ubpf-temp

# Verify the extracted library
echo -e "\nVerifying extracted library..."
if [ ! -f "lib/libubpf.so" ]; then
    echo "Error: libubpf.so not found in lib directory"
    exit 1
fi

echo -e "\nChecking library permissions..."
ls -l lib/libubpf.so

echo -e "\nChecking libubpf.so symbols..."
nm -D lib/libubpf.so | grep "ubpf_"

echo -e "\nChecking library dependencies..."
ldd lib/libubpf.so

echo -e "\nChecking if library is position independent..."
readelf -h lib/libubpf.so | grep "Type.*DYN"

echo -e "\nVerifying library can be loaded..."
zig run src/main.zig -lc -L ./lib -lubpf -rpath \$ORIGIN/lib

echo -e "\nLibrary verification complete!"