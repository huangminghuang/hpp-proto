#!/bin/bash -eu

# Configure the build explicitly instead of using presets because the
# OSS-Fuzz base image ships an older CMake that doesn't support our preset version.
cmake -G Ninja -B build -S . \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DHPP_PROTO_PROTOC=find \
  -DHPP_PROTO_TESTS=ON \
  -DHPP_PROTO_BENCHMARKS=OFF

# Build the targets.
cmake --build build

# Copy the fuzzing binaries to the output directory.
cp build/fuzz/fuzz_* $OUT/
