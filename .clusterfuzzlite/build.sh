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

# Ensure the descriptor is available next to the fuzzers at runtime.
# It is generated into the build tree by tests and copied into build/fuzz.
cp build/fuzz/unittest.desc.binpb $OUT/../unittest.desc.binpb
mkdir -p $OUT/../cifuzz-corpus/fuzz_json
mkdir -p $OUT/../cifuzz-corpus/fuzz_binpb
cp build/fuzz/json_seed_corpus/* $OUT/../cifuzz-corpus/fuzz_json
cp build/fuzz/binpb_seed_corpus/* $OUT/../cifuzz-corpus/fuzz_binpb