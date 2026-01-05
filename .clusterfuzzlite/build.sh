#!/bin/bash -eu

# Configure the build explicitly instead of using presets because the
# OSS-Fuzz base image ships an older CMake that doesn't support our preset version.
cmake -G Ninja -B build -S . \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DHPP_PROTO_PROTOC=find \
  -DHPP_PROTO_BENCHMARKS=OFF \
  -DHPP_PROTO_FUZZER_ONLY=ON

# Build the targets.
cmake --build build

# Copy the fuzzing binaries to the output directory.
cp build/fuzz/fuzz_* $OUT/

# Ensure the descriptor is available next to the fuzzers at runtime.
# It is generated into the build tree by tests and copied into build/fuzz.
cp build/fuzz/unittest.desc.binpb $OUT/../unittest.desc.binpb

zip -j $OUT/fuzz_binpb_seed_corpus.zip build/fuzz/binpb_seed_corpus/*
zip -j $OUT/fuzz_json_seed_corpus.zip build/fuzz/json_seed_corpus/*
