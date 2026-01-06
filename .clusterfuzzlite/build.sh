#!/bin/bash -eu

BUILD_DIR=${BUILD_DIR:-build}

export CCACHE_DIR=$(pwd)/.ccache

if ! command -v ccache &> /dev/null; then
    echo "ccache not found. Installing..."
    apt-get update && apt-get install -y ccache
fi

echo "CCACHE Config:"
ccache -p
echo "CCACHE Stats (Before):"
ccache -s

# Configure the build explicitly instead of using presets because the
# OSS-Fuzz base image ships an older CMake that doesn't support our preset version.
cmake -G Ninja -B "$BUILD_DIR" -S . \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DHPP_PROTO_PROTOC=find \
  -DHPP_PROTO_BENCHMARKS=OFF \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DHPP_PROTO_FUZZER_ONLY=ON

# Build the targets.
cmake --build "$BUILD_DIR"

echo "CCACHE Stats (After):"
ccache -s

# Copy the fuzzing binaries to the output directory.
cp "$BUILD_DIR"/fuzz/fuzz_binpb $OUT/
cp "$BUILD_DIR"/fuzz/fuzz_json $OUT/


# Ensure the descriptor is available next to the fuzzers at runtime.
# It is generated into the build tree by tests and copied into build/fuzz.
cp "$BUILD_DIR"/fuzz/unittest.desc.binpb $OUT/../unittest.desc.binpb

zip -j $OUT/fuzz_binpb_seed_corpus.zip "$BUILD_DIR"/fuzz/binpb_seed_corpus/*
zip -j $OUT/fuzz_json_seed_corpus.zip "$BUILD_DIR"/fuzz/json_seed_corpus/*
