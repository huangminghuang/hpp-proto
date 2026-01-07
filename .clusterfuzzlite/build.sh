#!/bin/bash -eu

BUILD_DIR=${BUILD_DIR:-build}
echo "SANITIZER=${SANITIZER}"

FUZZ_COMPILE_OPTIONS="-fsanitize=fuzzer,address;-fno-sanitize-recover=all"
FUZZ_LINK_OPTIONS="-fsanitize=fuzzer,address"


# # Common safety flags for all builds
# UBSAN_OPTIONS="-fsanitize=undefined -fno-sanitize=unsigned-integer-overflow -fno-sanitize-recover=all"

# if [ "${SANITIZER:-}" = "coverage" ]; then
#   BUILD_TYPE="Debug"
#   # For coverage, we use fuzzer-no-link to instrument without linking the engine.
#   # We also include UBSan.
#   # Note: 'coverage' sanitizer usually implies source-based coverage flags handled by the compiler wrapper,
#   # but we explicitly add fuzzer-no-link here as per previous setup.
#   FUZZ_COMPILE_OPTIONS="${UBSAN_OPTIONS} -fsanitize=fuzzer-no-link"
#   FUZZ_LINK_OPTIONS="-fsanitize=undefined -fsanitize=fuzzer-no-link"
# else
#   BUILD_TYPE="RelWithDebInfo"
#   # Default to address sanitizer if not specified
#   SAN="${SANITIZER:-address}"
  
#   # For fuzzing, we need the sanitizer (e.g. address) AND fuzzer instrumentation.
#   FUZZ_COMPILE_OPTIONS="${UBSAN_OPTIONS} -fsanitize=${SAN},fuzzer"
#   FUZZ_LINK_OPTIONS="-fsanitize=undefined,${SAN},fuzzer"
# fi

WORKSPACE_DIR=$OUT/..
export CCACHE_DIR="${WORKSPACE_DIR}"/.ccache
export CCACHE_BASEDIR="$PWD"

echo "Current working directory: $PWD"
echo "Using CCACHE_DIR: $CCACHE_DIR"
mkdir -p "$CCACHE_DIR"
ls -ld "$CCACHE_DIR"

if ! command -v ccache &> /dev/null; then
    echo "ccache not found. Installing..."
    apt-get update && apt-get install -y ccache
fi

# Configure the build explicitly instead of using presets because the
# OSS-Fuzz base image ships an older CMake that doesn't support our preset version.
cmake -G Ninja -B "$BUILD_DIR" -S . \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DHPP_PROTO_FUZZ_COMPILE_OPTIONS="$FUZZ_COMPILE_OPTIONS" \
  -DHPP_PROTO_FUZZ_LINK_OPTIONS="$FUZZ_LINK_OPTIONS" \
  -DHPP_PROTO_PROTOC=find \
  -DHPP_PROTO_BENCHMARKS=OFF \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DHPP_PROTO_FUZZER_ONLY=ON

# Build the targets.
cmake --build "$BUILD_DIR"

# Copy the fuzzing binaries to the output directory.
cp "$BUILD_DIR"/fuzz/fuzz_binpb $OUT/
cp "$BUILD_DIR"/fuzz/fuzz_json $OUT/


# Ensure the descriptor is available next to the fuzzers at runtime.
# It is generated into the build tree by tests and copied into build/fuzz.
cp "$BUILD_DIR"/fuzz/unittest.desc.binpb "${WORKSPACE_DIR}"/unittest.desc.binpb

zip -j $OUT/fuzz_binpb_seed_corpus.zip "$BUILD_DIR"/fuzz/binpb_seed_corpus/*
zip -j $OUT/fuzz_json_seed_corpus.zip "$BUILD_DIR"/fuzz/json_seed_corpus/*
