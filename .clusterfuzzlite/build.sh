#!/bin/bash -eu

# Configure the build using the 'fuzz' preset, which contains all
# necessary flags for an optimized, sanitized build with asserts enabled.
cmake --preset fuzz -B build -S .

# Build the targets.
cmake --build build

# Copy the fuzzing binaries to the output directory.
cp build/fuzz/fuzz_* $OUT/
