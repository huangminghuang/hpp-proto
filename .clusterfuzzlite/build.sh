#!/bin/bash -eu

cmake -GNinja -DCMAKE_BUILD_TYPE=Release -Bbuild -S .
cmake --build build --config Release
cp build/fuzz/fuzz_* $OUT/
 
