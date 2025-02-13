#!/bin/bash -eu

cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DHPP_PROTO_BUILD_FUZZ=ON -Bbuild -S .
cmake --build build --config Release
cp build/fuzz/fuzz_* $OUT/
 
