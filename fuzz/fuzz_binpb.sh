#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p binpb_corpus
./fuzz_binpb binpb_corpus binpb_seed_corpus -dict=fuzz_binpb.dict -rss_limit_mb=4096 -timeout=3600 -runs=10000000
### For debugging use the following command
###   fuzz_binpb --minimize-crash crash-xxxxxxxx