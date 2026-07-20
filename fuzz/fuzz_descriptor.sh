#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p descriptor_corpus
./fuzz_descriptor descriptor_corpus descriptor_seed_corpus -dict=fuzz_descriptor.dict -rss_limit_mb=4096 -timeout=3600 -runs=100000000
### For debugging use the following command
###   fuzz_descriptor --minimize-crash crash-xxxxxxxx
