#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p json_corpus
./fuzz_json json_corpus json_seed_corpus -dict=fuzz_json.dict -rss_limit_mb=4096 -timeout=3600 -runs=10000000
### For debugging use the following command
###   fuzz_json --minimize-crash crash-xxxxxxxx