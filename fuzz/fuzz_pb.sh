#!/usr/bin/env bash
cd "$(dirname "$0")"
mkdir -p pb_corpus
./fuzz_pb pb_corpus pb_seed_corpus -dict=fuzz_pb.dict -rss_limit_mb=4096 -timeout=3600 -runs=10000000
