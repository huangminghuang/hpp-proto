#!/bin/bash

./fuzz_descriptor descriptor_corpus descriptor_seed_corpus -dict=fuzz_descriptor.dict -rss_limit_mb=4096 -timeout=3600 -runs=100000000

### Minimize a crash with:
###   fuzz_descriptor --minimize-crash crash-xxxxxxxx
