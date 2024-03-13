#!/bin/sh

set -o errexit

# Tarpaulin must be run either in the root of a crate or with an explicit `--manifest-path`.
# The former produces a cleaner output file.
cd "$(dirname "$0")"/../..

exec cargo tarpaulin                       \
    --exclude-files lighthouse             \
    --exclude-files lighthouse-quick-start \
    --ignore-tests                         \
    --out Xml                              \
    --timeout 240                          \
    --verbose
