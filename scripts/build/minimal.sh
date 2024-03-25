#!/bin/sh

exec cargo build                \
    --bin      grandine         \
    --features default-networks \
    --features preset-minimal   \
    --profile  compact
