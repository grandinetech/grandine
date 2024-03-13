#!/bin/sh

exec cargo build                \
    --bin      grandine         \
    --features default-networks \
    --profile  compact
