#!/bin/sh

exec cargo build                \
    --bin      grandine         \
    --features default-networks \
    --features preset-minimal   \
    --features tracing          \
    --profile  compact          \
    --workspace                 \
    --exclude zkvm_host         \
    --exclude zkvm_guest_risc0
