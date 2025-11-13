#!/bin/sh

cross build \
    --bin grandine \
    --target x86_64-unknown-linux-gnu \
    --features default-networks \
    --features tracing          \
    --profile compact           \
    --workspace                 \
    --exclude zkvm_host         \
    --exclude zkvm_guest_risc0

docker buildx build \
    --file Dockerfile.cross \
    --platform linux/amd64 \
    --push \
    --tag sifrai/grandine:latest-amd64 \
    ./target/x86_64-unknown-linux-gnu/compact/

cross build \
    --bin grandine \
    --target aarch64-unknown-linux-gnu \
    --features default-networks \
    --features tracing          \
    --profile compact           \
    --workspace                 \
    --exclude zkvm_host         \
    --exclude zkvm_guest_risc0

docker buildx build \
    --file Dockerfile.cross \
    --platform linux/arm64 \
    --push \
    --tag sifrai/grandine:latest-arm64 \
    ./target/aarch64-unknown-linux-gnu/compact/

docker manifest rm sifrai/grandine:latest
docker manifest create sifrai/grandine:latest \
    --amend sifrai/grandine:latest-amd64 \
    --amend sifrai/grandine:latest-arm64

docker manifest push sifrai/grandine:latest
