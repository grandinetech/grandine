# Grandine's toolchain (`rust-toolchain.toml`).
FROM rust:1.100.0-bookworm AS builder
RUN apt-get update && apt-get --yes upgrade && apt-get install --yes cmake libclang-dev
COPY . .
RUN scripts/build/release.sh

FROM ubuntu:latest
# The root certificates that HTTPS downloads such as checkpoint sync verify servers with.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && apt-get clean
COPY --from=builder /target/compact/grandine /usr/local/bin/grandine

ENTRYPOINT ["grandine"]
