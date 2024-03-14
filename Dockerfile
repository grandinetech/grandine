FROM rust:1.76.0-bullseye AS builder
RUN apt-get update && apt-get --yes upgrade && apt-get install --yes cmake libclang-dev
COPY . .
RUN scripts/build/release.sh

FROM ubuntu:latest
COPY --from=builder /target/compact/grandine /usr/local/bin/grandine

ENTRYPOINT ["/usr/local/bin/grandine"]
