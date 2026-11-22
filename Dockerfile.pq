# Grandine for PQ networks, with the leanVM sidecar they need:
#   docker build -f Dockerfile.pq -t grandine:pq .
# `grandine-pq` starts the sidecar and then Grandine on its socket.

# Grandine's toolchain (`rust-toolchain.toml`).
FROM rust:1.100.0-bookworm AS builder
RUN apt-get update && apt-get --yes upgrade && apt-get install --yes cmake libclang-dev
COPY . .
RUN scripts/build/release.sh

# The leanVM sidecar of PQ networks, from the leanVM revision Grandine is pinned to: proofs of
# another revision do not verify. `grandine-pq` starts it and then Grandine.
# leanVM uses edition 2024 and pins no toolchain; this is Grandine's (`rust-toolchain.toml`).
FROM rust:1.100.0-bookworm AS sidecar
COPY Cargo.toml /grandine/Cargo.toml
RUN rev=$(sed -n "s/^lean_xmss = .*rev = '\([0-9a-f]*\)'.*/\1/p" /grandine/Cargo.toml) \
  && test -n "$rev" \
  && if [ "$(uname -m)" = x86_64 ]; then \
  export RUSTFLAGS='-C target-feature=+sse3,+ssse3,+pclmulqdq'; \
  fi \
  && cargo install leanvm-sidecar --locked --git https://github.com/leanEthereum/leanVM \
  --rev "$rev" --features experimental_prover

FROM ubuntu:latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl-dev && apt-get clean
COPY --from=builder /target/compact/grandine /usr/local/bin/grandine
COPY --from=sidecar /usr/local/cargo/bin/leanvm-sidecar /usr/local/bin/leanvm-sidecar
COPY --chmod=755 scripts/pq/grandine-pq /usr/local/bin/grandine-pq

ENTRYPOINT ["grandine-pq"]
