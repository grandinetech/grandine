#!/usr/bin/env bash
# Targeted checks only. Does not download or alter upstream test vectors.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/grandine-target}"
mode="${1:-new}"
case "$mode" in
  quick)
    bash "${BASH_SOURCE[0]}" new
    bash "${BASH_SOURCE[0]}" vectors
    ;;
  new)
    cargo test --locked --release \
      -p transition_functions -p bls -p kzg_utils \
      --features transition_functions/eip8321,bls/blst,kzg_utils/blst \
      --lib hash_chain_randao -- --nocapture
    ;;
  vectors)
    vector_dir="${EIP8321_VECTORS_DIR:-$PWD/test-vectors/eip8321}"
    if [[ -z "${EIP8321_VECTORS_DIR:-}" && ! -d "$vector_dir" ]]; then
      archive="$PWD/test-vectors/eip8321.tar.xz"
      if [[ ! -f "$archive" ]]; then
        echo 'Missing bundled test-vectors/eip8321.tar.xz archive.' >&2
        exit 2
      fi
      (cd test-vectors && sha256sum --check --status eip8321.sha256)
      staging="$(mktemp -d "$PWD/test-vectors/.eip8321-extract.XXXXXX")"
      echo 'Extracting bundled EIP-8321 reference vectors...'
      tar -xJf "$archive" -C "$staging"
      mv -T -- "$staging" "$vector_dir"
    fi
    if [[ ! -d "$vector_dir/minimal/eip8321" || ! -d "$vector_dir/mainnet/eip8321" ]]; then
      echo 'Missing generated vectors: set EIP8321_VECTORS_DIR to the reftests directory.' >&2
      exit 2
    fi
    export EIP8321_VECTORS_DIR="$vector_dir"
    cargo test --locked --release \
      -p transition_functions -p bls -p kzg_utils \
      --features transition_functions/eip8321,bls/blst,kzg_utils/blst \
      --lib eip8321_reference_vectors -- --ignored --nocapture
    ;;
  legacy)
    if [[ ! -d consensus-spec-tests/tests/minimal/gloas ]]; then
      echo 'Existing consensus-spec-tests fixtures are required for legacy checks.' >&2
      exit 2
    fi
    cargo test --locked --release \
      -p transition_functions -p bls -p kzg_utils \
      --features bls/blst,kzg_utils/blst \
      --lib randao -- --nocapture
    ;;
  client)
    cargo check --locked --release -p grandine -p transition_functions \
      --features grandine/default-networks,grandine/eip8321
    ;;
  *)
    echo 'Usage: bash scripts/test_randao.sh [quick|new|vectors|legacy|client]' >&2
    exit 2
    ;;
esac
