#!/bin/sh

set -o errexit
set -o nounset

cd "$(dirname "$0")"

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

git submodule update --init       \
    ../../eth2_libp2p             \
    ../../grandine-snapshot-tests \
    ../../slashing-protection-interchange-tests

curl                     \
    --fail               \
    --proto =https       \
    --show-error         \
    --silent             \
    --tlsv1.2            \
    https://sh.rustup.rs |
    sponge               |
    sh -s -- --no-modify-path -y

# `cargo-fmt` must be run in the root of a crate. It appears to be a regression:
# <https://github.com/rust-lang/rustfmt/issues/3647>
# Running `cargo-fmt` with `--all` works too but takes noticeably longer. This explains why:
# <https://github.com/rust-lang/rustfmt/issues/4247#issuecomment-644957261>
(
    cd ../..
    cargo fmt -- --check
)

# download consensus spec tests if not exist.
(
  cd ../..
  ./scripts/download_spec_tests.sh
)

./clippy.bash --deny warnings
cargo test --release --no-fail-fast --features stub-grandine-version --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
./consensus-spec-tests-coverage.rb
