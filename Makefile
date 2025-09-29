all: build

build:
	cargo build --release --bin grandine --features default-networks --workspace --exclude zkvm_host --exclude zkvm_guest_risc0

test:
	cargo test --release --workspace --exclude zkvm_host --exclude zkvm_guest_risc0

build-zkvm-pico:
	cargo +nightly-2025-08-04 build --release -p zkvm_host --features pico
