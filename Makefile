all: build

build:
	cargo build --release --bin grandine --features default-networks --workspace --exclude zkvm_host --exclude zkvm_guest_risc0

test:
	cargo test --release --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
