EXCLUDES = --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
all: build

check:
	cargo check --features default-networks $(EXCLUDES)

build:
	cargo build --release --bin grandine --features default-networks $(EXCLUDES)

download-spec-tests:
	./scripts/download_spec_tests.sh

release:
	cargo build --profile compact --bin grandine --features default-networks $(EXCLUDES)

test: download-spec-tests
	cargo test --release $(EXCLUDES)

build-zkvm-pico:
	cargo +nightly-2025-08-04 build --release -p zkvm_host --features pico
