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
