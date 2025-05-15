.PHONY: check build download-spec-tests release test linux-x64 linux-arm64

EXCLUDES = --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
TARGET ?= x86_64-unknown-linux-gnu

all: build

check:
	cargo check --features default-networks $(EXCLUDES)

build:
	cargo build --release --bin grandine --features default-networks $(EXCLUDES)

download-spec-tests:
	./scripts/download_spec_tests.sh

release:
	cross build --bin grandine --target $(TARGET) --features default-networks --profile compact $(EXCLUDES)

linux-x64:
	$(MAKE) release TARGET=x86_64-unknown-linux-gnu

linux-arm64:
	$(MAKE) release TARGET=aarch64-unknown-linux-gnu

test: download-spec-tests
	cargo test --release $(EXCLUDES)
