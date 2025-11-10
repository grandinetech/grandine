EXCLUDES = --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
TARGET ?= 

.PHONY: all
all: build

.PHONY: check
check:
	cargo check --features default-networks $(EXCLUDES)

.PHONY: build
build:
	cargo build --release --bin grandine --features default-networks $(EXCLUDES)

.PHONY: download-spec-tests
download-spec-tests:
	./scripts/download_spec_tests.sh

.PHONY: release
release:
ifeq ($(TARGET),)
	cargo build --profile compact --bin grandine --features default-networks $(EXCLUDES)
else ifneq (,$(findstring linux,$(TARGET)))
	cross build --bin grandine --target $(TARGET) --features default-networks --profile compact $(EXCLUDES)
else
	cargo build --profile compact --bin grandine --target $(TARGET) --features default-networks $(EXCLUDES)
endif

.PHONY: test
test: download-spec-tests
	cargo test --release $(EXCLUDES)
