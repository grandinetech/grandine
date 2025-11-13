EXCLUDES = --workspace --exclude zkvm_host --exclude zkvm_guest_risc0
FEATURES = --features default-networks

# build with metrics collection for core crates (transition_functions, helper_functions)
# e.g. make METRICS=1
ifeq ($(METRICS),1)
	FEATURES := $(FEATURES) --features metrics
endif

# build without tracing support for core crates (transition_functions, helper_functions)
# e.g. make DISABLE_TRACING=1
DISABLE_TRACING ?= 0

ifeq ($(DISABLE_TRACING),0)
	FEATURES := $(FEATURES) --features tracing
endif

all: build

check:
	cargo check ${FEATURES} $(EXCLUDES)

build:
	cargo build --release --bin grandine $(FEATURES) $(EXCLUDES)

download-spec-tests:
	./scripts/download_spec_tests.sh

release:
	cargo build --profile compact --bin grandine $(FEATURES) $(EXCLUDES)

test: download-spec-tests
	cargo test --release --features stub-grandine-version $(EXCLUDES)
