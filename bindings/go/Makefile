ifeq ($(PROFILE), debug)
	CARGO_FLAGS=--debug
	CARGO_OUTPUT_DIR=debug
else
	CARGO_FLAGS=--release
	CARGO_OUTPUT_DIR=release
endif

TARGET_TRIPLET=x86_64-unknown-linux-gnu

libc_grandine.a:
	cargo build $(CARGO_FLAGS) --manifest-path ../c/Cargo.toml
	mkdir -p lib
	cp ../../target/$(CARGO_OUTPUT_DIR)/libc_grandine.a ./lib/libc_grandine.a
	cp ../c/build/c_grandine.h ./lib/c_grandine.h
