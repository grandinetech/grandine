# libgrandine

This crate allows to build grandine as static/dynamic library, to embed it into EL.

## Building

For local testing, library can be built by command:

```bash
cargo build -p c_grandine --release
```

For deployment, use makefile script at the root directory of this project, to build for specified target:

```bash
# build both grandine binary and library for x86 linux
make -B x86_64-unknown-linux-gnu

# or build just library
make -B ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so
```

Available targets are:
* x86_64-unknown-linux-gnu
* aarch64-unknown-linux-gnu
* x86_64-pc-windows-msvc
* x86_64-apple-darwin
* aarch64-apple-darwin
