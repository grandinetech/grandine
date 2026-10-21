# Building from source

Build Grandine from source when you want the newest code, a platform without official binaries, a
build with extra features, or to check exactly what you run.

## Requirements

- **Rust**, installed with [rustup](https://rustup.rs/). The repository pins its toolchain in
  `rust-toolchain.toml` (Rust 1.95.0 at the time of writing). rustup reads this file and installs
  the right version on the first build, so you do not need to pick a version yourself.
- **System packages**: a C compiler toolchain, Clang, CMake, the Protocol Buffers compiler, and the
  OpenSSL and zlib development files.
- **Git**, to clone the repository and its submodules.
- Enough memory and disk for the build: plan for at least 8 GB of RAM and 20 GB of free disk. These are estimates, not measured figures.
  <!-- TODO(verify): build memory and disk needs, and build time, are estimates. The repository gives no figures; CI and release builds run on standard GitHub-hosted runners after freeing disk space. -->

On Ubuntu or Debian, install the system packages with:

```bash
sudo apt-get install build-essential ca-certificates libssl-dev clang cmake unzip protobuf-compiler libprotobuf-dev libz-dev git
```

Then install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build

1. Clone the repository and fetch the submodules the build needs:

   ```bash
   git clone https://github.com/grandinetech/grandine
   cd grandine
   git submodule update --init dedicated_executor eth2_libp2p
   ```

   The other submodules (`grandine-snapshot-tests`, `slashing-protection-interchange-tests`, `hive`)
   are only needed for tests.

2. To build a release, check out its tag. Skip this step to build the `develop` branch:

   ```bash
   git checkout VERSION
   git submodule update --init dedicated_executor eth2_libp2p
   ```

3. Build:

   ```bash
   make release
   ```

   The build takes several minutes. The binary is written to `./target/compact/grandine`.

4. Install it:

   ```bash
   sudo cp ./target/compact/grandine /usr/local/bin/grandine
   grandine --version
   ```

### What `make release` does

`make release` runs:

```bash
cargo build --profile compact --bin grandine --features default-networks --features tracing \
  --workspace --exclude zkvm_host --exclude zkvm_guest_risc0 --exclude c_grandine --exclude csharp_grandine
```

Use `make release` rather than typing this command. If you do run `cargo` yourself, keep the
`--workspace --exclude …` options: without them, Cargo also builds workspace members that enable a
second BLS backend, and the build fails with errors such as
`` the name `AggregatePublicKey` is defined multiple times ``.

- The `compact` profile is the release profile without debug information. It produces a much smaller
  binary.
- `default-networks` includes the Mainnet, Sepolia, Holesky and Hoodi configurations. At least one
  network or preset feature is required; a plain `cargo build` without features stops with
  `at least one preset must be enabled`.
- `tracing` enables tracing support in the core crates. Build with `make release DISABLE_TRACING=1` to
  leave it out.

Other useful targets:

| Command | Result |
| --- | --- |
| `make build` | Uses the `release` profile instead of `compact`: same optimizations with full debug information, so backtraces have file names and line numbers. The binary is in `./target/release/grandine` and is much larger |
| `make release METRICS=1` | Adds metrics collection inside the core crates (`transition_functions`, `helper_functions`) |
| `make minimal` | A build for the `minimal` preset, used by local devnets and tests |
| `make check` | Type-check the workspace without building |
| `make test` | Download the consensus spec tests and run the test suite |

## Cryptography backends

Grandine selects its BLS and KZG libraries at compile time with Cargo features. The `grandine` crate
enables `blst` for both by default, which is what the official binaries use.

The KZG library used at run time can be chosen with `--kzg-backend` from the backends compiled in. To
compile in additional KZG backends, add their features. The Makefile has no option for extra
features, so run the command that `make release` runs, with the feature added:

```bash
cargo build --profile compact --bin grandine --features default-networks,arkworks \
  --workspace --exclude zkvm_host --exclude zkvm_guest_risc0 --exclude c_grandine --exclude csharp_grandine
```

This keeps the default `blst` backend and adds `arkworks`. CI builds the workspace the same way with
other backend combinations.

The available KZG backends are `arkworks`, `blst`, `constantine`, `mcl` and `zkcrypto`. The
`constantine` backend also needs the Nim compiler and, on Linux, `libgmp-dev` and `llvm`. Asking
for a backend at run time that was not compiled in fails with
`backend is not compiled - please specify feature flag when compiling grandine`.

> **Note:** When you build a single crate with `cargo -p`, select a backend yourself, for example
> `-p bls --features bls/blst -p kzg_utils --features kzg_utils/blst`.

## Cross-compilation

Grandine uses [cross](https://github.com/cross-rs/cross) to build Linux binaries for another
architecture. cross runs the build in a container, so you need Docker or Podman. The container images
and the extra packages they install are configured in `Cross.toml`.

Install cross:

```bash
cargo install cross --git https://github.com/cross-rs/cross
```

Build for x86-64 Linux:

```bash
make release TARGET=x86_64-unknown-linux-gnu
```

Build for ARM64 Linux, for example a Raspberry Pi 5 or an ARM server:

```bash
make release TARGET=aarch64-unknown-linux-gnu
```

The binaries are written to `./target/TARGET/compact/grandine`. These targets also build
`libgrandine.so`, the library used by the Nethermind bundle.

macOS (`x86_64-apple-darwin`, `aarch64-apple-darwin`) and Windows (`x86_64-pc-windows-msvc`) targets
are built natively with Cargo on those systems, for example `make aarch64-apple-darwin` on an Apple
silicon Mac.

## Docker images

### From a cross-compiled binary

This is how the official images are made. Build the binary with cross first, then package it with
`Dockerfile.cross`, which copies it into an Ubuntu 24.04 image:

```bash
make release TARGET=x86_64-unknown-linux-gnu

docker buildx build \
  --file Dockerfile.cross \
  --platform linux/amd64 \
  --tag grandine:local \
  target/x86_64-unknown-linux-gnu/compact/
```

For ARM64, use `TARGET=aarch64-unknown-linux-gnu`, `--platform linux/arm64` and
`target/aarch64-unknown-linux-gnu/compact/`.

### All in Docker

The `Dockerfile` in the repository root compiles Grandine inside a Rust container and copies the result
into an Ubuntu image. Fetch the submodules first, because the build copies your working tree:

```bash
git submodule update --init dedicated_executor eth2_libp2p
docker build --tag grandine:local .
```

The builder stage starts from the `rust:1.82.0-bullseye` image, but rustup installs the toolchain
pinned in `rust-toolchain.toml` when the build starts, so the Rust version in the image tag is not
the one used. Keep in mind that:

- The build copies the whole working tree, including a local `target` directory if you have one,
  because the repository has no `.dockerignore`. Delete or move `target` first to keep the build
  context small.
- The final image is plain `ubuntu:latest` without the `ca-certificates` package, so HTTPS
  connections, for example to a checkpoint sync server, fail certificate checks. Add the package in
  your own image, or use the official `sifrai/grandine` image, which includes it.

## Updating a source build

```bash
cd grandine
git fetch --tags
git checkout VERSION
git submodule update --init dedicated_executor eth2_libp2p
make release
```

Then restart Grandine with the new binary. See [Updating Grandine](./updating.md).

## Troubleshooting builds

- **`at least one preset must be enabled`**: you ran `cargo build` without features. Use `make release`
  or add `--features default-networks`.
- **`` the name `AggregatePublicKey` is defined multiple times ``** and similar errors in `bls`: you
  ran `cargo build` without the `--workspace --exclude …` options. Use `make release`.
- **`cannot open crtn.o` or `cannot open crt1.o`** while linking: the C library development files are
  missing. Install `build-essential`, or at least `libc6-dev`.
- **`'stdarg.h' file not found`** in `reth-mdbx-sys`: Clang is missing or incomplete. Install `clang`.
- **Errors about `protoc` or `cmake`**: install `protobuf-compiler` and `cmake`.
- **Errors in `eth2_libp2p` or `dedicated_executor`**, such as missing files or functions that do
  not exist: the submodules are not checked out, or are at a different commit than the one this
  version of Grandine expects (for example after a `git pull` or a `git checkout`). Run
  `git submodule update --init dedicated_executor eth2_libp2p`.
- **The build is killed**: the machine ran out of memory. Close other programs, add swap, or limit
  parallel jobs with `CARGO_BUILD_JOBS=2 make release`.

For development workflows (tests, lints, spec tests), see [Contributing and development](./contributing.md).

## Command line options

- `--kzg-backend`: default `blst` in the official builds. KZG library to use, from those compiled in.

See the [Command line reference](./cli_options.md) for the full list.
