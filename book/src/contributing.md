# Contributing and development

This page is for people who want to change Grandine or this book: how to set up a development
environment, build and test the code, run the lints that CI runs, and preview the documentation.

Grandine is open source under the GNU General Public License, version 3. The source code is at
[github.com/grandinetech/grandine](https://github.com/grandinetech/grandine). The main development
branch is `develop`; open pull requests against it.

## Development setup

### System packages

On Ubuntu or Debian, install the packages CI uses:

```bash
sudo apt-get install ca-certificates libssl-dev clang cmake unzip protobuf-compiler libprotobuf-dev libz-dev
```

### Rust toolchain

Install Rust with [rustup](https://rustup.rs/). The repository pins its toolchain version and
components (`clippy`, `rustfmt`) in `rust-toolchain.toml`, so `cargo` selects the right version
automatically when you run it inside the repository.

### Source and submodules

```bash
git clone https://github.com/grandinetech/grandine
cd grandine
git submodule update --init dedicated_executor eth2_libp2p
```

The repository has these submodules:

| Submodule | Needed for |
|---|---|
| `dedicated_executor` | Building |
| `eth2_libp2p` | Building (the networking stack) |
| `grandine-snapshot-tests` | Running the full test suite |
| `slashing-protection-interchange-tests` | Running the full test suite (EIP-3076 test vectors) |
| `hive` | [Hive](https://github.com/ethereum/hive) integration testing only |

To run the whole test suite, also fetch the test submodules:

```bash
git submodule update --init grandine-snapshot-tests slashing-protection-interchange-tests
```

## Building

The `Makefile` wraps the common Cargo commands for the whole workspace:

| Command | What it does |
|---|---|
| `make check` | `cargo check` of the workspace with the default networks enabled. |
| `make build` | Release build of the `grandine` binary (`target/release/grandine`). |
| `make release` | Build with the `compact` profile, as release artifacts are built (`target/compact/grandine`). |
| `make minimal` | Build with the minimal preset as well, for minimal-preset devnets. |
| `make test` | Download the spec tests, then run all tests in release mode. |

Two variables change what is compiled in:

- `make METRICS=1 ...` enables metrics collection in core crates (`transition_functions`,
  `helper_functions`).
- `make DISABLE_TRACING=1 ...` builds without tracing support in core crates.

See [Building from source](./build_from_source.md) for cross-compilation and Docker builds.

### Building or testing a single crate

A crate does not compile on its own until a cryptography backend is selected. The full binary selects
`blst` by default, but `cargo -p CRATE` does not. Add the BLS and KZG backend features to any command
that uses `-p`:

```bash
cargo test -p fork_choice_control \
  -p bls --features bls/blst \
  -p kzg_utils --features kzg_utils/blst
```

```bash
cargo clippy -p runtime \
  -p bls --features bls/blst \
  -p kzg_utils --features kzg_utils/blst
```

Other backends are tested in CI as well and are selected the same way: `zkcrypto` for BLS, and
`arkworks`, `constantine`, `mcl` or `zkcrypto` for KZG.

## Lints

CI rejects code that is not formatted or that has Clippy warnings. Run the same checks before you
push:

```bash
cargo fmt --check
scripts/ci/clippy.bash --deny warnings
```

`scripts/ci/clippy.bash` runs Clippy on all targets (including tests and benchmarks) of the
workspace's own packages with the features CI uses. Run `cargo fmt` without `--check` to fix
formatting.

## Tests

### Unit and integration tests

```bash
make test
```

This downloads the spec tests (see below) and runs:

```bash
cargo test --release --features default-networks,stub-grandine-version --workspace --exclude ...
```

`stub-grandine-version` replaces the real version string with a fixed one (`1.2.3`), so test results
do not depend on the version being built.

### Consensus spec tests

The official [consensus-spec-tests](https://github.com/ethereum/consensus-specs) are not a submodule.
They are downloaded from the consensus-specs releases by a script:

```bash
scripts/download_spec_tests.sh
# or
make download-spec-tests
```

The script downloads three sets of test vectors into the repository root:

| Directory | Source | Version variable |
|---|---|---|
| `consensus-spec-tests/` | `ethereum/consensus-specs` releases (`general`, `minimal`, `mainnet` and fork choice compliance tests) | `SPEC_VERSION` |
| `cryptography-spec-tests/` | `ethereum/cryptography-specs` releases (BLS and KZG vectors) | `CRYPTO_SPEC_VERSION` |
| `ssz-spec-tests/` | `ethereum/ssz-specs` releases (SSZ generic vectors) | `SSZ_SPEC_VERSION` |

The default versions are set at the top of the script. Each directory records its version in a
`.version` file, and the script skips the download if the version already matches. To test against
another release, set the variable:

```bash
SPEC_VERSION=vX.Y.Z scripts/download_spec_tests.sh
```

Spec tests run as part of `cargo test`. CI also runs `scripts/ci/consensus-spec-tests-coverage.rb`
to check that every spec test case is covered.

### What CI runs

On every push and pull request, CI builds and tests on Linux, macOS and Windows with several
cryptography backends. The steps are, in short:

1. `cargo fmt --check`
2. `scripts/download_spec_tests.sh`
3. `scripts/ci/clippy.bash --deny warnings`
4. `cargo test --release ...`
5. The spec test coverage check (Linux)

## Local devnets

To try a change against other clients, start a local network with Kurtosis and a Grandine image or
binary built from your branch. See
[Configuration files and custom networks](./configuration_files.md#devnets).

## Contributing to this book

The book is an [mdBook](https://rust-lang.github.io/mdBook/) in the `book` directory. Pages are
Markdown files in `book/src`, and `book/src/SUMMARY.md` defines the table of contents.

### Preview the book

```bash
cargo install mdbook
mdbook serve book
```

Then open `http://localhost:3000`. The page reloads when you save a file. To build static HTML into
`book/book`, run `mdbook build book`.

### Writing guidelines

- Check every option, default and path against the source code. The CLI is defined in
  `runtime/src/grandine_args.rs`, and most defaults are in `runtime/src/defaults.rs`.
- Write for node operators: say what a feature is, when it is needed, and how to use it, with
  commands that can be copied.
- Use `hoodi` in testnet examples and `mainnet` otherwise. Write placeholders in capitals, such as
  `EL-HOST` or `/path/to/jwt.hex`.
- Link to other pages with relative links such as `[Checkpoint sync](./checkpoint_sync.md)`.
- When you add or rename an option, update [Command line reference](./cli_options.md) and the
  `## Command line options` section of the pages that use it.
- Add new pages to `SUMMARY.md`.

Every page has an edit link that opens the file on GitHub, so small fixes can be proposed from the
browser.

## Getting help

Ask development questions on Discord or in a GitHub issue. See [Support](./support.md). Report
security issues privately, as described there.
