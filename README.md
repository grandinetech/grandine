# Grandine: A fast and lightweight Ethereum consensus client

## Documentation

The documentation is available [here](https://docs.grandine.io/). Feel free to reach us if you would like more details in some documentation chapters or have any questions.

## Performance

Grandine is a optimised and parallelised client. There aren't many published performance comparisons, but a previous [research](https://arxiv.org/abs/2311.05252) by MigaLabs may give some insight. We run 50,000 Holesky validators on one of our developer's machine.

## Memory Usage

Grandine is a lightweight client and needs only ~2.5GB of memory on the mainnet. In order to measure the amount of memory that Grandine actually needs one should stress the operating system to release the shared memory. `stress-ng` is an easy way to do it:

```
stress-ng --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k --vm-keep -m 1
```
## Build

Rust is needed in order to build Grandine. We recommend to use [rustup](https://rustup.rs/).

Some system dependencies are needed, the command below should install it on Ubuntu:

```
apt-get install ca-certificates libssl-dev clang cmake unzip protobuf-compiler libprotobuf-dev libz-dev
```

Then the build may take a few minutes:

```shell
git clone https://github.com/grandinetech/grandine
cd grandine
git submodule update --init dedicated_executor eth2_libp2p
make release
```

The compiled binary is available at `./target/compact/grandine`.

For faster building (larger binary size) use `--release` instead of `--profile compact`.

### Docker builds

Docker image can build with a simple command:

```shell
docker build .
```

### Cross-compilation

[Cross](https://github.com/cross-rs/cross) can be used for Grandine cross-compilation.

Cross-compilation command for `amd64` architecture:

```shell
make release TARGET=x86_64-unknown-linux-gnu
```

Cross-compilation command for `arm64` architecture:

```shell
make release TARGET=aarch64-unknown-linux-gnu
```

### Docker Cross builds

Cross-compiled binaries can be used for Docker images.

Docker build command for `amd64` architecture:

```shell
docker buildx build \
    --file Dockerfile.cross \
    --platform linux/amd64 \
    target/x86_64-unknown-linux-gnu/compact/
```

Docker build command for `arm64` architecture:

```shell
docker buildx build \
    --file Dockerfile.cross \
    --platform linux/arm64 \
    target/aarch64-unknown-linux-gnu/compact/
```

## PQ devnets

On a network that schedules the PQ fork, validators sign with XMSS keys, and aggregates of their
signatures are STARK proofs. Grandine proves and verifies them in-process with leanVM, at the
revision pinned in `Cargo.toml` (`lean_vm`): proofs made with another revision do not verify. The
beacon node starts the prover at startup (`grandine vc` needs none). The `LEANVM_THREADS`
environment variable sets its thread count; the default, 0, lets leanVM choose about one per
physical core it may run on. A proof can use several GiB of memory while it runs.

`make build` and `make release` compile leanVM's prover once per CPU tier
(`scripts/build/tier-rustc`), and the binary runs the fastest tier the CPU supports. A plain `cargo
build` leaves the tiers without their CPU features: proofs are then slower, and the first one prints
a warning. x86-64 hosts need AVX2 and PCLMULQDQ.

The validator keys of a PQ network are the usual EIP-2335 keystores. Grandine derives the XMSS key
and the VRF tree of each validator from its BLS secret key, as the devnet genesis does. Both are
slow to build: about a second per XMSS key, and minutes per VRF tree, without which a validator
cannot propose. Two optional artifacts of the devnet save that work for genesis validators. Each is
a URL or a local path, and both are checked against the keys, so neither needs to be trusted:

- `--xmss-cache-url`: the XMSS cache, the trees of each devnet key. It needs the built-in beacon
  node, and is ignored under `grandine vc`.
- `--vrf-state-url`: the VRF state, the branch of slot 0 in each VRF tree. A tree loaded from it
  covers the first `2^20` slots.

Keys without a matching record are built as before, and VRF trees are saved under the validator
directory once built.

By default, Grandine proves aggregates only for committees in which one of its validators is an
aggregator. `--features AggregateAllAttestations` proves every committee it collects signatures
for, which is useful on a small devnet but costs much more proving time.

## Team

Grandine is built by [Grandine core team](https://grandine.io/) led by [Saulius Grigaitis](https://twitter.com/sauliuseth).
We also involve academia in the early stages of new ideas, however, the optimized production code is delivered by the core team.

## Audits

Grandine is used in production and the [audits](/audit) have been completed by [Matter Labs](https://matter-labs.io/) and [X41 D-Sec](https://x41-dsec.de/). The client was also tested by [Antithesis](https://antithesis.com/) team. No serious issues were found. However, always secure your keys with the approach you trust ([Web3Signer](https://docs.web3signer.consensys.io), [Vouch](https://github.com/attestantio/vouch), etc.). Use it at your risk.

## Contact

It's best to reach us via [Grandine Discord](https://discord.gg/H9XCdUSyZd) or [Grandine Telegram](https://t.me/+yMHjrJanClozYzQ0). Feel free to join!

## Donate

Funding public goods is hard. We appreciate your donations via Ethereum address [0x93b10cc89A3D3b5bb6bBB04EfFe104873EF002A9](https://etherscan.io/address/0x93b10cc89A3D3b5bb6bBB04EfFe104873EF002A9).

## Credits

Grandine focuses on original consensus core implementations, however it uses [a lot of crates](Cargo.lock) developed by the community. For example, Grandine uses `rust-libp2p` based networking libraries developed by the Lighthouse team since the beginning. Lighthouse's `eth2_libp2p` library was generic back then and we still use a fork of it now. We also used `libmdbx-rs` bindings library by Akula maintainer and now we use a fork of it maintained by Reth team. So we focus on the original consensus core because it's the unique value Grandine offers for the community, but we also love to use some great crates developed by other client teams and the community. Grandine would not be where it is now without the efforts of the other client teams and the community! Huge thanks to everyone!
