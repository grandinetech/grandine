# Grandine: A fast and lightweight Ethereum consensus client

## Documentation

The documentation is available [here](https://docs.grandine.io/). Feel free to reach us if you would like more details in some documentation chapters or have any questions.

## Performance

Grandine is a optimised and parallelised client. There aren't many published performance comparisions, but a previous [research](https://arxiv.org/abs/2311.05252) by MigaLabs may give some insight. We run 50,000 Holesky validators on one of our developer's machine.

## Memory Usage

Grandine is a lightweight client and needs only ~2.5GB of memory on the mainnet. In order to measure the amount of memory that Grandine actually needs one should stress the operating system to release the shared memory. `stress-ng` is an easy way to do it:

```
stress-ng --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k --vm-keep -m 1
```
## Build

Rust is needed in order to build Grandine. We recommend to use [rustup](https://rustup.rs/).

Some system dependencies are needed, the command below should install it on Ubuntu:

```
apt-get install ca-certificates libssl-dev clang cmake unzip protobuf-compiler libz-dev
```

Then the build may take a few minutes:

```shell
git clone https://github.com/grandinetech/grandine
cd grandine
git submodule update --init dedicated_executor eth2_libp2p
cargo build --profile compact --features default-networks
```

The compiled binary is available at `./target/compact/grandine`.

For faster building (larger binary size) use `--release` instead of `--compact`.

### Docker builds

Docker image can build with a simple command:

```shell
docker build .
```

### Cross-compilation

[Cross](https://github.com/cross-rs/cross) can be used for Grandine cross-compilation.

Cross-compilation command for `amd64` architecture:

```shell
cross build \
    --bin grandine \
    --target x86_64-unknown-linux-gnu \
    --features default-networks \
    --profile compact
```

Cross-compilation command for `arm64` architecture:

```shell
cross build \
    --bin grandine \
    --target aarch64-unknown-linux-gnu \
    --features default-networks \
    --profile compact
```

### Docker Cross builds

Cross-compilated binaries can be used for Docker images.

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

## Team

Grandine is built by [Grandine core team](https://grandine.io/) led by [Saulius Grigaitis](https://twitter.com/sauliuseth).
We also involve academia in the early stages of new ideas, however, the optimized production code is delivered by the core team.

## Audits

Grandine is used in production, however no audits are completed. Always secure your keys with the approach you trust ([Web3Signer](https://docs.web3signer.consensys.io), [Vouch](https://github.com/attestantio/vouch), etc.). Use it at your risk. 

## Contact

It's best to reach us via [Grandine Discord](https://discord.gg/H9XCdUSyZd) or [Grandine Telegram](https://t.me/+yMHjrJanClozYzQ0). Feel free to join!

## Credits

Grandine focuses on original consensus core implementations, however it uses [a lot of crates](Cargo.lock) developed by the community. For example, Grandine uses `rust-libp2p` based networking libraries developed by the Lighthouse team since the beginning. Lighthouse's `eth2_libp2p` library was generic back then and we still use a fork of it now. We also used `libmdbx-rs` bindings library by Akula maintainer and now we use a fork of it maintained by Reth team. So we focus on the original consensus core because it's the unique value Grandine offers for the community, but we also love to use some great crates developed by other client teams and the community. Grandine would not be where it is now without the efforts of the other client teams and the community! Huge thanks to everyone!
