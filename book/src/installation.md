# Installation overview

You can install Grandine in four ways. All of them give you the same `grandine` binary with the same
options.

| Method | Best for | Page |
| --- | --- | --- |
| Pre-built binary | Most Linux, macOS and Windows users who run Grandine directly or under systemd | [Pre-built binaries and Docker](./downloads.md) |
| Docker image | Users who run their node with their own Docker or Docker Compose setup | [Pre-built binaries and Docker](./downloads.md) |
| Eth Docker | Stakers who want a ready-made Docker Compose setup that also runs the execution client, MEV-Boost and key management | [Running with Eth Docker](./eth_docker.md) |
| Build from source | Developers, unusual platforms, custom features, or users who want to audit what they run | [Building from source](./build_from_source.md) |

Before you install, check the [System requirements](./hardware_requirements.md).

## Which version to install

Grandine has two release channels:

- **Stable** releases have plain version tags such as `3.0.0`. Use them on Mainnet.
- **Unstable** builds come from the `develop` branch and from pre-release tags such as `3.0.0-rc.0`.
  They get new features and fixes first, and suit testnets and testing.

See [Updating Grandine](./updating.md) for how releases are published and how to upgrade.

## Supported platforms

| Platform | Binary | Docker |
| --- | --- | --- |
| Linux x86-64 | Yes | Yes (`linux/amd64`) |
| Linux ARM64 | Yes | Yes (`linux/arm64`) |
| macOS Intel | Yes | No |
| macOS Apple silicon | Yes | No |
| Windows x86-64 | Yes | No |

Binaries are attached to every GitHub release. Builds of the `develop` branch are published only as
the `unstable` Docker image, so on macOS and Windows the newest unstable code requires
[building from source](./build_from_source.md).

## After installing

1. Check the version:

   ```bash
   grandine --version
   ```

   It prints the application name and version, for example `Grandine 3.0.0`.

2. List the options:

   ```bash
   grandine --help
   ```

3. Follow the [Quick start](./quick_start.md) to run an execution client and Grandine together.

4. Set Grandine up as a long-running service with
   [Running as a service](./running_as_a_service.md).
