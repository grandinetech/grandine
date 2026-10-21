# Pre-built binaries and Docker

The Grandine team publishes ready-to-run binaries on GitHub and multi-platform Docker images on
Docker Hub. Both are built by the same release workflow from the same source.

## Binaries

Binaries are attached to each tagged release on the
[GitHub releases page](https://github.com/grandinetech/grandine/releases). Each release has one file per
platform, named `grandine-VERSION-PLATFORM`:

| Platform | File name |
| --- | --- |
| Linux x86-64 | `grandine-VERSION-linux-x64` |
| Linux ARM64 | `grandine-VERSION-linux-arm64` |
| macOS Intel | `grandine-VERSION-osx-x64` |
| macOS Apple silicon | `grandine-VERSION-osx-arm64` |
| Windows x86-64 | `grandine-VERSION-win-x64.exe` |

The binaries are single, self-contained executables built with the `compact` Cargo profile (release
optimizations without debug information). They include the Mainnet, Sepolia, Holesky and Hoodi network
configurations.

Builds of the `develop` branch are not published on GitHub. To run the newest unstable code, use the
`unstable` Docker image or [build from source](./build_from_source.md).

### Install a binary on Linux

1. Download the binary for your platform from the releases page. Replace `VERSION` with the release
   you want, for example `3.0.0`:

   ```bash
   VERSION=3.0.0
   curl -LO "https://github.com/grandinetech/grandine/releases/download/${VERSION}/grandine-${VERSION}-linux-x64"
   ```

2. Make it executable and move it onto your `PATH`:

   ```bash
   chmod +x "grandine-${VERSION}-linux-x64"
   sudo mv "grandine-${VERSION}-linux-x64" /usr/local/bin/grandine
   ```

3. Check that it runs:

   ```bash
   grandine --version
   ```

Grandine builds OpenSSL into the binary, but it uses the system's CA certificates to verify HTTPS
connections, for example to a checkpoint sync server. On a minimal Debian or Ubuntu system, install
them first:

```bash
sudo apt-get install ca-certificates
```

### Verify a download

Releases do not include checksum or signature files, and the binaries are not code-signed.
To check a binary, compare its version with the release you meant to download, and download only from
the official GitHub repository. If you need full assurance, [build from source](./build_from_source.md)
at the release tag and compare the behavior and version of the result.

### macOS and Windows

The macOS binaries are not notarized, so macOS may refuse to open them. Remove the quarantine
attribute after downloading:

```bash
xattr -d com.apple.quarantine grandine-VERSION-osx-arm64
chmod +x grandine-VERSION-osx-arm64
```

On Windows, run `grandine-VERSION-win-x64.exe` from PowerShell or a command prompt. Most examples in
this book use Linux paths; adjust them for your system.

## Docker

Images are published to Docker Hub as
[`sifrai/grandine`](https://hub.docker.com/r/sifrai/grandine/tags). They support `linux/amd64` and
`linux/arm64`. The image is based on Ubuntu 24.04, contains the binary at `/usr/local/bin/grandine` and
uses it as its entry point, so the arguments after the image name are passed to `grandine`.

### Tags

Grandine images:

| Tag | Content |
| --- | --- |
| `latest`, `stable` | Latest stable release, multi-platform |
| `stable-amd64`, `stable-arm64` | Latest stable release, single platform |
| `VERSION` | A specific release, multi-platform |
| `unstable` | Latest unstable build, multi-platform |
| `unstable-amd64`, `unstable-arm64` | Latest unstable build, single platform |
| `unstable-COMMIT` (for example `unstable-d779d84`) | An unstable build of a specific commit, multi-platform |
| `unstable-amd64-COMMIT`, `unstable-arm64-COMMIT` | An unstable build of a specific commit, single platform |

Grandine embedded in Nethermind (see [Grandine embedded in Nethermind](./nethermind_integration.md)):

| Tag | Content |
| --- | --- |
| `VERSION-nethermind-NETHERMIND_VERSION` | A specific Grandine release with a specific Nethermind release, multi-platform |
| `unstable-nethermind` | Latest unstable build with the latest packaged Nethermind, multi-platform |
| `unstable-nethermind-NETHERMIND_VERSION` | Latest unstable build with a specific Nethermind release, multi-platform |
| `unstable-amd64-nethermind-NETHERMIND_VERSION`, `unstable-arm64-nethermind-NETHERMIND_VERSION` | The same, single platform |
| `unstable-COMMIT-nethermind`, `unstable-COMMIT-nethermind-NETHERMIND_VERSION` | An unstable build of a specific commit with Nethermind, multi-platform |

> **Tip:** On Mainnet, use the `stable` tag. It follows stable releases only, so pre-releases and
> `develop` builds never reach it. To control exactly when you update, pin a version tag such as
> `sifrai/grandine:VERSION` instead. See [Updating Grandine](./updating.md).

### Pull and run

```bash
docker pull sifrai/grandine:stable
docker run --rm sifrai/grandine:stable --version
```

The container runs as `root`, so Grandine's default data directory inside it is
`/root/.grandine`. Mount a host directory there to keep the database across container restarts, and
mount the JWT secret:

```bash
docker run -d --name grandine \
  --restart unless-stopped \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -v $HOME/.grandine:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  --network hoodi \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /jwt.hex \
  --checkpoint-sync-url CHECKPOINT-URL \
  --http-address 0.0.0.0
```

Inside a container, the Beacon Node API must listen on `0.0.0.0` (`--http-address 0.0.0.0`) to be
reachable from outside the container. Publish port 5052 (`-p 127.0.0.1:5052:5052`) only if you need
the API on the host, and do not expose it to the internet.

For a complete setup with an execution client, see the Docker Compose example in
[Running as a service](./running_as_a_service.md), or use [Eth Docker](./eth_docker.md).

### Volumes and paths

| Path in the container | What it holds |
| --- | --- |
| `/root/.grandine/NETWORK/beacon` | Beacon database (`beacon_fork_choice`, `eth1_cache`, `pubkey_cache`, `sync`) |
| `/root/.grandine/NETWORK/network` | Peer-to-peer network key and state |
| `/root/.grandine/NETWORK/validator` | Validator data, including the slashing protection database |
| `/root/.grandine/NETWORK/meta.json` | Data directory schema version |

`NETWORK` is the network name, such as `mainnet` or `hoodi`. See
[Default ports and paths](./default_ports.md).

## Grandine bundled with Nethermind

Releases also include archives named `grandine-VERSION-nethermind-NETHERMIND_VERSION-PLATFORM.zip`, and
Docker Hub has matching `-nethermind` tags (`VERSION-nethermind-NETHERMIND_VERSION`). These contain a Nethermind
release with Grandine embedded as a plugin, so one process runs both the execution and the consensus
layer, and Grandine calls Nethermind's Engine API directly. See
[Grandine embedded in Nethermind](./nethermind_integration.md).

## Command line options

- `--version`: print the version and exit.
- `--help`: print all options and exit.
- `--data-dir`: default `$HOME/.grandine`. Parent directory for data; the network name is appended.
- `--http-address`: default `127.0.0.1`. Address the Beacon Node API listens on.
- `--http-port`: default `5052`. Port of the Beacon Node API.

See the [Command line reference](./cli_options.md) for the full list.
