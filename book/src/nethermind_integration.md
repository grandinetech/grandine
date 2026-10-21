# Grandine embedded in Nethermind

Grandine can run embedded inside the [Nethermind](https://www.nethermind.io/) execution client. One
process then runs both the execution layer and the consensus layer, and the two talk to each other
directly, without the network hop that normally sits between them. This setup is for nodes that need
the fastest possible communication between the execution and consensus clients.

## Why embed Grandine in Nethermind

In a standard setup, the consensus client and the execution client are separate processes. They talk
over the [Engine API](https://github.com/ethereum/execution-apis/tree/main/src/engine): every call is
an HTTP request, authenticated with a JWT, with its payload encoded as JSON and decoded again on the
other side. Execution payloads and blobs are large, so this encoding work is on the critical path of
every block that is imported or proposed.

Standard setup:

```text
+---------------------+                         +----------------------+
| Grandine process    |   HTTP + JWT + JSON     | Execution client     |
|                     | <---------------------> | process              |
|  beacon node        |   Engine API, port 8551 |  (Nethermind, Geth,  |
|                     |                         |   Besu, ...)         |
+---------------------+                         +----------------------+
```

With the Nethermind integration, Grandine is loaded into the Nethermind process as a plugin and calls
Nethermind's Engine API implementation directly, as native function calls.

Embedded setup:

```text
+--------------------------------------------------------------+
| Nethermind process                                           |
|                                                              |
|  +----------------------+               +-----------------+  |
|  | Grandine             |  direct calls |  Nethermind     |  |
|  |  beacon node         | <-----------> |  Engine API     |  |
|  |  (plugin)            |               |  execution      |  |
|  +----------------------+               +-----------------+  |
|                                                              |
+--------------------------------------------------------------+
```

This removes:

- the HTTP round trip on `engine_newPayload`, `engine_forkchoiceUpdated`, `engine_getPayload`,
  `engine_getBlobs` and the other Engine API methods;
- JSON encoding and decoding of execution payloads, blobs and proofs;
- the JWT secret, and the risk of a misconfigured or mismatched Engine API endpoint;
- a second process to install, update and supervise.

Grandine still runs its own beacon node with peer-to-peer networking, the Beacon Node API, metrics
and, if you pass validator keys, the built-in validator client. Only the link to the execution client
changes.

## How it works

The integration has two parts, both placed in Nethermind's `plugins` directory:

- `libgrandine.so` (`libgrandine.dylib` on macOS, `grandine.dll` on Windows): Grandine built as a
  native library. It is built from the `bindings/c` crate of the Grandine repository.
- `Grandine.NethermindPlugin.dll`: a Nethermind plugin that starts Grandine when Nethermind starts and
  connects it to Nethermind's Engine API module. It is built from `bindings/csharp`.

When the plugin is enabled, Nethermind starts Grandine after it has registered its RPC modules, passes
it the configured options, and stops it on shutdown. Grandine's Engine API calls go straight to
Nethermind's implementation of the Engine API in the same process.

To embed Grandine in another program the same way, see [Embeddable Grandine](./embedding.md).

## Download

Each Grandine release publishes the integration in two forms.

### Release archives

The [GitHub releases](https://github.com/grandinetech/grandine/releases) include archives named
`grandine-GRANDINE_VERSION-nethermind-NETHERMIND_VERSION-PLATFORM.zip`. Each one contains a full
Nethermind release with both plugin files already in its `plugins` directory. Platforms are
`linux-x64`, `linux-arm64`, `windows-x64`, `macos-x64` and `macos-arm64`.

### Docker images

The `sifrai/grandine` repository on Docker Hub has images built on the official
`nethermind/nethermind` image with the plugin added. Their tags are:

- `VERSION-nethermind-NETHERMIND_VERSION`: a specific Grandine release with a specific Nethermind
  release;
- `unstable-nethermind`: the latest unstable Grandine with the latest Nethermind it was packaged with;
- `unstable-nethermind-NETHERMIND_VERSION`: the latest unstable Grandine with a specific Nethermind
  release, also as `unstable-amd64-nethermind-NETHERMIND_VERSION` and
  `unstable-arm64-nethermind-NETHERMIND_VERSION` for a single platform;
- `unstable-COMMIT-nethermind` and `unstable-COMMIT-nethermind-NETHERMIND_VERSION`: an unstable build
  of a specific Grandine commit.

All multi-platform tags support `linux/amd64` and `linux/arm64`. See the full list on
[Docker Hub](https://hub.docker.com/r/sifrai/grandine/tags).

The image's entrypoint is Nethermind, so options after the image name are Nethermind options.

## Configuration

Grandine is configured through Nethermind's configuration system, in the `Grandine` section. The
plugin is off by default. Turn it on with `Grandine.Enabled`:

```bash
./nethermind \
  --config mainnet \
  --Grandine.Enabled true \
  --Grandine.CheckpointSyncUrl CHECKPOINT-URL
```

Every Grandine beacon node and validator option is available as a Nethermind setting. Its name is the
Grandine option in PascalCase under `Grandine.`:

| Grandine option | Nethermind setting |
|---|---|
| `--checkpoint-sync-url` | `Grandine.CheckpointSyncUrl` |
| `--data-dir` | `Grandine.DataDir` |
| `--http-address` | `Grandine.HttpAddress` |
| `--suggested-fee-recipient` | `Grandine.SuggestedFeeRecipient` |
| `--keystore-dir` | `Grandine.KeystoreDir` |
| `--keystore-password-file` | `Grandine.KeystorePasswordFile` |
| `--metrics` | `Grandine.Metrics` |

Flags such as `--metrics` take `true`. Options that take a value take it as a string, in the same
format the Grandine command line uses.

Nethermind also accepts each setting in kebab case with a `grandine-` prefix, for example
`--grandine-checkpoint-sync-url` for `--Grandine.CheckpointSyncUrl`. The bare Grandine option, such as
`--checkpoint-sync-url`, is not a Nethermind option. The same settings can also go in the `Grandine`
section of a Nethermind JSON configuration file, or in environment variables named
`NETHERMIND_GRANDINECONFIG_` followed by the setting in upper case, for example
`NETHERMIND_GRANDINECONFIG_CHECKPOINTSYNCURL`. Command line options take precedence over
environment variables, and environment variables over the configuration file. See
[Nethermind configuration](https://docs.nethermind.io/fundamentals/configuration).

Some options are set by the integration and are not available:

- `--eth1-rpc-urls` and `--jwt-secret`: there is no Engine API endpoint or JWT secret, because
  Grandine calls Nethermind directly.

If you do not set `Grandine.Network`, the plugin chooses the Grandine network from the chain that
Nethermind runs, so `--config mainnet` runs Grandine on Mainnet and `--config hoodi` on Hoodi.

### Docker example

```bash
docker run -d --name nethermind-grandine \
  -p 30303:30303/tcp -p 30303:30303/udp \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -v /var/lib/nethermind:/nethermind/data \
  -v $HOME/.grandine:/root/.grandine \
  sifrai/grandine:VERSION-nethermind-NETHERMIND_VERSION \
  --config mainnet \
  --data-dir /nethermind/data \
  --Grandine.Enabled true \
  --Grandine.CheckpointSyncUrl CHECKPOINT-URL
```

Replace `VERSION` and `NETHERMIND_VERSION` with a tag listed on
[Docker Hub](https://hub.docker.com/r/sifrai/grandine/tags).

Open the peer-to-peer ports of both clients: Nethermind's (30303 TCP and UDP by default) and
Grandine's (9000 TCP and UDP, and 9001 UDP for QUIC). See [Networking and peers](./networking.md).

## Logs and APIs

Grandine's log lines appear in Nethermind's output, and Nethermind logs the arguments it starts
Grandine with (`Starting grandine with arguments: ...`). Grandine's Beacon Node API and metrics are
served on their usual ports (5052 and 5054 by default), so tools and validator clients connect to them
exactly as they would to a standalone Grandine. See [Beacon Node API](./beacon_node_api.md) and
[Metrics](./metrics.md).

## When to use it

Use the embedded setup when Engine API latency matters, for example on nodes that propose blocks for
many validators, or that serve block building and other latency-sensitive workloads, and when you run
Nethermind as your execution client anyway.

Keep separate processes when you want to pair Grandine with a different execution client, when you
want to update or restart the two clients independently, or when you run them on separate machines.
The standard setup is described in [Connecting an execution client](./execution_client.md).

## Building it yourself

From the root of the Grandine repository:

```bash
# Build the Nethermind plugin (needs the .NET SDK)
make -B nethermind-plugin

# Download a Nethermind release and package it with Grandine for Linux x64
make -B grandine-nethermind-linux-x64 GRANDINE_VERSION=VERSION NETHERMIND_VERSION=NETHERMIND-VERSION
```

The other targets are `grandine-nethermind-linux-arm64`, `grandine-nethermind-windows-x64`,
`grandine-nethermind-macos-x64` and `grandine-nethermind-macos-arm64`. `make nethermind-docker` builds
the Docker images. See `bindings/csharp/README.md` in the repository for the details, and
[Building from source](./build_from_source.md) for the Grandine build itself.
