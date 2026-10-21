# Running a beacon node

The beacon node is the part of Grandine that follows the Ethereum consensus layer. It connects to
other nodes over the peer-to-peer network, downloads and verifies blocks, runs fork choice, drives an
execution client through the Engine API, and serves the [Beacon Node API](./beacon_node_api.md).
Validators, whether built in or remote, perform their duties through it.

This page explains how to start the beacon node, what it does while it starts, how to read its logs
while it syncs, and how it shuts down. For the bigger picture, see
[How Grandine works](./architecture.md).

## Ways to run Grandine

One binary covers three modes:

| Command | What runs |
|---|---|
| `grandine` | The beacon node together with the built-in validator client. The validator client has nothing to do until you give it keys. |
| `grandine bn` | Only the beacon node. |
| `grandine vc` | Only the validator client, connected to one or more remote beacon nodes. See [Validator client](./validator_client.md). |

If you do not run validators on this machine, `grandine` and `grandine bn` behave almost the same.
Use `grandine bn` when you want to make it explicit that the process must never load keys, for
example on a node that serves only an API or backs a separate validator client.

> **Note:** With `bn` and `vc`, every option goes after the subcommand. `grandine bn --network hoodi`
> works. `grandine --network hoodi bn` fails with `--network must be specified after bn`.

## Before you start

You need:

- An execution client (Geth, Nethermind, Besu, Erigon, Reth or another Engine API client) running
  on the same network. See [Connecting an execution client](./execution_client.md).
- A JWT secret file shared by both clients.
- A checkpoint sync URL, so the node does not have to sync from genesis. See
  [Checkpoint sync](./checkpoint_sync.md).
- Open peer-to-peer ports. See [Networking and peers](./networking.md).

Check the [System requirements](./hardware_requirements.md) before you start on mainnet. Practice
on the Hoodi testnet first.

## Start the beacon node

Mainnet:

```bash
grandine bn \
  --network mainnet \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL
```

Hoodi:

```bash
grandine bn \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL
```

`--network` defaults to `mainnet`. The other built-in networks are `sepolia`, `holesky` and
`hoodi`. `custom` connects to a network defined by your own configuration files (see
[Configuration files and custom networks](./configuration_files.md)).

With Docker, the image's entrypoint is `grandine`, so the arguments follow the image name. The data
directory inside the container is `/root/.grandine`:

```bash
docker run -d --name grandine \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -v /path/to/grandine-data:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  bn \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL \
  --http-address 0.0.0.0
```

> **Warning:** `--http-address 0.0.0.0` makes the Beacon Node API listen on every interface of the
> container. Publish port 5052 only to hosts you trust. See [Security best practices](./security.md).

To run Grandine as a long-lived service, see
[Running as a service](./running_as_a_service.md).

## Keeping options in a file

`--args-file` loads options from a YAML file. Keys are the long option names without the leading
dashes:

```yaml
network: mainnet
eth1-rpc-urls:
  - http://127.0.0.1:8551
jwt-secret: /path/to/jwt.hex
checkpoint-sync-url: CHECKPOINT-SYNC-URL
```

```bash
grandine bn --args-file /path/to/grandine.yaml
```

Options given on the command line take precedence over the same options in the file.

## What happens at startup

When the beacon node starts, it goes through these steps. Each step logs a line at the `INFO`
level, so you can follow them in the output.

1. **Configuration report.** Grandine logs the client version (`client version: ...`), followed by
   the network, the data directory, the storage mode, the database size limits, the Eth1 RPC URLs,
   the HTTP API address and whether back-sync is enabled.
2. **Port check.** Grandine checks that its TCP and UDP ports are free before it binds them. If one
   is taken, it exits with an error such as `libp2p port (9000) is unavailable; make sure no other
   instance of the application is running or specify a different port with --libp2p-port`.
3. **Data directory.** Grandine creates the data directory if needed and records the database schema
   version in `meta.json` (`initialized data directory with schema version ...`). See
   [Storage and database](./storage.md).
4. **Validator keys.** In the combined mode, Grandine loads any validator keys you passed. If it
   finds keys but no `--eth1-rpc-urls`, it stops with `--eth1-rpc-urls must be specified when
   validators are present`.
5. **Genesis.** Grandine needs the genesis state of the network. It is built into the binary for
   mainnet. For Sepolia, Holesky and Hoodi, Grandine downloads it on the first run
   (`downloading genesis state from ...`) and saves it as `genesis_state.ssz` in the beacon
   directory, so later starts load it from disk.
6. **Anchor state.** Grandine picks the state to start from:
   - If the database already holds a finalized state, it loads it (`loaded state at slot N`).
   - Otherwise, if you passed `--checkpoint-sync-url`, it downloads a recent finalized block and
     state (`performing checkpoint sync from ...`, then `loaded state at slot N from ...`).
   - Otherwise, it starts from genesis.
7. **Services.** Grandine starts the execution client connection (`updated capabilities for eth1
   endpoint: ...`), the peer-to-peer stack (`Libp2p Starting`, `ENR Initialised`, `Listening
   established`), the HTTP API (`HTTP server listening on 127.0.0.1:5052`), the operation pools and
   the sync service.
8. **Sync.** The node requests blocks from peers and imports them until it reaches the head of the
   chain.

## Reading the logs

Each log line starts with a timestamp, the level and the module that emitted it. Most lines end with
a `peers=[CONNECTED/TARGET]` field: the number of connected peers and the `--target-peers` value. A
node that shows `peers=[0/200]` for minutes cannot sync. See [Networking and peers](./networking.md).

### While syncing

Grandine logs a line for every block it imports, with the number of blobs in the block. Shown here
without the timestamp prefix:

```text
imported beacon block with 7 blobs (slot: 12345678, 0x5c1e…a9f2) peers=[87/200]
imported beacon block with 0 blobs (slot: 12345679, 0x8b07…41d3) peers=[87/200]
```

Watch the `slot` value. It grows quickly while the node catches up and then advances by one slot
every 12 seconds once the node is at the head. To also log how long each block takes to process,
start Grandine with `--features LogBlockProcessingTime`; see [Runtime features](./runtime_features.md).

While the execution client is still syncing, Grandine imports blocks before the execution client
has confirmed their payloads. The head is then *optimistic*, which the sync status shows as
`"is_optimistic": true` (see [below](#checking-sync-status-through-the-api)). This is normal until
the execution client catches up. See [Optimistic sync](./execution_client.md#optimistic-sync).

On each new finalized epoch, Grandine logs:

```text
new finalized checkpoint (epoch: 385802, root: 0x…, head slot: 12345700, head root: 0x…)
```

As the node syncs, it periodically writes finalized data to disk (`saving checkpoint block & state
in slot N`, `saving state in slot N`).

### Checking sync status through the API

Grandine does not print a periodic sync summary. To check the status at any time, ask the Beacon
Node API:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/syncing
```

```json
{"data":{"head_slot":"12345700","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}
```

- `is_syncing: false` and `sync_distance: 0` mean the node is at the head.
- `is_optimistic: true` means the execution client has not yet verified the head. The node is not
  ready for validator duties.
- `el_offline: true` means no execution client endpoint is answering.

`/eth/v1/node/health` returns HTTP 200 when the node is synced and 206 while it is syncing, which is
convenient for load balancers and monitoring:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5052/eth/v1/node/health
```

For long-term monitoring, see [Metrics](./metrics.md) and [Logging](./logging.md).

### Warnings worth acting on

| Message | Meaning |
|---|---|
| `skipping checkpoint sync: existing database found; pass --force-checkpoint-sync to force checkpoint sync` | The node resumed from its own database and ignored `--checkpoint-sync-url`. This is the expected behavior on a restart. |
| `checkpoint sync failed` followed by an error | The download failed and the node fell back to its database or to genesis. See [Checkpoint sync](./checkpoint_sync.md). |
| `Eth1 RPC endpoint ... returned an error: ...; switching to ...` | The primary execution client did not answer. Grandine moved to the next URL. |
| `engine_newPayload returned SYNCING status` | The execution client is still syncing. Blocks are imported optimistically. |
| `UPnP enabled with manual ENR settings: ...` | You set ENR options while UPnP is on. UPnP might override them. |

See [Troubleshooting](./troubleshooting.md) for more.

## Automatic restarts

If the beacon node stops with an error or panics, Grandine logs `application runtime failed` (or
`application runtime panicked`) and restarts its runtime inside the same process, without exiting.
When the error is a full database (`MapFull`), Grandine first doubles the database size limits
(`increasing environment map size limits`). A few errors end the process instead, such as
doppelgangers detected by [doppelganger protection](./doppelganger_protection.md).

To make Grandine exit on the first error instead, for example so that systemd or Docker restarts it,
enable the `InhibitApplicationRestart` [runtime feature](./runtime_features.md):

```bash
grandine bn --features InhibitApplicationRestart ...
```

## Shutting down

Grandine stops cleanly on `SIGINT` (Ctrl+C) and `SIGTERM` (sent by `systemctl stop` and
`docker stop`). It then:

1. stops the slot clock and the services,
2. logs `saving current chain before exit…`,
3. writes the finalized chain and the unfinalized blocks of the canonical chain to the database, and
   logs `chain saved (finalized blocks: N, unfinalized blocks: M)`.

Most of the shutdown time goes into this last step: Grandine writes the blocks not yet in the
database and, usually, a finalized checkpoint state, in one database transaction. It takes longer when
the chain has not finalized for a long time and many blocks are waiting to be written.

On the next start, Grandine resumes from the saved state and only has to sync the slots it missed.

> **Warning:** Do not stop Grandine with `SIGKILL` (`kill -9`) unless it hangs. A killed node loses
> the unfinalized part of the chain and has to fetch it again. Give the service enough time to stop:
> `docker stop` waits only 10 seconds by default, so use `docker stop -t 120 grandine` or set
> `stop_grace_period` in Docker Compose. 120 seconds is a generous allowance, not a measured
> shutdown time; allow more after a long period without finality.
<!-- TODO(verify): needs a measured Mainnet shutdown time, with and without a long period of non-finality. 120 seconds is a conservative bound, not a measured value. -->

## Command line options

The most important beacon node options. See [Command line reference](./cli_options.md) for the full
list.

- `--network` (default: `mainnet`): network to join: `mainnet`, `sepolia`, `holesky`, `hoodi` or
  `custom`.
- `--data-dir` (default: `$HOME/.grandine`): parent directory for all data. Grandine adds the
  network name below it.
- `--eth1-rpc-urls` (default: none): Engine API URLs of your execution clients.
- `--jwt-secret` (default: none): path to the JWT secret shared with the execution client.
- `--checkpoint-sync-url` (default: none): Beacon Node API URL to checkpoint sync from.
- `--args-file` (default: none): load options from a YAML file.
- `--http-address` (default: `127.0.0.1`): Beacon Node API listen address.
- `--http-port` (default: `5052`): Beacon Node API port.
- `--disable-http-api` (default: off): run without the Beacon Node API.
- `--target-peers` (default: `200`): number of peers to aim for.
- `--features` (default: none): comma-separated [runtime features](./runtime_features.md).
- `--in-memory` (default: off): keep everything in memory and write nothing to disk. All data is lost
  on exit.
