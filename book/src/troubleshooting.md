# Troubleshooting

This page is organized by area. Each entry starts with what you see (a symptom or a log message),
then explains the cause and the fix. Log messages are quoted as Grandine prints them; parts in CAPS
vary.

Before you dig in, check the basics:

- Run the latest release (`grandine --version`). See [Updating Grandine](./updating.md).
- Make sure the execution client is synced and reachable.
- Read the first error in the log, not the last one. Later errors are often consequences.

> **Note:** When the application fails at runtime, Grandine logs `application runtime failed: ...`
> and restarts itself inside the same process. A message that repeats every few seconds usually means
> the same startup error is happening on every restart.

## Starting Grandine

### `--OPTION must be specified after bn` (or `after vc`)

Options for `grandine bn` and `grandine vc` must come after the mode name. Change
`grandine --network hoodi bn` to `grandine bn --network hoodi`. See
[Command line reference](./cli_options.md#modes-and-where-options-go).

### `error: unexpected argument '--OPTION' found`

The option does not exist in this mode, or it is misspelled. Common cases:

- A beacon node option given to `grandine vc` (for example `--checkpoint-sync-url`, `--target-peers`,
  `--builder-url`), or a validator option given to `grandine bn` (for example `--keystore-dir`).
- Options from old guides that were renamed or removed (`--jwtsecret` instead of `--jwt-secret`,
  `--slashing-enabled`).

Run `grandine --help`, `grandine bn --help` or `grandine vc --help` to see the accepted options.

### `error: the argument '--A' cannot be used with '--B'`

The two options exclude each other. For example, `--back-sync` and `--archive-storage` cannot be used
with `--prune-storage`, and `--supernode` cannot be used with `--semi-supernode`. Remove one of them.

### `error: the following required arguments were not provided`

An option needs a companion. For example, `--keystore-dir` needs `--keystore-password-file` or
`--keystore-password-dir`, `--force-checkpoint-sync` needs `--checkpoint-sync-url`, `--disable-ipv4`
needs `--listen-address-ipv6`, and `grandine vc` needs `--beacon-node-urls`.

### `PORT_NAME port (PORT) is unavailable; make sure no other instance of the application is running or specify a different port with OPTION`

Another process already listens on that port. Often it is a second Grandine instance, or another
consensus client using the same defaults (`9000`, `5052`). Stop the other process, or choose another
port with the option named in the message. See [Default ports](./default_ports.md).

### `identical addresses specified for SERVICE1 and SERVICE2`

Two of Grandine's APIs (HTTP API, metrics, validator API) are set to the same address and port.
Give each a different port.

### `expected schema version compatible with 0.2.0, found VERSION` or `expected application name "Grandine", found NAME`

The data directory contains a `meta.json` that Grandine cannot use: it was written by an incompatible
version, or the directory belongs to another program. Use a fresh `--data-dir`, or move the old one
away and sync again with [checkpoint sync](./checkpoint_sync.md).

### `PRESET preset is not included in this executable`

The network's `config.yaml` sets `PRESET_BASE: minimal`, but release binaries only include the
mainnet preset. Build a minimal-preset binary with `make minimal`. See
[Building from source](./build_from_source.md).

### `--configuration-file must be specified when connecting to custom network`

`--network custom` needs the network's configuration. Pass `--configuration-directory` or
`--configuration-file`. See [Configuration files and custom networks](./configuration_files.md).

## Beacon node

### `skipping checkpoint sync: existing database found; pass --force-checkpoint-sync to force checkpoint sync`

`--checkpoint-sync-url` is only used when the database is empty. On later restarts Grandine continues
from its own database, and this warning is normal. To start over from a new checkpoint, add
`--force-checkpoint-sync` for one run.

### `checkpoint sync failed`

Grandine could not load a finalized checkpoint from `--checkpoint-sync-url`. The reason follows in the
same message, for example:

- `remote beacon node has no finalized block`: the remote node is not synced, or it is on another
  network.
- `remote beacon node does not have post-state of block ROOT` or `remote beacon node has no block
  usable as anchor`: the remote node does not serve the needed state. Use another provider.
- A connection or timeout error: check the URL, and raise `--request-timeout` if the provider is slow.

> **Warning:** Without `--force-checkpoint-sync`, a failed checkpoint sync is only a warning, and
> Grandine falls back to syncing from genesis, which takes much longer. If you see this message on a
> fresh node, stop Grandine, fix the URL, and start it again.

### `too many empty slots after state: SLOT + MAX_EMPTY_SLOTS < SLOT`

A block or attestation refers to a state so old that Grandine would have to process more than
`--max-empty-slots` (default `32`) empty slots to use it. This happens on networks with many missed
slots, such as a devnet in trouble or long non-finality. On a healthy network these messages are
harmless and come from peers sending stale data. On an unhealthy network you can raise
`--max-empty-slots` at the cost of more CPU work.

### `application runtime failed: ...` followed by `increasing environment map size limits`

The database reached its size limit (`--database-size`, default `1 TiB`, or `--eth1-database-size`,
default `16 GiB`). Grandine restarts with the limits doubled and logs the new ones
(`Eth2 database upper limit: ...`). This is automatic, but to avoid the restart, set a larger
`--database-size` when you run an archive node. Also check that the disk has free space.

### High memory use

Grandine keeps unfinalized states in memory with structural sharing. Memory use stays low while the
network finalizes and grows during long periods of non-finality. To cap it, lower
`--unfinalized-states-in-memory` (default `128`, minimum two epochs of slots) and
`--max-epochs-to-retain-states-in-cache` (default `8`). See
[Performance and memory tuning](./performance_tuning.md).

### `--unfinalized-states-in-memory must be at least MINIMUM`

The value is below two epochs of slots (`64` on mainnet presets). Raise it.

### The node uses much more disk than expected

Check the storage mode. `--archive-storage` keeps all blocks, blobs and periodic states, and
`--back-sync` downloads history. For a staking node, the default mode is enough. `--prune-storage` uses less disk but is not for
production use, because it does not keep data for the period the specification requires.
See [Storage and database](./storage.md) and [Back-sync and archive nodes](./historical_data.md).

### `unknown configuration variables: [...]`

The chain configuration has fields Grandine does not know. For a devnet that adds fields for a future
fork, this is expected. On a public network, it can mean that your Grandine version is too old for an
upcoming fork. Update Grandine.

## Execution client

### `JWT secret must be at least 32 bytes` or `failed to parse JWT secret`

The file given with `--jwt-secret` is not a valid hex-encoded secret of at least 32 bytes. It must
contain at least 64 hex characters (an optional `0x` prefix and a trailing newline are fine). Generate one with:

```bash
openssl rand -hex 32 | tr -d "\n" > /path/to/jwt.hex
```

Give the same file to the execution client.

### `Eth1 RPC endpoint URL returned an error: ERROR; switching to URL` or `last available Eth1 RPC endpoint URL returned an error: ERROR`

Grandine could not talk to the execution client. Check, in order:

1. The execution client is running and the URL host and port are right. Grandine needs the
   **authenticated Engine API** port (usually `8551`), not the public JSON-RPC port (usually `8545`).
2. Both clients use the same JWT secret file. An authentication error (HTTP 401) means they do not.
3. The clocks of both machines are synced (JWT tokens are time-limited). Run an NTP client such as
   `chrony` or `systemd-timesyncd`.
4. In Docker, `localhost` inside the Grandine container is the container itself. Use the execution
   client's service name or host address.

When you list several URLs in `--eth1-rpc-urls`, Grandine moves to the next one on errors.

### `engine_newPayload returned SYNCING status` or `engine_forkchoiceUpdated returned SYNCING status`

The execution client is still syncing. This is normal while it catches up, and Grandine follows the
chain optimistically in the meantime. If it does not go away after the execution client reports that
it is synced, check the execution client's logs.

### `validator cannot perform its duties because chain head has not been fully verified by an execution engine`

The head block is optimistic: the execution client has not validated its payload yet, usually because
it is still syncing. Validators cannot attest or propose on an unverified head. Wait for the execution
client to finish syncing.

### `engine_newPayload returned INVALID status` or `engine_forkchoiceUpdated returned INVALID status`

The execution client rejected a payload. One rejected block on the network is not your problem. If it
repeats for the canonical chain, your execution client may be on an old version or have a corrupted
database. Update it, and report the issue if it persists.

### `--eth1-rpc-urls must be specified when validators are present`

Validators attached to the built-in beacon node need an execution client to propose blocks. Add
`--eth1-rpc-urls` and `--jwt-secret`.

## Networking

### Few or no peers

Grandine aims for `--target-peers` (default `200`) peers. If it stays far below:

1. Make sure the P2P ports are open: TCP `9000`, UDP `9000`, and UDP `9001` for QUIC (more if you use
   IPv6). Forward them on your router, or open them in the firewall. See
   [Default ports](./default_ports.md).
2. If UPnP fails (see the next entry), set port forwarding by hand and add `--disable-upnp`.
3. Behind NAT with a static public address, advertise it with `--enr-address`.
4. Check that the system clock is correct.
5. Check `--boot-nodes` if you set it: a wrong list replaces the built-in one.

See [Networking and peers](./networking.md).

### `error while initializing UPnP: ...`

Your router does not support UPnP or has it turned off. This is harmless if you forward the ports by
hand. Add `--disable-upnp` to silence it.

### `UPnP enabled with manual ENR settings: OPTIONS; manual ENR settings might be overridden by UPnP`

You set ENR addresses or ports, and UPnP may replace them. If you configured the ENR on purpose, add
`--disable-upnp`.

### No peers on a local devnet

Discovery ignores peers with private IP addresses by default. Add `--enable-private-discovery`. See
[Configuration files and custom networks](./configuration_files.md#devnets).

## Validator

### `failed to load validator keys`

Grandine was told to load keys but loaded none. Check that `--keystore-dir` contains EIP-2335
keystore files and that the passwords match. With `--keystore-password-dir`, each keystore
`NAME.json` needs a password file `NAME.txt`. Errors such as `unable to load validator keys` or
`unable to discover validator keystores` give the reason. See [Managing validator keys](./key_management.md).

### `Doppelganger validators detected on the network (public keys: [...])`

Doppelganger protection saw your validators active on the network while this instance was not signing.
The same keys are probably running somewhere else. Grandine stops and does not restart itself.
**Do not** simply restart it with protection turned off. Find and stop the other instance first. See
[Doppelganger protection](./doppelganger_protection.md).

### `Doppelganger protection prevented validator PUBKEY from signing a message since not enough time has passed to ensure there are no duplicate validators participating on network`

This is expected for the first epochs after starting with `--detect-doppelgangers`. The validators
start signing once the check passes.

### `--track-liveness must be specified for --detect-doppelgangers with the built-in beacon node`

With the built-in beacon node, doppelganger protection needs liveness tracking. Add `--track-liveness`.

### `slashing protector rejected slashable attestation` or `slashing protector rejected slashable beacon block`

Slashing protection refused to sign a message that conflicts with one already signed. Possible causes:

- The same keys run in another client or machine. Stop it now.
- You restored or imported an older slashing protection database, or imported keys without their
  slashing protection history.
- After moving validators from another client, a few rejections in the first epochs can happen if
  the history was imported correctly; they stop once new duties start.

Never delete the slashing protection database to get rid of this message. See
[Slashing protection](./slashing_protection.md).

### `Web3Signer at URL did not return any validator keys. It will retry to fetch keys again in the next epoch.`

Web3Signer is reachable but serves no keys. Check its key configuration, and that the URL points to the
right Web3Signer instance. See [Web3Signer](./web3signer.md).

### `grandine vc`: `no beacon node given with --beacon-node-urls reported genesis; retrying in 2 s`

The separate validator client cannot reach any beacon node. Check the URLs, that the beacon nodes'
HTTP API listens on an address the validator client can reach (`--http-address`), and firewalls.

### `grandine vc`: `beacon nodes given with --beacon-node-urls are on a chain with genesis validators root ROOT where ROOT was expected`

The beacon nodes are on another network than the validator client. Give the validator client the same
`--network` (or configuration) as the beacon nodes. A related warning is
`beacon node at URL is on a different network`.

### `grandine vc`: `no remote beacon node is fully synced`

None of the beacon nodes is synced, so duties cannot be performed reliably. Wait for them to sync, or
add another beacon node. See [Redundancy and fallback beacon nodes](./redundancy.md).

### Missed attestations

Occasional misses are normal. If they are frequent:

- Check peers, CPU load and disk latency on the beacon node.
- Check that the system clock is synced.
- Check that the execution client is synced and responds quickly.

See [Monitoring validator performance](./validator_monitoring.md).

## Docker

### The data is gone after recreating the container

Grandine stores data in `/root/.grandine` inside the container. Mount a volume there:
`-v $HOME/.grandine:/root/.grandine`. Without it, every new container starts from scratch.

### The API is not reachable from the host or other containers

The HTTP API listens on `127.0.0.1` by default, which inside a container means the container only.
Add `--http-address 0.0.0.0` and publish the port with `-p 127.0.0.1:5052:5052`. The same applies to
`--metrics-address` and `--validator-api-address`.

### Grandine cannot reach the execution client

Inside a container, `localhost` is the container. Put both containers on the same Docker network and
use the execution client's service name, for example `--eth1-rpc-urls http://geth:8551`.

### `Permission denied` on mounted files

The image runs Grandine as `root`. If you run the container with `--user`, make sure that user can
read the JWT secret and keystores and can write to the data directory.

## Reporting a bug

If you cannot solve the problem, open an issue on
[GitHub](https://github.com/grandinetech/grandine/issues) or ask on Discord (see [Support](./support.md)).
A good report includes:

1. **The version.** Run `grandine --version`, or query a running node:

   ```bash
   curl -s http://127.0.0.1:5052/eth/v1/node/version
   ```

2. **How you run Grandine.** The full command line or `--args-file` contents, the network, and whether
   you use Docker, systemd, or something else. Remove secrets and passwords, but keep the flags.
3. **The execution client** and its version.
4. **Logs.** Include the startup messages and several minutes around the problem, not only the
   final error. Also attach `exception.log` from the data directory (`$HOME/.grandine/exception.log`
   by default) if it exists.
5. **System details.** Operating system, CPU, RAM, disk type, and free disk space.

### Getting more detailed logs

The `GRANDINE_LOG` environment variable adds log filter directives, using the `tracing` filter
syntax:

```bash
GRANDINE_LOG=debug grandine --network hoodi ...
GRANDINE_LOG=fork_choice_control=debug,p2p=debug grandine --network hoodi ...
```

You can also change the log level of a running node through the HTTP API (and the validator API of a
separate validator client) without restarting it:

```bash
curl -X POST http://127.0.0.1:5052/eth/v2/debug/tracing/log_level \
  -H 'Content-Type: application/json' \
  -d '{"target": "fork_choice_control", "level": "debug"}'
```

See [Logging](./logging.md).

### Debug tools

- `grandine export --from SLOT --to SLOT` writes blocks and states to SSZ files, which developers can
  use to reproduce a problem. See [Subcommands and tools](./subcommands.md).
- Runtime features can dump or log extra data, for example `--features DumpBeaconBlocks` or
  `--features LogBlockProcessingTime`. See [Runtime features](./runtime_features.md). Use them only
  while you investigate, since some write a lot of data.

## Command line options

- `--force-checkpoint-sync` (default disabled): checkpoint sync even when a database exists.
- `--request-timeout` (default `30000` ms): timeout for outgoing requests, including checkpoint sync.
- `--max-empty-slots` (default `32`): how many empty slots Grandine processes through for a block or attestation.
- `--database-size` (default `1 TiB`): beacon database size limit.
- `--unfinalized-states-in-memory` (default `128`): unfinalized states kept in memory.
- `--disable-upnp` (default disabled): turn off UPnP port mapping.
- `--enable-private-discovery` (default disabled): discover peers with private IP addresses.
- `--track-liveness` (default disabled): track liveness; needed for doppelganger protection with the built-in beacon node.
- `--http-address` (default `127.0.0.1`): Beacon Node API listen address.

See the [Command line reference](./cli_options.md) for all options.
