# Frequently asked questions

Short answers to common questions, with links to the pages that cover each topic in depth. For error
messages, see [Troubleshooting](./troubleshooting.md).

## General

### What is Grandine?

Grandine is an Ethereum consensus client written in Rust. One binary contains a beacon node and a
validator client. You can run both in one process, or each on its own. See
[How Grandine works](./architecture.md).

### Which networks does Grandine support?

Mainnet, Sepolia, Holesky and Hoodi are built in (`--network mainnet`, `sepolia`, `holesky`, `hoodi`).
Holesky has reached its end of life; use Hoodi or Sepolia instead.
Other networks and devnets work with `--network custom` and their configuration files. See
[Supported networks](./networks.md) and [Configuration files and custom networks](./configuration_files.md).

### How do I check which version I run?

```bash
grandine --version
```

For a running node, query the Beacon Node API:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/version
```

### Where does Grandine keep its data?

In `$HOME/.grandine/NETWORK` by default, for example `$HOME/.grandine/mainnet`. `--data-dir` changes
the parent directory; the network name is always appended. See [Default ports and paths](./default_ports.md#paths).

### Does Grandine have a configuration file?

Yes. `--args-file FILE` loads command line options from a YAML file whose keys are option names. The
command line overrides the file. See
[Configuration files](./configuration_files.md#keeping-command-line-options-in-a-file).

### Which platforms are supported?

Release binaries are built for Linux (x86-64 and ARM64), macOS (x86-64 and ARM64) and Windows
(x86-64). The Docker image `sifrai/grandine` is available for `linux/amd64` and `linux/arm64`. See
[Pre-built binaries and Docker](./downloads.md).

### Has Grandine been audited?

Yes. The reports are in the [`audit` directory](https://github.com/grandinetech/grandine/tree/develop/audit)
of the repository: a security review by Matter Labs (November 2024) and a code review by X41 D-Sec
(November 2024). See [Security best practices](./security.md).

## Beacon node

### Do I need an execution client?

Yes, for any real use. Grandine talks to it through the Engine API (`--eth1-rpc-urls` and
`--jwt-secret`). Validators attached to the built-in beacon node do not start without one
(`--eth1-rpc-urls must be specified when validators are present`). See
[Connecting an execution client](./execution_client.md).

### How long does syncing take?

With [checkpoint sync](./checkpoint_sync.md) (`--checkpoint-sync-url`), the beacon node follows the
head within minutes. The execution client usually takes much longer. Syncing from genesis, or with
`--back-sync` and `--archive-storage`, takes days. <!-- TODO(verify): needs measured Mainnet times for checkpoint sync, genesis sync and back-sync with --archive-storage. Nothing current is published; the only measurement (MigaLabs, arXiv:2311.05252: about 50 hours from genesis) used Grandine 0.2.0 before the Merge. -->

### What is the difference between `grandine` and `grandine bn`?

`grandine` runs the beacon node and, if you give it validator keys, the validator client in the same
process. `grandine bn` runs only the beacon node and refuses validator options. Use `bn` when your
validators run in a separate `grandine vc` or another validator client. See
[Running a beacon node](./beacon_node.md).

### Why does memory use grow?

Grandine keeps unfinalized states in memory. When the network does not finalize for a long time,
there are more of them. Limit this with `--unfinalized-states-in-memory`. See
[Performance and memory tuning](./performance_tuning.md).

### How do I resync from scratch?

Stop Grandine and start it once with `--force-checkpoint-sync` and `--checkpoint-sync-url`. To delete
the beacon databases instead, use `--force-reset-beacon-db`. Neither touches the slashing protection
database or your keys.

### How much disk space do I need?

It depends on the storage mode: pruned (`--prune-storage`), default, or archive
(`--archive-storage`). See [System requirements](./hardware_requirements.md) and
[Storage and database](./storage.md).

## Validator

### Can the beacon node and validators run in one process?

Yes, and this is the simplest setup. Pass `--keystore-dir` and `--keystore-password-file` (or
`--keystore-password-dir`) to `grandine`. See [Validator client](./validator_client.md).

### Can one validator client use several beacon nodes?

Yes, with `grandine vc --beacon-node-urls URL1,URL2`. Duties go to the healthiest node, and by default
everything is published to every node. See [Redundancy and fallback beacon nodes](./redundancy.md).

> **Warning:** Never run the same validator keys in two validator clients at once. That is how
> validators get slashed.

### My validator is not attesting. Is something wrong?

First check that the validator is active on the beacon chain. A new deposit waits in the activation
queue before the validator gets duties. Then check that Grandine logs `loaded N validator key(s)` at
startup and that the execution client is synced. See
[Monitoring validator performance](./validator_monitoring.md).

### How do I move validators to Grandine from another client?

Stop the old validator client, export its slashing protection data, import it with
`grandine interchange import FILE`, import the keys, and start Grandine. See
[Migrating from another client](./migration.md).

### Does Grandine include a slasher?

The code contains one, but it is currently disabled and cannot be turned on from the command line.
See [Slasher](./slasher.md).

### Where do I set the fee recipient?

`--suggested-fee-recipient` sets the default; `validators.yml` or the Keymanager API set it per
validator. See [Fee recipient, graffiti and gas limit](./fee_recipient.md).

## Networking

### Which ports do I need to open?

TCP `9000` and UDP `9000` for libp2p and discovery, and UDP `9001` for QUIC. With IPv6, also TCP
`9050`, UDP `9050` and UDP `9051`. Keep the API ports (`5052`, `5054`, `5055`) closed to the internet.
See [Default ports and paths](./default_ports.md).

### Why do I have so few peers?

Usually because the P2P ports are not reachable from the internet. Forward them or check the
firewall. See [Networking and peers](./networking.md) and
[Troubleshooting](./troubleshooting.md#few-or-no-peers).

### My public IP address changed. What do I do?

Nothing, in most cases. Grandine updates the address in its ENR automatically from what peers report.
If you set `--enr-address` by hand, or used `--disable-enr-auto-update`, update the flag and restart.

### Does Grandine support IPv6?

Yes. Add `--listen-address-ipv6 ADDRESS` to listen on IPv4 and IPv6, or also `--disable-ipv4` for
IPv6 only. See [Networking and peers](./networking.md).
