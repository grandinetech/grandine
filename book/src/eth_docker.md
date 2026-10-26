# Running with Eth Docker

[Eth Docker](https://ethdocker.com/) is a Docker Compose setup for Ethereum nodes, maintained by
EthStaker. It supports Grandine in every mode Grandine offers: as a standalone beacon node or
embedded in Nethermind, with the integrated validator client, with a separate `grandine vc`, or as a
validator client on its own.

Eth Docker is the recommended way to deploy Grandine for most regular use cases, such as a solo
staking node or a node that serves your own applications. It sets up the execution client, Grandine,
MEV-Boost and key management together, and keeps them updated with one command. Run Grandine directly
only when you need a setup that Eth Docker does not cover.

> **Note:** Support for the separate `grandine vc` (`grandine.yml`, `grandine-vc-only.yml`,
> `grandine-plugin-cl-only.yml`, the separate validator client in `grandine-plugin.yml`, and every
> combination that includes `grandine-vc-only.yml` or `grandine-plugin-cl-only.yml`) comes from
> [eth-docker#2832](https://github.com/ethstaker/eth-docker/pull/2832), which is not merged yet.
> Released Eth Docker versions offer `grandine-allin1.yml`, `grandine-cl-only.yml`,
> `grandine-plugin-allin1.yml`, and `grandine-plugin.yml` as a beacon node without a validator client.

<!-- TODO(verify): replace the note above with the first Eth Docker release that includes https://github.com/ethstaker/eth-docker/pull/2832 once it ships (still an open draft on 2026-10-21; latest release v26.10.0). -->

## Choose a mode

Eth Docker picks the clients from the Compose files listed in `COMPOSE_FILE` in its `.env` file,
separated by `:`. Each Grandine mode has its own file, and you combine it with the files of the other
clients. In the table, `<el>.yml` stands for the Compose file of any execution client, for example
`nethermind.yml`, `geth.yml` or `reth.yml`, and `<cl>-cl-only.yml` and `<vc>-vc-only.yml` for the
files of another consensus or validator client, for example `lighthouse-cl-only.yml` or
`teku-vc-only.yml`:

| `COMPOSE_FILE` | Setup |
| --- | --- |
| `nethermind.yml:grandine-plugin-allin1.yml` | Grandine beacon node and validator client integrated in Nethermind. One process runs the execution client, the beacon node and the validator client, which gives the best performance and the fewest moving parts. The validator keys live in the same process as the node. |
| `nethermind.yml:grandine-plugin.yml` (the same as `nethermind.yml:grandine-plugin-cl-only.yml:grandine-vc-only.yml`) | Grandine beacon node integrated in Nethermind for the best performance, and a separate `grandine vc` process for stronger protection of the keys. Two processes. |
| `nethermind.yml:grandine-plugin-cl-only.yml` | Grandine beacon node integrated in Nethermind, without validators. For a node that serves your own applications, or validator clients on other machines. One process. |
| `nethermind.yml:grandine-plugin-cl-only.yml:<vc>-vc-only.yml` | Grandine beacon node integrated in Nethermind, with another client's validator client. |
| `<el>.yml:grandine-allin1.yml` | Standalone Grandine with the integrated validator client, with any execution client. The simplest setup with a free choice of the execution client. Two processes: the execution client, and `grandine` with the beacon node and validator client. |
| `<el>.yml:grandine.yml` (the same as `<el>.yml:grandine-cl-only.yml:grandine-vc-only.yml`) | Standalone Grandine beacon node and a separate `grandine vc`, with any execution client. The keys are kept apart from the node. Three processes: the execution client, `grandine bn` and `grandine vc`. |
| `<el>.yml:grandine-cl-only.yml` | Standalone Grandine beacon node without validators, with any execution client. For a node that serves your own applications, or validator clients on other machines. Two processes: the execution client and `grandine bn`. |
| `<el>.yml:grandine-cl-only.yml:<vc>-vc-only.yml` | Standalone Grandine beacon node with another client's validator client. |
| `<el>.yml:<cl>-cl-only.yml:grandine-vc-only.yml` | `grandine vc` with another client's beacon node. |
| `grandine-vc-only.yml` | `grandine vc` alone, against beacon nodes on other machines given in `CL_NODE`. Keeps the keys on a machine that runs no node, or uses several beacon nodes for [redundancy](./redundancy.md). One process. |

`grandine-plugin*.yml` files run Grandine inside Nethermind, so they go only with `nethermind.yml`,
and there is no separate consensus container. With them, a separate validator client finds the Beacon
Node API in the Nethermind container: set `CL_NODE=http://execution:5052`.

Add other Eth Docker files as usual, for example `mev-boost.yml` for MEV-Boost or `web3signer.yml`
for [Web3Signer](./web3signer.md). See
[How Grandine works](./architecture.md#integrated-or-separate-validator-client) for the differences
between the integrated and the separate validator client, and
[Grandine embedded in Nethermind](./nethermind_integration.md) for the embedded setup.

## Set up

Install Eth Docker and run its configuration wizard:

```bash
git clone https://github.com/ethstaker/eth-docker.git
cd eth-docker
./ethd install
./ethd config
```

The wizard asks for the network, the clients and the fee recipient, and writes them to `.env`. Choose
Grandine as the consensus client, or as the validator client for a validator-only setup.

For a mode that the wizard does not offer, such as the Nethermind plugin files, set `COMPOSE_FILE`
in `.env` yourself, for example:

```bash
COMPOSE_FILE=nethermind.yml:grandine-plugin.yml
```

Start the node and follow the logs:

```bash
./ethd up
./ethd logs -f consensus
```

With the plugin files, Grandine logs as part of the `execution` service.

## Storage mode

`CL_NODE_TYPE` in `.env` selects the [storage mode](./storage.md):

| `CL_NODE_TYPE` | Grandine options | Result |
| --- | --- | --- |
| `pruned` (default) | none | Standard mode. Blocks and states of roughly the last five months. |
| `full` | `--back-sync` | Standard mode, with the history before the checkpoint downloaded back to the start of that window. |
| `archive` | `--back-sync --archive-storage` | Archive mode, back to genesis. Nothing is pruned, including blob data. |
| `aggressive-pruned` | `--prune-storage` | Prune mode. Not for production use: it does not keep data for the period the specification requires. |

Eth Docker's `blob-archive` node type is not supported for Grandine, and is not needed. For other
clients, `archive` still prunes blob data and `blob-archive` keeps it. Grandine in archive mode never
prunes blob sidecars or data columns, so for Grandine `archive` already keeps all blob data. Two limits apply to every client:

- Peers serve blob data only for the data availability window of about 18 days, so the node keeps
  blob data from about 18 days before it started onwards. Older blob data cannot be back-synced.
- After PeerDAS, a node stores only the data columns it custodies. To keep all blob data, also run
  it as a [supernode](./peerdas.md) with `CL_EXTRAS=--supernode`.

Changing the node type usually requires a resync. See
[Back-sync and archive nodes](./historical_data.md).

## Validator keys

Import keys with:

```bash
./ethd keys import
```

Eth Docker imports them through the [Keymanager API](./keymanager_api.md) of the validator client:
the beacon node in the integrated modes, and `grandine vc` in the separate ones. `./ethd keys list`
shows the loaded keys. Grandine writes each imported keystore to its own file in the validator
directory, with its password in a plain file under `secrets/`. The wallet password that Eth Docker
generates (`./ethd get-grandine-wallet` prints it) only unlocks keys that older Grandine versions kept
in the legacy `keystores.json` storage. See [Managing validator keys](./key_management.md).

`DOPPELGANGER=true` enables [doppelganger protection](./doppelganger_protection.md),
`WEB3SIGNER=true` uses [Web3Signer](./web3signer.md) for the keys, and `GRAFFITI` sets the graffiti.

### Switching modes

The validator keys and slashing protection data live in a Docker volume that depends on where the
validator client runs:

- The integrated validator client (`grandine-allin1.yml`, `grandine-plugin-allin1.yml`) keeps them
  in the beacon node's volume.
- The separate validator client (`grandine.yml`, `grandine-plugin.yml`, `grandine-vc-only.yml`)
  keeps them in its own volume.

Switching between files of the same group keeps the validator data, so you do not need to import the
keys again. Switching between the groups, for example from `grandine-allin1.yml` to `grandine.yml`,
starts the new validator client with no keys. Move them like this:

1. Run `./ethd keys delete all`. This removes the keys from the old validator client and exports
   their slashing protection data to `.eth/validator_keys`.
2. Change `COMPOSE_FILE` and run `./ethd up`.
3. Put the keystore files into `.eth/validator_keys` next to the exported slashing protection data,
   and run `./ethd keys import`.

Eth Docker recommends treating this like a move to another machine, with about 15 minutes of
downtime. Never run the same keys in two validator clients at once. See
[Slashing protection](./slashing_protection.md).

## Extra options

`CL_EXTRAS` passes extra options to the beacon node, and `VC_EXTRAS` to the validator client. For
example:

```bash
CL_EXTRAS=--target-peers 100
VC_EXTRAS=--publish-to-every-node attestations,blocks
```

See the [Command line reference](./cli_options.md) for the options, and
[Redundancy and fallback beacon nodes](./redundancy.md) for a validator client that uses several
beacon nodes, set as a comma-separated list in `CL_NODE`.

## Updating

```bash
./ethd update
./ethd up
```

This updates Eth Docker and the client images. See [Updating Grandine](./updating.md) for what to
check before you update.
