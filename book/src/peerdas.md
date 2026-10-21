# PeerDAS and blob data

Rollups publish their data to Ethereum as *blobs*. Blobs are not executed by the execution layer
and are kept only for a limited time, so the consensus layer is responsible for making sure they
were published and for serving them for that time. This is called data availability.

- From the Deneb fork, every beacon node downloaded and stored every blob as a *blob sidecar*.
- From the Fulu fork, Ethereum uses PeerDAS (Peer Data Availability Sampling, EIP-7594). Each blob
  is extended with erasure coding and split into 128 *data columns*. A node no longer downloads
  all blobs. It *custodies* a subset of the columns, stores them, and serves them to its peers.
  Because any half of the columns is enough to rebuild the rest, the network as a whole keeps all
  data available while each node handles only part of it.

Grandine supports both. Fulu is scheduled on all built-in networks, and when PeerDAS is scheduled,
Grandine logs the custody mode at startup, for example `custody mode: Minimal`.

## Custody

The columns are grouped into 128 custody groups. Which groups a node custodies follows from its node
ID, and the number it custodies is its *custody group count*. Grandine advertises the count in its
ENR and in its metadata, so peers know which columns to request from it.

Grandine has three custody modes:

| Mode | Option | Custody groups | Use it for |
|---|---|---|---|
| Minimal (default) | none | The protocol minimum (`CUSTODY_REQUIREMENT`, 4 on mainnet), raised by attached validators (see below). The node samples at least `SAMPLES_PER_SLOT` (8) groups. | Most nodes. |
| Semi-supernode | `--semi-supernode` | Half of all groups (64). | Nodes that serve blobs through the API with less bandwidth than a supernode. |
| Supernode | `--supernode` | All groups (128). | Nodes that serve blobs to rollups, explorers or other services, and archive nodes that want all data. |

The options have aliases that match other clients: `--subscribe-all-data-column-subnets` for
`--supernode`, and `--subscribe-half-data-column-subnets` for `--semi-supernode`. The two options
conflict with each other.

```bash
grandine \
  --network mainnet \
  --supernode \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

A supernode subscribes to every data column subnet and downloads and stores every column, so it
needs considerably more bandwidth and disk space than a node in the minimal mode. A semi-supernode
needs about half of that.

### Validator custody

The protocol asks nodes with validators to custody more. Grandine computes the requirement from the
total effective balance of the validators registered with the node: the keys of the built-in
validator client and the validators that validator clients, such as `grandine vc` or another
client's, announce to it through the Beacon Node API with `prepare_beacon_proposer` or
`register_validator`. Beacon committee subscriptions alone do not count:


```text
custody groups = max(VALIDATOR_CUSTODY_REQUIREMENT, total effective balance / BALANCE_PER_ADDITIONAL_CUSTODY_GROUP)
```

capped at 128. On mainnet, `VALIDATOR_CUSTODY_REQUIREMENT` is 8 and
`BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` is 32 ETH. So a node with up to 256 ETH of effective balance
custodies 8 groups, and a node with 4,096 ETH or more custodies all 128 groups, like a supernode.

Grandine re-checks the requirement once per epoch, from the last finalized state, and only ever
raises the custody group count. A supernode is already at the maximum and skips the check.

### Backfilling custody

When the custody group count goes up, the node is now responsible for columns it did not keep
before. Grandine then backfills those columns for the data availability window by requesting them
from peers, so it can serve them as the protocol expects. The log shows this as
`starting data column backfill (columns: {…}) from SLOT to SLOT slot`.

`--no-custody-groups-backfill` turns the backfill off. The node then custodies the new columns only
from the moment the count increased.

## Reconstruction

When a node has received at least half of the columns of a block, it can rebuild the missing ones.
Grandine does this automatically for nodes that custody at least half of the columns
(semi-supernodes, supernodes and nodes with large validator custody). It skips blocks it proposed
itself, and blocks whose columns all arrive before reconstruction starts. At the head, Grandine
imports the block as soon as it has half of the columns, without waiting for the reconstruction, and
then publishes the rebuilt columns to help the network. It always does so at the head; there is no
option to turn it off. Columns rebuilt while syncing are stored but not published.

- `--reconstruction-delay` (default: 250 ms) is how long Grandine waits after receiving enough
  columns of a gossiped block before it starts reconstructing, so that columns still arriving from
  the network are not computed needlessly. For blocks requested from peers, the wait is 2 seconds.
- While syncing, Grandine also reconstructs missing columns of older blocks when it has enough of
  them. `--sync-without-reconstruction` turns that off, which saves CPU during sync at the cost of
  fetching more columns from peers.

## Blobs from the execution client

The execution client often already has a block's blobs in its transaction pool. After the payload of
a new block is validated, Grandine asks the execution client for them with `engine_getBlobsV1`
(Deneb and Electra) or `engine_getBlobsV2` (Fulu), and uses what it gets instead of waiting for the
network. This speeds up block import, especially for nodes that custody many columns. It needs no
configuration; Grandine uses it whenever the execution client advertises support for these
methods.

## Retention

Blob sidecars and data column sidecars are kept for the data availability window:
`MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` and `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS`,
4,096 epochs (about 18 days) on mainnet. After that, Grandine deletes them.

| Storage mode | Sidecars |
|---|---|
| Standard (default) | Kept for the data availability window. |
| `--prune-storage` | Data columns are not written to disk. |
| `--archive-storage` | Kept forever. Combine with `--supernode` to keep every column. |

`--data-availability-window EPOCHS` changes the window in standard mode. It is intended for testing.
Setting it below the network default means your node cannot serve data that peers are entitled to
request. See [Storage and database](./storage.md).

## Serving blobs through the API

The Beacon Node API serves blob data on these routes:

- `GET /eth/v1/beacon/blob_sidecars/{block_id}`
- `GET /eth/v1/beacon/blobs/{block_id}`
- `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}`

For blocks from Fulu on, Grandine builds blobs and blob sidecars from the stored data columns. That
needs at least half of the columns, so only a supernode, a semi-supernode or a node whose validator
custody covers at least half of the groups can answer these requests. On a node in the minimal
mode, the blob routes return an empty list for Fulu blocks.

If you run rollup infrastructure or anything else that reads blobs from your beacon node, run it as
a supernode or semi-supernode. See [Beacon Node API](./beacon_node_api.md).

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--supernode` (alias `--subscribe-all-data-column-subnets`, default: off): custody all data
  columns.
- `--semi-supernode` (alias `--subscribe-half-data-column-subnets`, default: off): custody half of
  the data columns.
- `--no-custody-groups-backfill` (default: off): do not backfill columns when the custody group
  count increases.
- `--reconstruction-delay` (default: `250`): milliseconds to wait before reconstructing missing
  columns.
- `--sync-without-reconstruction` (default: off): do not reconstruct columns while syncing.
- `--data-availability-window` (default: network setting): epochs to keep sidecars. For testing.
- `--kzg-backend` (default: `blst`): cryptography library for KZG proofs.
- `--archive-storage` (default: off): keep sidecars forever.
- `--prune-storage` (default: off): do not keep data columns on disk.
