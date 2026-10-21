# Back-sync and archive nodes

A beacon node that was started with [checkpoint sync](./checkpoint_sync.md) knows the chain only from
its checkpoint onwards. That is all a staking node needs. Some uses need more history:

- serving old blocks to block explorers, indexers or researchers,
- answering Beacon API queries for old states, for example balances at a past epoch,
- serving historical blocks to peers that sync from genesis.

Grandine covers these with two settings: the storage mode, which decides what the node keeps, and
back-sync, which downloads the history that came before the checkpoint.

## What the node keeps

| Storage mode | Option | Blocks | States | Blob and data column sidecars |
|---|---|---|---|---|
| Prune | `--prune-storage` | Only the latest checkpoint block. | Only the latest checkpoint state. | Kept in memory only, not written to disk. |
| Standard (default) | none | Finalized blocks of roughly the last five months (`MIN_EPOCHS_FOR_BLOCK_REQUESTS`). | One state every `--archival-epoch-interval` epochs within that window, plus the latest checkpoint state. | The data availability window, 4,096 epochs (about 18 days) on mainnet. |
| Archive | `--archive-storage` | All finalized blocks. | One state every `--archival-epoch-interval` epochs, forever. | Everything it receives, forever. |

`MIN_EPOCHS_FOR_BLOCK_REQUESTS` is 33,024 epochs (about 146 days) on mainnet. Peers are only required
to serve blocks from this window, and the standard mode keeps exactly that.

Execution payloads are not part of this table: by default Grandine stores finalized blocks without
payloads and asks the execution client for them when needed. See
[Storage and database](./storage.md#execution-payloads).

## Back-sync

Back-sync downloads blocks, and the blobs or data columns that are still available, backwards from
the checkpoint. Enable it with `--back-sync`:

```bash
grandine \
  --network mainnet \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --back-sync \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

How far back it goes depends on the storage mode:

- **Standard mode:** back to the start of the `MIN_EPOCHS_FOR_BLOCK_REQUESTS` window. The node can
  then serve every block its peers may ask for.
- **Archive mode:** back to genesis. When the blocks are in, Grandine replays them from genesis to
  rebuild the historical states it keeps.

`--back-sync` conflicts with `--prune-storage`.

Back-sync starts once the node has caught up with the head, and pauses whenever the node falls
behind, so it never delays the forward sync. The node follows the head and serves validators while
back-sync runs. Its progress is visible in the log:

```text
starting back-sync from 12345664 to 7593984 slot
back-synced to 12339200 slot
…
back-sync completed
```

The progress is stored in the `sync` database, so back-sync resumes where it stopped after a
restart.

> **Note:** Back-sync is planned only when the node loads its anchor from a checkpoint sync server.
> Adding `--back-sync` to a node that restarts from an existing database has no effect. To enable it
> later, restart once with `--back-sync --checkpoint-sync-url URL --force-checkpoint-sync`. The node
> then loads a new checkpoint and back-syncs from it to the start of the block request window, or to
> genesis in archive mode. If the node already ran with `--back-sync`, it stops instead at the last
> finalized checkpoint it saw, filling only the gap. Remove `--force-checkpoint-sync` afterwards,
> or the node will checkpoint sync again on every restart.

### Why back-sync is slow

Back-sync is limited by how fast peers serve old blocks, and Grandine verifies every block it
receives. In archive mode, rebuilding the states afterwards means replaying every block since
genesis, which takes a long time on mainnet. Expect back-sync to take much longer than the initial
checkpoint sync.

## Run an archive node

> **Coming soon:** a new high-performance archive node for Grandine is in development and not yet
> released. It is built for the best historical data serving performance among consensus clients.
> Until it ships, use `--archive-storage` as described below.


An archive node keeps all blocks and a state every `--archival-epoch-interval` epochs from genesis
to the head. There are two ways to build one.

**Checkpoint sync and back-sync.** The node is ready for the head within minutes and fills in the
history in the background:

```bash
grandine \
  --network mainnet \
  --archive-storage \
  --back-sync \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

When the block download is finished, Grandine reconstructs the states:

```text
archiving back-synced states from 0 to 12345664
archiving back-sync data up to 1048576 slot
…
back-synced state archival completed (start_slot: 0, end_slot: 12345664)
```

**Sync from genesis.** Leave out `--checkpoint-sync-url`. The node verifies the whole chain itself
and stores states as it goes forward. This is the slowest option:

```bash
grandine \
  --network mainnet \
  --archive-storage \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

> **Warning:** Choose the storage mode before the node syncs. Switching an existing standard node to
> `--archive-storage` keeps everything from that point on, but does not bring back history that the
> standard mode has already pruned. For a complete archive, start a fresh database.

Blob and data column sidecars are a special case. Peers only serve them for the data availability
window, so an archive node started from a checkpoint cannot download sidecars older than about 18
days. It keeps all sidecars it receives from then on. With PeerDAS, a node keeps only the data
columns it custodies. To keep all of them, also run as a supernode. See
[PeerDAS and blob data](./peerdas.md).

### Archival epoch interval

`--archival-epoch-interval` (default: 32) sets how often Grandine stores a full state. To answer a
query for a state that is not stored, Grandine loads the closest earlier stored state and replays
the blocks in between.

- A smaller interval uses more disk space and answers historical state queries faster.
- A larger interval saves disk space and makes those queries slower.

With the default of 32 epochs, at most 32 epochs of blocks have to be replayed.

### Execution payloads in an archive

Grandine stores finalized blocks without their execution payloads unless you pass
`--store-payloads`. To serve old full blocks, it fetches the payloads from the execution client
with `engine_getPayloadBodiesByHash`. An archive node therefore needs an execution client that keeps
all historical block bodies, or `--store-payloads` so that Grandine keeps the payloads itself. The
second option costs extra disk space.

Execution clients now implement history expiry (EIP-4444). Dropping pre-Merge blocks does not
affect Grandine, because those blocks have no execution payloads. Dropping post-Merge block bodies
does: some clients and prune modes keep only a recent window (for example, Erigon's default `full`
prune mode), and rolling expiry of bodies older than about a year is spreading. Defaults change
between releases, so check your execution client's documentation on history pruning and configure it
to keep all post-Merge bodies, or use `--store-payloads`:
[Geth](https://geth.ethereum.org/docs/fundamentals/historypruning),
[Nethermind](https://docs.nethermind.io/fundamentals/history-pruning),
[Besu](https://besu.hyperledger.org/public-networks/reference/cli/options),
[Erigon](https://docs.erigon.tech/),
[Reth](https://reth.rs/run/configuration#prune).

## Disk usage

Disk usage grows with the history you keep. The prune mode uses the least, the standard mode adds a
few months of blocks plus the sidecar window, and an archive node grows without bound. See
[System requirements](./hardware_requirements.md) for current estimates and
[Storage and database](./storage.md) for how to check what the database holds.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--back-sync` (default: off): download history before the checkpoint. Conflicts with
  `--prune-storage`. The older spelling `--back_sync` is deprecated.
- `--archive-storage` (default: off): keep all blocks, states and sidecars. Conflicts with
  `--prune-storage`.
- `--prune-storage` (default: off): keep only the latest checkpoint block and state.
- `--archival-epoch-interval` (default: `32`): number of epochs between stored states.
- `--store-payloads` (default: off): keep execution payloads of finalized blocks in the database.
- `--data-availability-window` (default: network setting): number of epochs to keep blob and data
  column sidecars in standard mode. Intended for testing. Conflicts with `--archive-storage` and
  `--prune-storage`.
- `--checkpoint-sync-url` (default: none): checkpoint to start from. See
  [Checkpoint sync](./checkpoint_sync.md).
- `--force-checkpoint-sync` (default: off): load a new checkpoint even if a database exists.
