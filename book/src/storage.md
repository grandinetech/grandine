# Storage and database

This page explains where Grandine keeps its data, how it uses memory and disk, which storage mode
to choose, and how to inspect, back up and restore the database.

## Memory and disk

Grandine keeps the unfinalized part of the chain in memory. States share their unchanged parts
(structural sharing), so Grandine does not have to copy full states for every block. This is one
reason Grandine is fast and uses little memory on a healthy network.

When the chain does not finalize for a long time, the unfinalized part grows and so does memory use.
`--unfinalized-states-in-memory` limits how many of the latest unfinalized slots keep their states
in memory. Older unfinalized states are dropped and rebuilt from blocks when needed. See
[Performance and memory tuning](./performance_tuning.md).

The finalized part of the chain is written to an embedded
[libmdbx](https://github.com/erthink/libmdbx) key-value database. Grandine uses the database to
restart where it stopped, to serve historical data through the API and to peers, and to store
blobs and data columns.

## Data directory layout

All data lives under `--data-dir` (default: `$HOME/.grandine`), in a subdirectory named after the
network:

```text
~/.grandine/
├── exception.log                # internal errors; rotated at 1 GB, 5 files kept
└── mainnet/                     # one directory per network
    ├── meta.json                # database schema version
    ├── beacon/                  # --store-directory
    │   ├── beacon_fork_choice/  # blocks, states, blobs, data columns
    │   ├── pubkey_cache/        # decompressed validator public keys
    │   ├── sync/                # back-sync progress
    │   ├── eth1_cache/          # deposit cache (custom genesis only)
    │   └── genesis_state.ssz    # downloaded genesis state (Sepolia, Holesky, Hoodi)
    ├── network/                 # --network-dir
    │   ├── key                  # libp2p private key (node identity)
    │   └── enr.dat              # last ENR
    ├── validator/               # validator client data
    │   ├── slashing_protection.sqlite
    │   ├── validators.yml
    │   └── 0xPUBKEY/keystore.json   # keystores imported through the Keymanager API
    └── secrets/                 # passwords of keystores imported through the Keymanager API
```

The network name is always added: `--data-dir /data` puts mainnet data in `/data/mainnet`. With
Docker, mount the host directory at `/root/.grandine`.

`--store-directory` and `--network-dir` move the `beacon` and `network` directories elsewhere, for
example to put the database on a faster disk:

```bash
grandine --network mainnet \
  --data-dir /var/lib/grandine \
  --store-directory /mnt/nvme/grandine-beacon \
  ...
```

`beacon/` can be deleted to re-sync. `network/key` holds the node's peer ID; deleting it gives the
node a new identity. `validator/` holds the slashing protection database and must never be
deleted while you run validators. See [Validator definitions](./validator_definitions.md) and
[Slashing protection](./slashing_protection.md) for what lives there.

Grandine creates its libmdbx database files with permissions `0600`. Run Grandine as a dedicated user that owns
the data directory. See [Running as a service](./running_as_a_service.md).

## Storage modes

The storage mode decides how much finalized history Grandine keeps. Choose it before the first sync.

| Mode | Option | Keeps | Use it for |
|---|---|---|---|
| Prune | `--prune-storage` | Only the latest checkpoint block and state. No historical blocks, states or sidecars on disk. | Testing and development only. Not for production use: it does not keep blocks and sidecars for the period the specification requires, so the node cannot serve them to peers. |
| Standard | default | Finalized blocks and periodic states for the `MIN_EPOCHS_FOR_BLOCK_REQUESTS` window (about five months on mainnet), and blob or data column sidecars for the data availability window (about 18 days). | Most nodes. The node can serve everything peers may ask for. |
| Archive | `--archive-storage` | All blocks, a state every `--archival-epoch-interval` epochs, and all sidecars it receives. Nothing is pruned. | Explorers, indexers, historical API queries. |

`--prune-storage` conflicts with `--archive-storage` and with `--back-sync`. The startup log shows
the mode in use, for example `storage mode: Standard { custom_data_availability_window: None }`.

For back-sync and archive nodes, see [Back-sync and archive nodes](./historical_data.md).

### Archival epoch interval

In the standard and archive modes, Grandine stores a full state at the first slot of every
`--archival-epoch-interval` epochs (default: 32). States in between are rebuilt on demand by
replaying blocks from the closest stored state. A larger value uses less disk space but makes
historical state queries slower.

Independently of the interval, once the node is synced it saves a checkpoint state at every new
finalized epoch, so it can restart from a recent state.

### Execution payloads

By default, Grandine stores finalized blocks *blinded*: without their execution payloads. When it
needs a full block, to serve it through the API or to a peer, it fetches the payload from the
execution client (`engine_getPayloadBodiesByHash`). This saves a lot of disk space, because the
execution client keeps the same data anyway.

`--store-payloads` keeps the payloads of finalized blocks in Grandine's database as well. Use it
when you cannot rely on the execution client to serve old block bodies.

### Data availability window

Blob sidecars (Deneb and Electra) and data column sidecars (Fulu and later) are kept for the data
availability window: 4,096 epochs, about 18 days, on mainnet. Older ones are pruned, except in
archive mode. `--data-availability-window EPOCHS` changes the window in standard mode. It is meant
for testing; peers expect at least the network default. See
[PeerDAS and blob data](./peerdas.md).

## Compression

Finalized blocks and execution payloads are compressed with zstd, at the level set by
`--zstd-compression-level` (default: 3, zstd's default level). All other values in the database are
compressed with Snappy, which the option does not affect. Higher levels save some disk space at the cost of CPU time when blocks are
written. Grandine rejects levels outside the range the zstd library supports.

## Database size limit

libmdbx needs an upper limit for the size of each database file. The file grows in steps of
256 MiB as data is added, up to the limit. The limit does not reserve disk space.

- `--database-size` (default: 1024 GiB) is the limit for each beacon database
  (`beacon_fork_choice`, `pubkey_cache`, `sync`).
- `--eth1-database-size` (default: 16 GiB) is the limit for the deposit cache.

Sizes accept units such as `512GiB` or `2TiB`. The startup log shows the limits in use
(`Eth2 database upper limit: ...`).

If a database reaches its limit, Grandine logs `increasing environment map size limits`, doubles
both limits and restarts its runtime automatically. To avoid this on a large archive node, set a
generous limit from the start:

```bash
grandine --network mainnet --archive-storage --database-size 4TiB ...
```

## Starting from an older state

On startup, Grandine loads the latest stored checkpoint state. `--state-slot SLOT` makes it search
the database for the latest stored state at or before `SLOT` and start from there instead. The
startup log shows `force state slot: SLOT`. This is mostly useful for debugging and requires that
the database actually holds a state that old: in standard mode, only states within the retention
window remain.

## In-memory mode

`--in-memory` runs Grandine without writing anything to the data directory. Every database lives
in memory, and everything is lost on exit. Grandine warns about this at startup. Use it for tests
and short experiments only.

## Inspecting the database

Two subcommands read the database. Pass the same `--network` and `--data-dir` you run with. Global
options go before the subcommand.

You do not need to stop Grandine first. The database supports access from several processes at
once, and these subcommands only read it. While Grandine is writing, a subcommand may wait a moment
before it starts. A long `db-stats` run keeps Grandine from reusing freed database pages until it
finishes, so the database files can grow a little in the meantime.

`db-stats` lists every record type in `beacon_fork_choice` with its count and size:

```bash
grandine --network mainnet db-stats
```

```text
…: 1234 entries, key_size: …, value_size: …, total_size: …
```

`db-info` prints information about the records in a database. `--database` is `beacon` or `sync`:

```bash
grandine --network mainnet db-info --database beacon
grandine --network mainnet db-info --database sync
```

Both accept `--path` to read a database at a custom location:

```bash
grandine --network hoodi db-stats --path ~/.grandine/hoodi/beacon/beacon_fork_choice
```

See [Subcommands and tools](./subcommands.md) for the other subcommands.

## Backup and restore

What to back up depends on what you would lose.

| Data | Back up? | Why |
|---|---|---|
| `validator/` and `secrets/` | **Yes**, regularly, and before every migration. | They hold the slashing protection database, `validators.yml` and keystores imported through the Keymanager API. Export slashing protection with `grandine interchange export` as well. See [Slashing protection](./slashing_protection.md). |
| Validator keystores and passwords | **Yes**, offline. | You need them to recover the validators. See [Managing validator keys](./key_management.md). |
| `network/key` | Optional. | Keeps the same peer ID after a restore. |
| `beacon/` | Optional. | A checkpoint sync rebuilds it in minutes. Back it up only to avoid a long back-sync or archive rebuild. |

To back up the beacon database:

1. Stop Grandine and wait for `chain saved (finalized blocks: …, unfinalized blocks: …)`.
2. Copy the directory, for example:

   ```bash
   sudo systemctl stop grandine
   sudo tar -C /var/lib/grandine -czf grandine-beacon-$(date +%F).tar.gz mainnet/beacon
   sudo systemctl start grandine
   ```

To restore, stop Grandine, replace `beacon/` with the backup, make sure the files belong to the
user that runs Grandine, and start it. The node resumes from the backed-up state and syncs the slots
since then.

> **Warning:** Do not copy the database files while Grandine is running. The copy may be
> inconsistent.

> **Tip:** For a staking node, a backup of `beacon/` is rarely worth it. If the database is lost or
> corrupted, delete `beacon/` and start with `--checkpoint-sync-url`.

### Moving the data directory

1. Stop Grandine.
2. Move or copy the whole network directory (for example `~/.grandine/mainnet`) to the new
   location, keeping the structure.
3. Start Grandine with `--data-dir` pointing at the parent of the network directory.

### Resetting the database

To start over, either delete the `beacon` directory while Grandine is stopped, or start once with
`--force-reset-beacon-db`. That option deletes `beacon_fork_choice`, `eth1_cache`, `pubkey_cache`
and `sync`, but not the validator data. Combine it with `--checkpoint-sync-url`. See
[Checkpoint sync](./checkpoint_sync.md#re-sync-from-a-new-checkpoint).

## Upgrades and schema versions

`meta.json` records the database schema version. A newer Grandine release that changes the schema
updates the file and logs `using schema version … for new data`. Check the release notes before you downgrade, and see
[Updating Grandine](./updating.md).

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--data-dir` (default: `$HOME/.grandine`): parent directory for all data. The network name is
  added below it.
- `--store-directory` (default: `{data_dir}/{network}/beacon`): directory of the beacon databases.
- `--network-dir` (default: `{data_dir}/{network}/network`): directory of the network key and ENR.
- `--prune-storage` (default: off): keep only the latest checkpoint block and state.
- `--archive-storage` (default: off): keep all history.
- `--archival-epoch-interval` (default: `32`): epochs between stored states.
- `--store-payloads` (default: off): store execution payloads of finalized blocks.
- `--zstd-compression-level` (default: `3`): zstd level for blocks and payloads.
- `--database-size` (default: 1024 GiB): size limit of each beacon database.
- `--eth1-database-size` (default: 16 GiB): size limit of the deposit cache database.
- `--data-availability-window` (default: network setting): epochs to keep sidecars. For testing.
- `--unfinalized-states-in-memory` (default: `128`): number of the latest unfinalized slots that
  keep their states in memory. The minimum is two epochs (64 on mainnet).
- `--max-epochs-to-retain-states-in-cache` (default: `8`): how many epochs of states the state cache
  keeps.
- `--state-cache-lock-timeout` (default: `1500`): state cache lock timeout in milliseconds.
- `--state-slot` (default: latest stored state): start from the stored state at or before this slot.
- `--force-reset-beacon-db` (default: off): delete the beacon databases at startup.
- `--in-memory` (default: off): keep everything in memory.
