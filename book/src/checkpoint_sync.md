# Checkpoint sync

Checkpoint sync starts a new beacon node from a recent finalized state downloaded from another,
trusted beacon node, instead of replaying the whole chain from genesis. It takes minutes instead of
days, and it protects the node against long-range attacks, because the node starts inside the weak
subjectivity period. It is the recommended way to start Grandine.

After a checkpoint sync, the node has no history before the checkpoint. That is enough for
staking. If you need older blocks or states, see [Back-sync and archive nodes](./historical_data.md).

## Choose an endpoint

You need the Beacon Node API URL of a node that is synced to the network you join. You can use:

- a beacon node you run yourself (any client, including another Grandine node), or
- a public checkpoint sync endpoint. The community keeps a list at
  <https://eth-clients.github.io/checkpoint-sync-endpoints/>, with endpoints for mainnet and the
  testnets.

The endpoint must serve SSZ responses for these two Beacon API routes:

- `GET /eth/v2/beacon/blocks/{block_id}`
- `GET /eth/v2/debug/beacon/states/{state_id}`

Most public checkpoint sync endpoints and beacon nodes do.

> **Note:** Grandine replaces the path of the URL with the API paths above, so only the scheme, host,
> port and any `user:password@` part are used. A provider URL whose API key is part of the path, such
> as `https://provider.example/API-KEY/`, does not work. Credentials in the URL are redacted in the
> logs.

## Start with checkpoint sync

Mainnet:

```bash
grandine \
  --network mainnet \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

Hoodi:

```bash
grandine \
  --network hoodi \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /path/to/jwt.hex
```

Docker:

```bash
docker run -d --name grandine \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -v /path/to/grandine-data:/root/.grandine \
  -v /path/to/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  --network mainnet \
  --checkpoint-sync-url https://CHECKPOINT-HOST \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /jwt.hex
```

A successful checkpoint sync logs:

```text
performing checkpoint sync from https://CHECKPOINT-HOST/…
loaded state at slot 12345664 from https://CHECKPOINT-HOST/
loaded state at slot 12345664
```

The node then syncs forward from that slot to the head. This usually takes a few minutes. Follow
the progress as described in [Running a beacon node](./beacon_node.md#reading-the-logs).

## How it works

1. Grandine fetches the latest finalized block (`/eth/v2/beacon/blocks/finalized`).
2. If that block is not the first block of an epoch, Grandine walks back to the first slot of the
   epoch, and further back if that slot is empty, until it finds a block at an epoch boundary.
3. It fetches the state at that block's slot (`/eth/v2/debug/beacon/states/{slot}`).
4. It stores the block and state as the anchor of its database and starts fork choice from there.

Each download has a timeout of 10 minutes.

## The checkpoint URL is used only for a new database

Grandine uses `--checkpoint-sync-url` only when its database is empty. On every later start it
resumes from its own database and logs:

```text
skipping checkpoint sync: existing database found; pass --force-checkpoint-sync to force checkpoint sync
```

This is the normal behavior, so you can leave `--checkpoint-sync-url` in your service
configuration.

> **Warning:** If the checkpoint sync fails, Grandine does not stop. It logs `checkpoint sync failed`
> with the error and continues from its database, or from genesis if the database is empty. A node
> that starts from genesis on mainnet takes a very long time to sync. If you see this warning on a
> new node, stop Grandine, fix the URL or choose another endpoint, delete the beacon directory and
> start again.

## Verify the checkpoint

Checkpoint sync trusts the endpoint you chose. A malicious or broken endpoint could give you a state
from a different chain. Grandine does not compare the checkpoint against a second source, so do it
yourself after the node has started.

Ask your node for its finalized checkpoint:

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/finalized/finality_checkpoints
```

Then ask one or more independent sources for the block root at the same epoch, for example a
different public endpoint, a node run by someone you trust, or a block explorer:

```bash
curl -s https://OTHER-BEACON-NODE/eth/v1/beacon/states/finalized/finality_checkpoints
```

The `finalized.root` values must match for the same `finalized.epoch`. If the epochs differ, look up
the block root for a specific slot on both sides:

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/blocks/SLOT/root
curl -s https://OTHER-BEACON-NODE/eth/v1/beacon/blocks/SLOT/root
```

If the roots differ, stop the node, delete its beacon directory, and checkpoint sync again from a
source you trust.

## Genesis state on testnets

Even with checkpoint sync, Grandine loads the genesis state of the network at startup. The mainnet
genesis state is built into the binary. For Sepolia, Holesky and Hoodi, Grandine downloads it from
the network's repository on GitHub on the first run, checks its genesis validators root, and saves
it as `genesis_state.ssz` in the beacon directory:

```text
downloading genesis state from https://github.com/eth-clients/hoodi/raw/…/metadata/genesis.ssz…
genesis state loaded at slot: 0
```

If GitHub is not reachable from your machine, either:

- download the file elsewhere and pass it with `--genesis-state-file /path/to/genesis.ssz`, or
- serve it from another location and pass `--genesis-state-download-url URL`.

For custom networks, `--genesis-state-file` (or `genesis.ssz` in `--configuration-directory`) is the
normal way to provide the genesis state. See
[Configuration files and custom networks](./configuration_files.md).

## Re-sync from a new checkpoint

To start over from a fresh checkpoint, for example after a long downtime or a corrupted database,
choose one of these:

- **Force a new checkpoint.** Keep the database and load a new anchor from the endpoint:

  ```bash
  grandine --network mainnet --checkpoint-sync-url https://CHECKPOINT-HOST --force-checkpoint-sync ...
  ```

  `--force-checkpoint-sync` requires `--checkpoint-sync-url`. Unlike a normal start, Grandine does
  not fall back to its database when the download fails: it logs the error and retries. Remove the
  flag again after the node has started, otherwise every restart downloads a new checkpoint.

- **Reset the beacon databases.** `--force-reset-beacon-db` deletes the `beacon_fork_choice`,
  `eth1_cache`, `pubkey_cache` and `sync` databases at startup. Combined with
  `--checkpoint-sync-url`, the node then checkpoint syncs into an empty database. This does not
  touch the validator directory or slashing protection data. Remove the flag after use.

- **Delete the beacon directory by hand** while Grandine is stopped. See
  [Storage and database](./storage.md#data-directory-layout).

> **Warning:** Never delete the `validator` directory to fix a sync problem. It holds the slashing
> protection database. See [Slashing protection](./slashing_protection.md).

## Sync from genesis

Without `--checkpoint-sync-url`, a new node syncs from genesis. This verifies the whole chain
yourself, but takes much longer and needs much more disk space if you keep the history. Use it
when you need an archive node that is built entirely from your own verification. See
[Back-sync and archive nodes](./historical_data.md).

## Start from an older stored state

`--state-slot SLOT` makes Grandine start from the stored state closest to, and not after, `SLOT`
instead of from the latest stored state. This is mainly useful for debugging. See
[Storage and database](./storage.md#starting-from-an-older-state).

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--checkpoint-sync-url` (default: none): Beacon Node API URL to load a recent finalized checkpoint
  from when the database is empty.
- `--force-checkpoint-sync` (default: off): checkpoint sync even if a database exists. Requires
  `--checkpoint-sync-url`.
- `--force-reset-beacon-db` (default: off): delete the beacon node databases at startup.
- `--genesis-state-file` (default: none): load the genesis state from an SSZ file.
- `--genesis-state-download-url` (default: the network's GitHub repository): where to download the
  genesis state of Sepolia, Holesky or Hoodi.
- `--state-slot` (default: latest stored state): start from the stored state at or before this
  slot.
- `--back-sync` (default: off): after the checkpoint sync, also download older blocks. See
  [Back-sync and archive nodes](./historical_data.md).
