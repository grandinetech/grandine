## Checkpoint Sync

Grandine supports checkpoint sync. Currently, it's the preferred way to sync the chain. By default, back-syncing is disabled, so no historical blocks are fetched and no historical states are reconstructed. This default behavior is sufficient for staking, however, for other use cases (such as historical data access via Beacon Node API) back-syncing must be enabled.

### Relevant command line options

* `--checkpoint-sync-url` - Beacon Node API URL to load a recent finalized checkpoint and sync from it (default: disabled)
* `--checkpoint-sync-block-id` - Beacon block ID to use as the checkpoint-sync starting point (default: `finalized`). Selecting `head`, a slot, or a block root explicitly trusts the configured checkpoint-sync server.
* `--back-sync` - enables back-syncing blocks and reconstructing states (default: disabled)

### Non-finalized checkpoint implementation spike

Passing `head`, a slot, or a block root to `--checkpoint-sync-block-id` is experimental. The configured remote beacon node is trusted to supply that block and its matching state. Grandine normalizes the selected block to an epoch-start anchor and verifies that the downloaded block and state agree before startup continues.

The spike has exposed the following finalized-checkpoint assumptions in the current startup path:

* `FinalizedCheckpoint` is used as the type for every startup anchor.
* `AnchorCheckpointProvider` stores a `FinalizedCheckpoint`.
* `Store::new` requires an epoch-start anchor and initializes its justified, finalized, unrealized justified, and unrealized finalized checkpoints from that anchor.
* initial storage writes the anchor under `FinalizedBlockByRoot`.
* forward sync derives its lower boundary from the store's finalized checkpoint.
* P2P status and peer grouping consume the store's finalized checkpoint.
* back-sync bookkeeping describes and stores its anchor as finalized.

Until those assumptions are separated from local startup trust, selecting a non-finalized block only exercises the remote loading and validation portion of the startup path. It does not yet provide safe non-finalized checkpoint sync.
