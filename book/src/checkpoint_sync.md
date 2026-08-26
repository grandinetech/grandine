## Checkpoint Sync

Grandine supports checkpoint sync. Currently, it's the preferred way to sync the chain. By default, back-syncing is disabled, so no historical blocks are fetched and no historical states are reconstructed. This default behavior is sufficient for staking, however, for other use cases (such as historical data access via Beacon Node API) back-syncing must be enabled.

### Relevant command line options

* `--checkpoint-sync-url` - Beacon Node API URL to load a recent finalized checkpoint and sync from it (default: disabled)
* `--checkpoint-sync-block-id` - Beacon block ID to use as the checkpoint-sync starting point (default: `finalized`). Selecting `head`, a slot, or a block root explicitly trusts the configured checkpoint-sync server.
* `--back-sync` - enables back-syncing blocks and reconstructing states (default: disabled)

### Non-finalized checkpoint sync (experimental)

Passing `head`, a slot, or a block root to `--checkpoint-sync-block-id` is experimental. The configured remote beacon node is trusted to supply that block and its matching state. Grandine normalizes the selected block to an epoch-start anchor and verifies that the downloaded block and state agree before startup continues.

For an explicit non-finalized selection, Grandine keeps the trusted startup anchor separate from
the protocol-finalized checkpoint contained in the downloaded state. It also downloads and
validates the protocol-finalized block and state so `finalized` Beacon API lookups, P2P status, and
forward-sync boundaries use on-chain finality rather than the trusted anchor.

The existing `finalized` checkpoint-sync path is unchanged: when
`--checkpoint-sync-block-id` is omitted, the downloaded anchor remains Grandine's initial finalized
checkpoint.

The implementation spike exposed additional startup assumptions that are not all addressed by
this initial separation:

* `FinalizedCheckpoint` is used as the type for every startup anchor.
* `AnchorCheckpointProvider` stores a `FinalizedCheckpoint`.
* `Store::new` requires an epoch-start anchor and initializes its justified, finalized, unrealized justified, and unrealized finalized checkpoints from that anchor.
* initial storage writes the anchor under `FinalizedBlockByRoot`.
* back-sync bookkeeping describes and stores its anchor as finalized.

Restart persistence, back-sync behavior, and broader failure-mode coverage remain experimental.
