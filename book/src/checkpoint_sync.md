## Checkpoint Sync

Grandine supports checkpoint sync. Currently, it's the preferred way to sync the chain. By default, back-syncing is disabled, so no historical blocks are fetched and no historical states are reconstructed. This default behavior is sufficient for staking, however, for other use cases (such as historical data access via Beacon Node API) back-syncing must be enabled.

### Relevant command line options

* `--checkpoint-sync-url` - Beacon Node API URL to load a recent finalized checkpoint and sync from it (default: disabled)
* `--back-sync` - enables back-syncing blocks and reconstructing states (default: disabled)
