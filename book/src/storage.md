## Storage

### Memory

By default, Grandine keeps the non-finalized part of the chain in the memory using structural sharing. This approach contributes to the high performance of Grandine because full state copies are avoided. This is a perfect approach for healthy chains (such as Ethereum Mainnet) that don't experience very long non-finalization periods. In such conditions, Grandine uses only ~1GB of memory on the Mainnet. However, during long non-finalization, this approach increases memory usage. In such cases, Grandine allows limiting the number of the latest memory stored states by settings the maximum number of the latest slots that should keep states in the memory.

### Disk

Grandine stores finalized part of the chain in the disk using an embedded key-value database `libmdbx`. Disk storage is passive and mainly used for storing/loading checkpoints, and serving historical data via API. Historical blocks and corresponding intermediate states are stored on the disk. It's possible to set the length of the intermediate states period. A higher value for this interval means lower disk usage and slower API responses for historical data.

Grandine allows starting the Beacon Node from an earlier stored checkpoint by using `--state-slot` option. In this case, Grandine will try to find and load from the disk the closest stored checkpoint before the specified `--state-slot`.

### Prune Mode

Grandine provides `--prune-storage` option for prune mode that only stores a single checkpoint state with the corresponding block. This mode also stores unfinalized blocks on Grandine shutdown. This mode is sufficient for staking.

### Relevant command line options

* `--archival-epoch-interval` - sets the number of epochs between stored states (default: `32`);
* `--prune-storage` - enables pruning mode that doesn't store historical states and blocks (default: disabled);
* `--state-slot` - sets the slot at which Grandine Beacon Node should start (default: latest finalized slot);
* `--unfinalized-states-in-memory` - the number of the latest slots that will store states in the memory (default: all unfinalized states stored in the memory).
