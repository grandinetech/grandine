## Storage

### Memory

By default, Grandine keeps the non-finalized part of the chain in the memory using structural sharing. This approach contributes to the high performance of Grandine because full state copies are avoided. This is a perfect approach for healthy chains (such as Ethereum Mainnet) that don't experience very long non-finalization periods. In such conditions, Grandine uses only ~1GB of memory on the Mainnet. However, during long non-finalization, this approach increases memory usage. In such cases, Grandine allows limiting the number of the latest memory stored states by settings the maximum number of the latest slots that should keep states in the memory.

### Disk

Grandine stores finalized part of the chain in the disk using an embedded key-value database `libmdbx`. Disk storage is passive and mainly used for storing/loading checkpoints, and serving historical data via API. Historical blocks and corresponding intermediate states are stored on the disk.

Grandine allows starting the Beacon Node from an earlier stored checkpoint by using `--state-slot` option. In this case, Grandine will try to find and load from the disk the closest stored checkpoint before the specified `--state-slot`.

### State hierarchy

Finalized states are not all written as full copies. Instead they are written into a *hierarchy* of layers, configured with `--state-hierarchy` as a comma separated list of slot exponents, sorted descending — shallowest layer first. Each exponent defines how often that layer is written: an exponent of `N` means one state every `2^N` slots. The default is `21,18,16,13,11,9,5` — a state every 2097152 slots in the shallowest layer, down to a state every 32 slots (one epoch) in the deepest one.

Only the shallowest layer — the *first* exponent in the list — is written as a full state, called a snapshot or frame. Every other layer is written as a delta against the closest state in the next shallower layer. Reading a state means loading the snapshot it descends from and applying the chain of deltas down to it. This trades a small amount of CPU on read for a large reduction in disk usage compared to writing full states.

Finalized states whose slots are not part of the hierarchy at all are not written to disk. They are reconstructed on demand by loading the closest older stored state and replaying the blocks in between, which is slower than applying deltas but costs no disk space. Unfinalized states pushed out of memory by `--unfinalized-states-in-memory` are the exception: each is written as a full snapshot regardless of the hierarchy, and finalized-state archival re-encodes it as a delta later.

The hierarchy is anchored to the later of the current phase's first slot and the slot the node was started from, so deltas are never computed across a fork boundary. On a checkpoint-synced node this means stored states fall at multiples of `2^N` slots *from the anchor block*, not on absolute epoch boundaries. Checkpoint syncing over an existing database moves the anchor; states written relative to the old anchor are kept and stay readable until pruning reaches them. Pruning computes what it must retain from the *current* anchor, so it removes states written under the old one without regard for the chains they form. A historical state whose delta parent has been pruned away is reported as absent, and reads fall back to replaying blocks from an older state.

Lowering the exponents stores states more densely: faster historical API responses, more disk usage. Raising them does the opposite. Adding layers makes delta chains longer, which makes each individual write cheaper and each read more expensive.

The deepest exponent may write states more often than once per epoch. `--state-hierarchy 21,16,4` stores one state every 16 slots and is accepted, as is any exponent down to `0`. Such states are stored, pruned and served over the historical APIs like any other, but they are not eligible as startup anchors: an anchor has to sit at an epoch start, so startup skips a mid-epoch state and loads the closest older epoch-start state instead, replaying the blocks in between. A sub-epoch deepest layer therefore buys faster historical reads inside an epoch and does not speed up startup.

The list itself must be non-empty, strictly decreasing — shallowest layer first — and every exponent at most `63`. `--state-hierarchy 5,16,21` is rejected, not silently reordered.

#### Upgrading from `--archival-epoch-interval`

Earlier releases wrote a full state once every `--archival-epoch-interval` epochs — `32` by default, so one state every 1024 slots — whether the node was forward synced or catching up. The `--state-slot` checkpoint written at every epoch start once forward synced was a single rolling row, overwritten each time, not a historical state. The flag is now ignored.

The default hierarchy stores a state every 32 slots in its deepest layer, which is 32 times denser than the old default — but all but the shallowest layer are deltas rather than full copies, so the density costs far less disk than the comparison suggests. The old *density* is `--state-hierarchy 10`, one state every 1024 slots; the old *behaviour*, every stored state a full copy, is that same single-layer hierarchy, since a one-layer hierarchy has nothing to delta against. Either way a single-layer hierarchy makes every read decompress a whole state, so neither is recommended over the default. Note that `--state-hierarchy` is written into the database the first time it is used and cannot be changed afterwards without discarding the database, so it is worth getting right before the first run.

#### Database compatibility

States written by earlier Grandine releases stay readable, and archival re-encodes them as deltas as it progresses, so upgrading needs no re-sync. The upgrade is one-way: this release writes states under a new key encoding, with zstd instead of snappy, and adds two rows recording the anchor slot and the hierarchy. No state this release writes is readable by an older one, and archival progressively re-encodes the states an older release could still read, so downgrading means discarding the beacon database with `--force-reset-beacon-db` and re-syncing.

#### Changing the hierarchy of an existing database

The hierarchy is written into the database on first use, and Grandine refuses to start if the configured `--state-hierarchy` does not match the stored one:

```
database was written with state hierarchy 11,9,5, but 13,9,5 is configured;
pass --state-hierarchy 11,9,5 to keep using this database or --force-reset-beacon-db to discard it
```

This is not a cosmetic check. Pruning derives the set of states it must retain from the configured layout. If the layout does not describe the delta chains actually on disk, pruning deletes states that other, still-retained states are encoded against, silently corrupting the database. Either keep using the stored hierarchy, or discard the database with `--force-reset-beacon-db` and re-sync.

#### State caches

`--state-cache-sizes` sets how many states are kept in memory per hierarchy layer, so that repeated reads and delta computations do not have to go back to disk. It takes a comma separated list starting from the shallowest layer — the full state snapshot — in the same order `--state-hierarchy` exponents are listed in. The list may be shorter than the hierarchy, in which case it is padded with zeros, and a size of `0` disables caching for that layer, so `--state-cache-sizes 5` caches only the snapshot layer. A list longer than the hierarchy is rejected. When the flag is not given, the sizes default to `5,3,3`, truncated to the number of layers, so changing `--state-hierarchy` alone does not require setting this too.

Shallow layers hold full or near-full states, so raising their sizes costs considerably more memory per cached entry than raising the deeper ones.

Independently of `--state-cache-sizes`, Grandine keeps the hierarchy ancestors of the most recently persisted state in memory — at most one state per layer, seven at the default hierarchy — so that forward sync can delta-encode without reading them back from disk. This is a floor: setting a layer's cache size to `0` disables its read cache but does not drop that state. Adding layers to `--state-hierarchy` therefore also raises baseline memory usage.

`--state-compression-level` sets the zstd compression level used for both snapshots and deltas (default: `3`). Higher levels shrink the database at the cost of CPU time on every state write. The level must be one zstd accepts; Grandine refuses to start otherwise.

### Archive Mode

Grandine provides `--archive-storage` option for archive mode, which disables pruning: blocks, blob sidecars, data columns and stored states are kept instead of being deleted once they fall outside the retention window. States are still written at the frequency defined by `--state-hierarchy`. This mode is mutually exclusive with `--prune-storage`.

### Prune Mode

Grandine provides `--prune-storage` option for prune mode that only stores a single checkpoint state with the corresponding block. This mode also stores unfinalized blocks on Grandine shutdown. This mode is sufficient for staking. No states are written to the hierarchy in this mode, so `--state-hierarchy` has no effect.

### Metrics

Two Prometheus histograms report on the delta state store. Both are labelled by `layer`, the number of deltas that have to be applied to reconstruct the state: `0` is a full snapshot, `1` is a delta against a snapshot, and so on. This is normally the state's depth in the hierarchy, but it is shorter when a hierarchy ancestor was missing and the state had to be encoded against a shallower one.

* `STATE_PATCH_SIZES` - serialized and compressed size in bytes of states written to the store. Snapshots are recorded here too, under layer `0`, so the buckets span from kilobyte-sized deltas to snapshots hundreds of megabytes large;
* `STATE_PATCH_COMPUTE_TIMES` - time in seconds spent computing a delta against its hierarchy ancestor.

Together they show how much space and CPU each layer costs, which is what `--state-hierarchy` and `--state-compression-level` trade against each other.

### Relevant command line options

* `--state-hierarchy` - comma separated list of slot exponents defining the state storage layout, shallowest layer first (default: `21,18,16,13,11,9,5`);
* `--state-cache-sizes` - number of states cached in memory per hierarchy layer, shallowest layer first; may be shorter than the hierarchy, in which case the remaining layers are not cached (default: `5,3,3`);
* `--state-compression-level` - zstd compression level for stored states (default: `3`);
* `--archive-storage` - retains all blocks, blobs and stored states by disabling pruning; mutually exclusive with `--prune-storage` (default: disabled);
* `--force-reset-beacon-db` - deletes the existing beacon node databases on startup, which is the escape hatch for a `--state-hierarchy` mismatch (default: disabled);
* `--prune-storage` - enables pruning mode that doesn't store historical states and blocks (default: disabled);
* `--state-slot` - sets the slot at which Grandine Beacon Node should start (default: latest finalized slot);
* `--unfinalized-states-in-memory` - the number of the latest slots that will store states in the memory (default: all unfinalized states stored in the memory);
* `--archival-epoch-interval` - **deprecated and ignored**; use `--state-hierarchy` instead.
