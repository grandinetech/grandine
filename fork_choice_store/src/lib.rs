//! Implementation of [Beacon Chain Fork Choice].
//!
//! Time is scarce and writing is hard, so the documentation is rather fragmented.
//! `fork_choice_control::extra_tests` has some diagrams that may help.
//!
//! We group unfinalized blocks into segments, each of which corresponds to a fork and contains
//! blocks starting from the point when the fork first appeared and ending with the tip of the fork.
//!
//! A chain may consist of multiple segments, with each segment branching off the previous one. In
//! the ideal case the whole chain will be contained in a single segment. This should almost always
//! be the case when syncing old blocks.
//!
//! Segments are assigned sequential IDs.
//! The IDs do not correspond to anything outside the application.
//!
//! Segments are kept in a map ordered by their IDs.
//! This has the effect of keeping unfinalized blocks topologically ordered.
//!
//! Segments are not uniquely represented. A chain with forks may be divided into segments in
//! multiple ways, depending on what order its blocks are received in.
//!
//! We assume finalized parts of the chain cannot be forked.
//! Finalized blocks are moved into a contiguous vector.
//!
//! We assume that the number of forks will be low. Some algorithms used here slow down linearly as
//! the number of forks increases. The slowdown should be negligible compared to everything else
//! unless the number of forks gets absurdly high.
//!
//! Denormalizing the data structure further may improve performance if it turns out to be bad.
//! Having [`Segment`] store a list of its children may help. The original design stored a list of
//! children and the best leaf segment ID in each [`UnfinalizedBlock`] as well as the parent
//! [`Location`] in each [`Segment`], but that turned out to be unnecessary.
//!
//! This implementation is inspired by [`proto_array`].
//! Compared to [`proto_array`], this implementation has several advantages:
//! - Block ancestors can be looked up using binary search or interpolation search
//!   (as long as the number of forks is small, that is).
//! - Fewer fields are needed in each unfinalized block.
//! - It's easy to determine the number of forks.
//!
//! Block and attestation processing is split into pairs of `validate_*` and `apply_*` methods.
//! The `validate_*` methods do not mutate [`Store`] and can be used to process objects in parallel.
//! Because of the split some functions from the Fork Choice specification do not have exact
//! equivalents in the implementation.
//!
//! This implementation makes use of persistent data structures, but they are not required for the
//! algorithm to work. They're only used to make snapshots cheap.
//!
//! This implementation prunes orphans as soon as possible. As a result, some validations for both
//! blocks and attestations are implicit. Also, this implementation discards blocks and attestations
//! that could be used for slashing. However, transitively delayed objects are not pruned.
//!
//! This implementation performs some of the validations listed in the Networking specifications,
//! but not all of them. Most notably:
//! - Multiple blocks proposed in a single slot by the same validator are accepted. This is arguably
//!   allowed because failure of this validation is supposed to result in the later blocks being
//!   `IGNORE`d, not `REJECT`ed. Also, the blocks are still technically valid (even when they are
//!   slashable) and can be obtained through requests.
//! - Multiple singular or aggregate attestations published by the same validator in one epoch are
//!   not explicitly `IGNORE`d. They are instead processed with no effect.
//! - Duplicate aggregate attestations are not `IGNORE`d either.
//!
//! Python `assert`s are represented by statements that either delay the processing of the offending
//! object or return [`Err`]. All other operations that can raise exceptions in Python
//! (like indexing into `dict`s) are represented by statements that panic on failure.
//!
//! Notes on nomenclature:
//! - Pruning means removing orphaned blocks and outdated attestations.
//! - Archiving means removing finalized blocks from memory.
//! - Unloading means removing states that can be recreated through state transitions.
//!
//! [`Location`]:         misc::Location
//! [`UnfinalizedBlock`]: misc::UnfinalizedBlock
//!
//! [Beacon Chain Fork Choice]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md
//! [`proto_array`]:            https://github.com/protolambda/lmd-ghost/tree/242f0dced3b34feed0d4e9d2fd0e5e66e448c359#array-based-stateful-dag-proto_array

pub use crate::{
    error::Error,
    misc::{
        AggregateAndProofAction, AggregateAndProofOrigin, ApplyBlockChanges, ApplyTickChanges,
        AttestationAction, AttestationItem, AttestationOrigin, AttestationValidationError,
        AttesterSlashingOrigin, BlobSidecarAction, BlobSidecarOrigin, BlockAction, BlockOrigin,
        ChainLink, DataAvailabilityPolicy, DataColumnSidecarAction, DataColumnSidecarOrigin,
        ExecutionPayloadEnvelopeAction, ExecutionPayloadEnvelopeOrigin, PartialBlockAction,
        PayloadAction, PayloadAttestationAction, PayloadAttestationOrigin, Storage,
        ValidAttestation,
    },
    segment::Segment,
    state_cache_processor::{Error as StateCacheError, StateCacheProcessor},
    store::Store,
    store_config::{StoreConfig, DEFAULT_CACHE_LOCK_TIMEOUT_MILLIS},
    validations::validate_merge_block,
};

mod blob_cache;
mod data_column_cache;
mod error;
mod execution_payload_envelope_cache;
mod misc;
mod segment;
mod state_cache_processor;
mod store;
mod store_config;
mod supersets;
mod validations;
