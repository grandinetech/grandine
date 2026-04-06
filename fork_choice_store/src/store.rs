use core::ops::{AddAssign as _, Bound, SubAssign as _};
use std::{
    backtrace::Backtrace,
    collections::{
        binary_heap::{BinaryHeap, PeekMut},
        HashSet as StdHashSet,
    },
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, bail, ensure, Result};
use arithmetic::NonZeroExt as _;
use bls::traits::SignatureBytes as _;
use clock::{Tick, TickKind};
use dashmap::DashMap;
use eip_7594::{verify_data_column_sidecar, verify_kzg_proofs, verify_sidecar_inclusion_proof};
use execution_engine::ExecutionEngine;
use features::Feature;
use hash_hasher::HashedMap;
use helper_functions::{
    accessors, electra,
    error::SignatureKind,
    misc, phase0, predicates,
    signing::SignForSingleFork as _,
    slot_report::NullSlotReport,
    verifier::{NullVerifier, SingleVerifier, Verifier},
};
use im::{hashmap, hashmap::HashMap, ordmap, vector, HashSet, OrdMap, Vector};
use itertools::{izip, Either, EitherOrBoth, Itertools as _};
use logging::{error_with_peers, info_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use ssz::{BitVector, ContiguousList, SszHash as _};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tracing::instrument;
use transition_functions::{
    combined,
    unphased::{self, ProcessSlots, StateRootPolicy},
};
use typenum::Unsigned as _;
use types::{
    combined::{
        Attestation, AttesterSlashing, AttestingIndices, BeaconState, DataColumnSidecar,
        SignedAggregateAndProof, SignedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::{BlobIndex, KzgCommitment},
    },
    electra::containers::IndexedAttestation as ElectraIndexedAttestation,
    fulu::{
        containers::{DataColumnIdentifier, DataColumnSidecar as FuluDataColumnSidecar},
        primitives::ColumnIndex,
    },
    gloas::{
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{
            CombinedPayloadAttestation, DataColumnSidecar as GloasDataColumnSidecar,
            SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
        },
        primitives::BuilderIndex,
    },
    nonstandard::{
        BlobSidecarWithId, DataColumnSidecarWithId, PayloadStatus, Phase, RelativeEpoch, WithStatus,
    },
    phase0::{
        consts::{ATTESTATION_PROPAGATION_SLOT_RANGE, GENESIS_EPOCH, GENESIS_SLOT},
        containers::{AttestationData, Checkpoint},
        primitives::{Epoch, ExecutionBlockHash, Gwei, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
use unwrap_none::UnwrapNone as _;

use crate::{
    blob_cache::BlobCache,
    data_column_cache::DataColumnCache,
    error::Error,
    execution_payload_envelope_cache::ExecutionPayloadEnvelopeCache,
    misc::{
        AggregateAndProofAction, AggregateAndProofOrigin, ApplyBlockChanges, ApplyTickChanges,
        AttestationAction, AttestationItem, AttestationValidationError, AttesterSlashingOrigin,
        BlobSidecarAction, BlobSidecarOrigin, BlockAction, BranchPoint, ChainLink,
        DataAvailabilityPolicy, DataColumnSidecarAction, DataColumnSidecarOrigin, Difference,
        DifferenceAtLocation, DissolvedDifference, ForkChoicePayloadStatus, LatestMessage,
        Location, PartialAttestationAction, PartialBlockAction, PayloadAction, Score, SegmentId,
        Storage, UnfinalizedBlock, ValidAttestation,
    },
    segment::{Position, Segment},
    state_cache_processor::StateCacheProcessor,
    store_config::StoreConfig,
    supersets::MultiPhaseAggregateAndProofSets as AggregateAndProofSupersets,
    validations::validate_merge_block,
    AttestationOrigin, ExecutionPayloadBidAction, ExecutionPayloadBidOrigin,
    ExecutionPayloadEnvelopeAction, ExecutionPayloadEnvelopeOrigin, PayloadAttestationAction,
    PayloadAttestationItem, PayloadAttestationValidationError, ValidPayloadAttestation,
};

/// [`Store`] from the Fork Choice specification.
///
/// [`Store`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#store
#[expect(clippy::type_complexity)]
#[derive(Clone)]
pub struct Store<P: Preset, S: Storage<P>> {
    chain_config: Arc<ChainConfig>,
    pubkey_cache: Arc<PubkeyCache>,
    store_config: StoreConfig,
    // The fork choice rule does not need a precise timestamp.
    tick: Tick,
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    unrealized_finalized_checkpoint: Checkpoint,
    // It would be more idiomatic to make `Store.proposer_boost_root` an `Option<H256>`, but that
    // only gets in the way. `consensus-spec-tests` expects `proposer_boost_root` to be retained
    // even when the corresponding block is pruned. This forces `Store::score` to check whether the
    // block is still present in the store, which is slightly more difficult with an `Option`.
    // Using `None` to represent an unset root would also be a deviation from `consensus-specs`,
    // though it would only matter in an extremely unlikely edge case that `consensus-specs` assumes
    // won't happen.
    proposer_boost_root: H256,
    equivocating_indices: HashSet<ValidatorIndex>,
    // This contains blocks starting with the anchor and ending with the last finalized block.
    finalized: Vector<ChainLink<P>>,
    // If `Store.unfinalized` has any elements, the number of them indicates the number of forks.
    // Some of the forks may be non-viable. If the anchor is not the genesis block, all of them may
    // be non-viable.
    //
    // If `Store.unfinalized` is empty, there is only one fork stored entirely in `Store.finalized`
    // and it is considered viable. Currently this fork is assumed to consist of a single block, but
    // that may no longer be true when persistence is implemented.
    unfinalized: OrdMap<SegmentId, Segment<P>>,
    finalized_indices: HashMap<H256, usize>,
    unfinalized_locations: HashMap<H256, Location>,
    // `Store.head_segment_id` holds the ID of the segment in `Store.unfinalized` whose last block
    // is the head. A `None` in `Store.head_segment_id` indicates that there are no viable forks in
    // `Store.unfinalized`.
    head_segment_id: Option<SegmentId>,
    // `Store.justified_active_balances` is a cache used to speed up validator balance lookups.
    // Repeatedly looking them up in `BeaconState.validators` is costly because `PersistentList` is
    // implemented as a tree.
    justified_active_balances: Arc<[Gwei]>,
    // Cached timely proposer score derived from `Store.justified_active_balances`.
    timely_proposer_score: OnceLock<Gwei>,
    // Long-lived forks can theoretically have different validator registries.
    // That makes validator indices ambiguous, but the fork choice store is unaffected.
    // The fork choice store only deals with active validator indices, which cannot diverge.
    // Validators can only become eligible for activation after they are finalized.
    latest_messages: Vector<Option<Arc<LatestMessage>>>,
    // `consensus-specs` doesn't explicitly state it, but `Store.checkpoint_states` is effectively a
    // cache, as its contents can be recomputed at any time using data from other fields.
    //
    // The fork choice rule only uses a few fields from `BeaconState`, so keeping states around in
    // their entirety isn't necessary. We don't bother optimizing this for two reasons:
    // - Most helper functions require an entire `BeaconState` as a parameter. This can be worked
    //   around in several ways (by adding traits exposing the required fields, by duplicating the
    //   logic, or by creating fictitious `BeaconState`s).
    // - Due to structural sharing in our SSZ collections, omitting the fields saves barely any
    //   memory at all (~10 MB out of ~3.74 GB when processing tens of thousands of blocks, and even
    //   that might be random fluctuation).
    //
    // There is another potential optimization: committees can be computed 1 epoch ahead, so the
    // checkpoint states don't even have to be in the right epoch. This suffers from the helper
    // function problem described above as well as additional ones:
    // - The optimization only applies if the first slot in the epoch as attested to was empty.
    // - Obtaining active balances from the justified state requires it to be in the right epoch.
    checkpoint_states: HashMap<Checkpoint, Arc<BeaconState<P>>>,
    // TODO(Grandine Team): Process current slot attestations incrementally to speed up
    //                      `Store::apply_tick`. Update the comment to match the new design.
    //
    //                      # Design #1: Precompute balance differences
    //
    //                      Replace `Store.current_slot_attestations` with:
    //                      ```
    //                      current_slot_messages: Vector<Option<Arc<LatestMessage>>>,
    //                      current_slot_differences: HashMap<H256, Difference>,
    //                      ```
    //
    //                      Apply precomputed differences in `Store::apply_tick`:
    //                      ```
    //                      self.latest_messages = self.current_slot_messages.clone();
    //
    //                      let current_slot_differences = core::mem::take(&mut self.current_slot_differences);
    //
    //                      self.apply_balance_differences(current_slot_differences)?;
    //                      ```
    //
    //                      `Store::attestation_balance_differences` should check if a later vote is
    //                      already present in `Store.current_slot_messages` when processing a past
    //                      attestation and modify `Store.current_slot_differences` to account for it.
    //
    //                      `Store::update_balances_after_justification` and
    //                      `Store.apply_attester_slashing` should also update
    //                      `Store.current_slot_differences`.
    //
    //                      # Design #2: Precompute attesting balances
    //
    //                      Generalize `Segment` to store arbitrary elements:
    //                      ```
    //                      struct Segment<T> {
    //                          elements: Vector<T>,
    //                          first_position: Position,
    //                      }
    //
    //                      type Forest<T> = OrdMap<SegmentId, Segment<T>>;
    //                      ```
    //
    //                      Store attesting balances separately from blocks:
    //                      ```
    //                      struct Store {
    //                          …
    //                          unfinalized: Forest<ChainLink<P>>,
    //                          latest_messages: Vector<Option<Arc<LatestMessage>>>,
    //                          attesting_balances: Forest<Gwei>,
    //                          current_slot_messages: Vector<Option<Arc<LatestMessage>>>,
    //                          current_slot_attesting_balances: Forest<Gwei>,
    //                          …
    //                      }
    //                      ```
    //
    //                      Update attesting balances in `Store::apply_tick`:
    //                      ```
    //                      self.latest_messages = self.current_slot_messages.clone();
    //                      self.attesting_balances = self.current_slot_attesting_balances.clone();
    //                      ```
    //
    // Attestations cannot affect fork choice until their slots have passed.
    // This field is used to store them in the meantime.
    current_slot_attestations: Vector<ValidAttestation<P>>,

    // ePBS:(dual location map) Both empty and full variants keyed by beacon_block_root
    // - Empty variants: beacon block without execution payload
    // - Full variants: beacon block + execution payload (envelope.beacon_block_root)
    unfinalized_locations_empty: HashMap<H256, Location>,
    unfinalized_locations_full: HashMap<H256, Location>,
    // ePBS: Tracks PTC (Payload Timeliness Committee) votes for each block root.
    // Used to determine if payload arrived on time.
    // Not mentioned in the spec to use BitVector
    // spec(gloas): https://github.com/ethereum/consensus-specs/blob/915907a6ed6d753bbbee4919a41a1e5b8a6a2d96/specs/gloas/fork-choice.md?plain=1#L148
    ptc_vote: HashMap<H256, BitVector<P::PtcSize>>,
    // spec(gloas): https://github.com/ethereum/consensus-specs/blob/915907a6ed6d753bbbee4919a41a1e5b8a6a2d96/specs/gloas/fork-choice.md?plain=1#L139
    // Blocks that arrived before the PTC deadline (current slot + before tick 12).
    // Used by should_apply_proposer_boost() to detect equivocations.
    // Unlike attestation timeliness (computed inline), PTC timeliness must be stored
    // because should_apply_proposer_boost() scans past blocks.
    ptc_timely_blocks: HashSet<H256>,
    execution_payload_locations: HashMap<ExecutionBlockHash, Location>,
    aggregate_and_proof_supersets: Arc<AggregateAndProofSupersets<P>>,
    accepted_blob_sidecars:
        HashMap<(Slot, ValidatorIndex, BlobIndex), HashMap<H256, KzgCommitment>>,
    accepted_data_column_sidecars: HashMap<
        (Slot, ValidatorIndex, ColumnIndex),
        HashMap<H256, ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    >,
    accepted_gloas_data_column_sidecars: HashMap<(H256, ColumnIndex), Slot>,
    accepted_payload_bids: HashMap<Slot, HashMap<BuilderIndex, Arc<SignedExecutionPayloadBid<P>>>>,
    accepted_execution_payload_envelopes: HashSet<(Slot, H256, ValidatorIndex)>,
    blob_cache: BlobCache<P>,
    state_cache: Arc<StateCacheProcessor<P>>,
    storage: Arc<S>,
    data_column_cache: DataColumnCache<P>,
    execution_payload_envelope_cache: ExecutionPayloadEnvelopeCache<P>,
    rejected_block_roots: HashSet<H256>,
    finished_initial_forward_sync: bool,
    finished_back_sync: bool,
    blacklisted_blocks: StdHashSet<H256>,
    sampling_columns: StdHashSet<ColumnIndex>,
    sidecars_construction_started: Arc<DashMap<H256, Slot>>,
    requested_blobs_from_el: HashMap<H256, Slot>,
}

impl<P: Preset, S: Storage<P>> Store<P, S> {
    /// [`get_forkchoice_store`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_forkchoice_store)
    #[expect(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        pubkey_cache: Arc<PubkeyCache>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        storage: Arc<S>,
        finished_initial_forward_sync: bool,
        finished_back_sync: bool,
        mut blacklisted_blocks: StdHashSet<H256>,
        sidecars_construction_started: Arc<DashMap<H256, Slot>>,
    ) -> Self {
        let block_root = anchor_block.message().hash_tree_root();
        let state_root = anchor_state.hash_tree_root();

        assert!(misc::is_epoch_start::<P>(anchor_block.message().slot()));
        assert_eq!(anchor_block.message().state_root(), state_root);
        assert_eq!(accessors::latest_block_root(&anchor_state), block_root);

        let epoch = accessors::get_current_epoch(&anchor_state);

        // Note that if `anchor_state` is the genesis state, this checkpoint will not be equal to
        // any checkpoints in it, because all checkpoints in a genesis state have their `root` set
        // to 0x00…00.
        let checkpoint = Checkpoint {
            epoch,
            root: block_root,
        };

        // Anchor state is always pre-execution (block_state). Post-execution states
        // are rejected at checkpoint sync ingestion. No execution_payload_state for anchors.
        let execution_payload_state = None;

        let anchor = ChainLink {
            block_root,
            block: anchor_block,
            block_state: Some(anchor_state.clone_arc()),
            execution_payload_state,
            current_justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            payload_status: Self::initial_payload_status(&anchor_state),
        };

        let validator_count = anchor_state.validators().len_usize();
        let latest_messages = core::iter::repeat_n(None, validator_count).collect();

        blacklisted_blocks.extend(chain_config.blacklisted_blocks.iter());

        Self {
            chain_config,
            pubkey_cache,
            store_config,
            tick: Tick::start_of_slot(anchor_state.slot()),
            justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            proposer_boost_root: H256::zero(),
            equivocating_indices: HashSet::new(),
            finalized: Vector::unit(anchor),
            unfinalized: ordmap! {},
            finalized_indices: HashMap::unit(block_root, 0),
            unfinalized_locations: hashmap! {},
            head_segment_id: None,
            justified_active_balances: Self::active_balances(&anchor_state),
            timely_proposer_score: OnceLock::new(),
            latest_messages,
            current_slot_attestations: vector![],
            unfinalized_locations_empty: hashmap! {},
            unfinalized_locations_full: hashmap! {},
            // For Gloas, anchor block should be in ptc_vote map
            // following every known block has a ptc_vote entry
            // dev notes: check if not in the map will give all false so that initialization is not required
            ptc_vote: if anchor_state.phase() >= Phase::Gloas {
                HashMap::unit(block_root, BitVector::default())
            } else {
                HashMap::default()
            },
            // Anchor block is considered PTC-timely
            ptc_timely_blocks: HashSet::unit(block_root),
            checkpoint_states: HashMap::unit(checkpoint, anchor_state),
            execution_payload_locations: hashmap! {},
            aggregate_and_proof_supersets: Arc::new(AggregateAndProofSupersets::new()),
            accepted_blob_sidecars: HashMap::default(),
            accepted_data_column_sidecars: HashMap::default(),
            accepted_gloas_data_column_sidecars: HashMap::default(),
            accepted_payload_bids: HashMap::default(),
            accepted_execution_payload_envelopes: HashSet::default(),
            blob_cache: BlobCache::default(),
            state_cache: Arc::new(StateCacheProcessor::new(
                store_config.state_cache_lock_timeout,
            )),
            storage,
            data_column_cache: DataColumnCache::default(),
            execution_payload_envelope_cache: ExecutionPayloadEnvelopeCache::default(),
            rejected_block_roots: HashSet::default(),
            finished_initial_forward_sync,
            finished_back_sync,
            blacklisted_blocks,
            sampling_columns: StdHashSet::default(),
            sidecars_construction_started,
            requested_blobs_from_el: HashMap::default(),
        }
    }

    #[must_use]
    pub fn chain_config(&self) -> &ChainConfig {
        &self.chain_config
    }

    #[must_use]
    pub const fn store_config(&self) -> StoreConfig {
        self.store_config
    }

    #[must_use]
    pub const fn tick(&self) -> Tick {
        self.tick
    }

    /// [`get_current_slot`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_current_slot)
    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.tick.slot
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.chain_config.phase_at_slot::<P>(self.slot())
    }

    #[must_use]
    pub fn previous_epoch(&self) -> Epoch {
        misc::previous_epoch(self.current_epoch())
    }

    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        Self::epoch_at_slot(self.slot())
    }

    #[must_use]
    pub fn anchor_epoch(&self) -> Epoch {
        Self::epoch_at_slot(self.anchor().slot())
    }

    #[must_use]
    pub fn cached_blob_sidecar_by_id(
        &self,
        blob_id: BlobIdentifier,
    ) -> Option<Arc<BlobSidecar<P>>> {
        self.blob_cache.get(blob_id)
    }

    #[must_use]
    pub fn cached_data_column_sidecar_by_id(
        &self,
        data_column_id: DataColumnIdentifier,
    ) -> Option<Arc<DataColumnSidecar<P>>> {
        self.data_column_cache.get(data_column_id)
    }

    #[must_use]
    pub fn cached_execution_payload_envelope_by_root(
        &self,
        block_root: H256,
    ) -> Option<Arc<SignedExecutionPayloadEnvelope<P>>> {
        self.execution_payload_envelope_cache.get(block_root)
    }

    #[must_use]
    pub fn accepted_payload_bid_at_slot(
        &self,
        slot: Slot,
    ) -> Option<&Arc<SignedExecutionPayloadBid<P>>> {
        self.accepted_payload_bids
            .get(&slot)?
            .values()
            .max_by_key(|bid| bid.message.value)
    }

    #[must_use]
    pub const fn justified_checkpoint(&self) -> Checkpoint {
        self.justified_checkpoint
    }

    #[must_use]
    pub const fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    #[must_use]
    pub const fn unrealized_justified_checkpoint(&self) -> Checkpoint {
        self.unrealized_justified_checkpoint
    }

    #[must_use]
    pub const fn justified_epoch(&self) -> Epoch {
        self.justified_checkpoint.epoch
    }

    #[must_use]
    pub const fn finalized_epoch(&self) -> Epoch {
        self.finalized_checkpoint.epoch
    }

    #[must_use]
    pub const fn finalized_root(&self) -> H256 {
        self.finalized_checkpoint.root
    }

    #[must_use]
    pub const fn finalized_slot(&self) -> Slot {
        Self::start_of_epoch(self.finalized_epoch())
    }

    #[must_use]
    pub const fn proposer_boost_root(&self) -> H256 {
        self.proposer_boost_root
    }

    #[must_use]
    pub const fn finalized(&self) -> &Vector<ChainLink<P>> {
        &self.finalized
    }

    #[must_use]
    pub const fn unfinalized(&self) -> &OrdMap<SegmentId, Segment<P>> {
        &self.unfinalized
    }

    fn lowest_unused_segment_id(&self) -> Result<SegmentId> {
        // A block cannot finalize itself, so once a child of the anchor is added to the store, the
        // number of unfinalized blocks cannot go down to zero. As a result of this, segment IDs
        // will never be reused.
        self.unfinalized
            .keys()
            .next_back()
            .copied()
            .map(SegmentId::next)
            .unwrap_or(Ok(SegmentId::FIRST))
    }

    /// Returns the chain link from the FULL-location map for unfinalized blocks,
    /// or from finalized storage when already finalized.
    ///
    /// In Gloas, unfinalized blocks are inserted as FULL placeholders, so callers
    /// that require the execution payload envelope must additionally check
    /// `chain_link.execution_payload_state.is_some()`.
    ///
    /// Finalized blocks are included, but FULL/EMPTY variant distinction is not
    /// retained after finalization. For strict unfinalized FULL-map checks, query
    /// `unfinalized_locations_full` directly.
    /// When this is used for envelope state, callers must handle payload-arrived
    /// vs payload-not-arrived explicitly (for example via `is_some()`).
    #[must_use]
    pub fn chain_link_full(&self, block_root: H256) -> Option<&ChainLink<P>> {
        if let Some(location) = self.unfinalized_locations_full.get(&block_root) {
            return Some(&self.unfinalized[&location.segment_id][location.position].chain_link);
        }
        // Finalized blocks included (variant not tracked after finalization)
        let index = self.finalized_indices.get(&block_root)?;

        Some(&self.finalized[*index])
    }

    #[must_use]
    pub fn block(&self, block_root: H256) -> Option<WithStatus<&Arc<SignedBeaconBlock<P>>>> {
        let chain_link = self.chain_link_full(block_root)?;

        Some(WithStatus {
            value: &chain_link.block,
            status: chain_link.payload_status,
            finalized: self.is_slot_finalized(chain_link.slot()),
        })
    }

    #[must_use]
    pub fn contains_block(&self, block_root: H256) -> bool {
        self.contains_unfinalized_block(block_root)
            || self.finalized_indices.contains_key(&block_root)
    }

    pub fn contains_block_and_data_available(&self, block_root: H256) -> bool {
        let is_block_imported = self.contains_block(block_root);
        let is_pre_gloas = self
            .block(block_root)
            .map(|chain_link| chain_link.value.phase() < Phase::Gloas)
            .unwrap_or(false);

        is_block_imported
            && (is_pre_gloas
                || self
                    .cached_execution_payload_envelope_by_root(block_root)
                    .is_some())
    }

    fn contains_unfinalized_block(&self, block_root: H256) -> bool {
        self.unfinalized_locations_full.contains_key(&block_root)
    }

    /// Get payload status for a node at a specific location.
    /// - EMPTY: location is in unfinalized_locations_empty
    /// - PENDING: location is in unfinalized_locations_full but execution_payload_state is None
    /// - FULL: location is in unfinalized_locations_full and execution_payload_state is Some
    /// Uses local store view for the given location, not parent-bid inference.
    /// For parent-variant inference, use `get_parent_payload_status`.
    /// Pre-Gloas nodes are expected to be in `unfinalized_locations_full` and map to `Full`.
    #[must_use]
    fn node_payload_status_at(&self, location: Location) -> ForkChoicePayloadStatus {
        let chain_link = &self.unfinalized[&location.segment_id][location.position].chain_link;
        let block_root = chain_link.block_root;

        // Check if this location is the EMPTY variant
        if self.unfinalized_locations_empty.get(&block_root) == Some(&location) {
            return ForkChoicePayloadStatus::Empty;
        }

        // FULL variant - check bid existence (pre-Gloas / no bid -> Full)
        let has_bid = chain_link
            .block
            .message()
            .body()
            .with_payload_bid()
            .is_some();
        if !has_bid {
            // Pre-Gloas block: payload is intrinsic to the beacon block.
            return ForkChoicePayloadStatus::Full;
        }

        // Bid exists → Pending or Full based on payload arrival
        if chain_link.execution_payload_state.is_some() {
            ForkChoicePayloadStatus::Full
        } else {
            ForkChoicePayloadStatus::Pending
        }
    }

    /// Get parent payload status for fork choice.
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice#get_parent_payload_status
    /// FULL if current bid's parent_block_hash matches parent bid's block_hash.
    /// EMPTY otherwise (child builds on parent's empty variant).
    #[must_use]
    fn get_parent_payload_status(&self, block_root: H256) -> ForkChoicePayloadStatus {
        let Some(current) = self.chain_link_full(block_root) else {
            return ForkChoicePayloadStatus::Empty;
        };

        let Some(current_gloas_body) = current.block.message().body().with_payload_bid() else {
            return ForkChoicePayloadStatus::Full; // Pre-Gloas
        };

        let parent_root = current.block.message().parent_root();
        let Some(parent) = self.chain_link_full(parent_root) else {
            return ForkChoicePayloadStatus::Empty;
        };

        let Some(parent_gloas_body) = parent.block.message().body().with_payload_bid() else {
            return ForkChoicePayloadStatus::Full; // Pre-Gloas parent
        };

        let parent_bid = &parent_gloas_body.signed_execution_payload_bid().message;
        let current_bid = &current_gloas_body.signed_execution_payload_bid().message;

        // Parent is full if current bid's parent_block_hash matches parent bid's block_hash
        if current_bid.parent_block_hash == parent_bid.block_hash {
            ForkChoicePayloadStatus::Full
        } else {
            ForkChoicePayloadStatus::Empty
        }
    }

    /// Check if parent node has execution payload processed (is full variant).
    ///
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice#is_parent_node_full
    #[must_use]
    fn is_parent_node_full(&self, block_root: H256) -> bool {
        self.get_parent_payload_status(block_root).is_full()
    }

    /// Checks if a block builds on the FULL variant of its consensus parent
    /// by comparing bid's `parent_block_hash` against parent's `block_hash`.
    /// Only called for Gloas blocks (callers guard with `with_payload_bid()`).
    /// different from get_parent_payload_status as this is for blocks which are not in the store yet so cant use store maps for incoming block here
    #[must_use]
    pub fn is_parent_node_full_for_block(&self, block: &SignedBeaconBlock<P>) -> bool {
        let parent_root = block.message().parent_root();

        // Finalized pre-Gloas parents are always FULL (payload intrinsic to block).
        // Gloas finalized parents fall through to bid comparison below.
        if let Some(index) = self.finalized_indices.get(&parent_root) {
            if self.finalized[*index].block.phase() < Phase::Gloas {
                return true;
            }
        }

        let Some(parent) = self.chain_link_full(parent_root) else {
            return false;
        };

        let Some(parent_gloas_body) = parent.block.message().body().with_payload_bid() else {
            return true; // Pre-Gloas parent
        };

        let Some(current_gloas_body) = block.message().body().with_payload_bid() else {
            return false;
        };

        // Genesis/default block_hash is zero — no envelope concept, not FULL.
        // See: https://github.com/ethereum/consensus-specs/issues/5043
        let parent_block_hash = parent_gloas_body
            .signed_execution_payload_bid()
            .message
            .block_hash;

        if parent_block_hash == H256::zero() {
            return false;
        }

        current_gloas_body
            .signed_execution_payload_bid()
            .message
            .parent_block_hash
            == parent_block_hash
    }

    /// Check if payload was timely.
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice#is_payload_timely
    /// True if locally available AND PTC votes > THRESHOLD (256).
    /// PAYLOAD_TIMELY_THRESHOLD = PTC_SIZE // 2 = 512 // 2 = 256.
    #[must_use]
    fn is_payload_timely(&self, block_root: H256) -> bool {
        // Check if we have PTC votes for this block
        let Some(ptc_votes) = self.ptc_vote.get(&block_root) else {
            return false;
        };

        // Check if payload is locally available (has full variant with execution state)
        // Note: Spec's `store.execution_payload_states` is never pruned, but our
        // `unfinalized_locations_full` is pruned on finalization/orphaning. This is safe
        // because the only caller (`should_extend_payload`) is used during head selection,
        // which only considers unfinalized blocks.
        let Some(location) = self.unfinalized_locations_full.get(&block_root) else {
            return false;
        };
        // Check payload actually arrived (not just FULL placeholder)
        if self.unfinalized[&location.segment_id][location.position]
            .chain_link
            .execution_payload_state
            .is_none()
        {
            return false;
        }

        // Count PTC votes (PAYLOAD_TIMELY_THRESHOLD = PTC_SIZE / 2 = 256)
        let vote_count = ptc_votes.count_ones();
        let threshold = P::PtcSize::USIZE / 2;

        vote_count > threshold
    }

    /// Decides if payload from previous slot should be extended.
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/fork-choice.md?plain=1#L307
    /// Used as tiebreaker between EMPTY/FULL variants from previous slot.
    /// TRUE if timely, no boost, boost conflicts, or boost extends payload.
    #[must_use]
    fn should_extend_payload(&self, block_root: H256) -> bool {
        // Condition 1: Payload was timely (PTC voted for it)
        if self.is_payload_timely(block_root) {
            return true;
        }

        let proposer_root = self.proposer_boost_root;

        // Condition 2: No proposer boost set
        if proposer_root == H256::zero() {
            return true;
        }

        // Get proposer boost block
        let Some(proposer_block) = self.chain_link_full(proposer_root) else {
            return true; // Can't verify, default to extend
        };

        let proposer_parent = proposer_block.block.message().parent_root();

        // Condition 3: Proposer boost does not build on this blokc
        if proposer_parent != block_root {
            return true;
        }

        // Condition 4: Proposer boost builds on FULL variant
        self.is_parent_node_full(proposer_root)
    }

    /// Spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.0/specs/gloas/fork-choice.md?plain=1#L328
    /// Previous-slot tiebreaker: FULL (timely) = 2 > EMPTY = 1 > FULL (late) = 0.
    #[must_use]
    fn get_payload_status_tiebreaker(
        &self,
        block_root: H256,
        payload_status: ForkChoicePayloadStatus,
    ) -> u8 {
        if payload_status.is_pending() {
            return payload_status as u8;
        }

        let is_previous_slot = self
            .chain_link_full(block_root)
            .is_some_and(|b| b.block.message().slot() + 1 == self.slot());

        if !is_previous_slot {
            return payload_status as u8;
        }

        if payload_status.is_empty() {
            1
        } else if self.should_extend_payload(block_root) {
            2
        } else {
            0
        }
    }

    /// ePBS: Extract PTC votes from block's payload_attestations.
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/915907a6ed6d753bbbee4919a41a1e5b8a6a2d96/specs/gloas/fork-choice.md?plain=1#L181
    /// Populates ptc_vote map used by is_payload_timely().
    /// Called during on_block().
    fn notify_ptc_messages(
        &mut self,
        block_root: H256,
        block: &SignedBeaconBlock<P>,
        state: &Arc<BeaconState<P>>,
    ) -> Result<()> {
        // Initialize empty BitVector for the root if it doesn't exist yet
        self.ptc_vote
            .entry(block_root)
            .or_insert_with(BitVector::default);

        // Only process Gloas blocks (pre-Gloas has no payload_attestations)
        let Some(gloas_body) = block.message().body().with_payload_attestations() else {
            return Ok(());
        };

        //using valid payload attestation as apply_payload_attestation_batch takes valid payload attestation.
        let mut valid_payload_attestations = Vec::new();

        // use the state(chainlink_full.block_state) at apply_block to get index payload attestsions
        for payload_attestation in gloas_body.payload_attestations() {
            let indexed = accessors::get_indexed_payload_attestation(state, payload_attestation)?;
            //use the same loop to get ptc members for the slot to later check
            let ptc_members = accessors::get_ptc(state, payload_attestation.data.slot)?;

            // use the indexed attestation data to create valid payload attestation for the actual apply_payload_attestation_batch call + a ptc membership check for the validator index
            for validator_index in indexed.attesting_indices {
                let positions = ptc_members
                    .iter()
                    .positions(|&member| validator_index == member)
                    .collect_vec();

                // dev notes: in the gossip payload attestation flow, the ptc members check has been done before apply_payload_attestation_message inside validation_payload_attestation
                // as we are not calling that validate function for block payload attestation, we need to do that check here to follow the spec. don't want to introduce a duplicate get ptc call
                // to apply_payload_attestation_message. the validate_payload_attestation_message has extra steps (current-slot, signature)
                ensure!(
                    !positions.is_empty(),
                    Error::<P>::PayloadAttestationNotInCommittee {
                        validator_index,
                        slot: payload_attestation.data.slot,
                    }
                );

                valid_payload_attestations.push(ValidPayloadAttestation {
                    data: payload_attestation.data,
                    attesting_indices_positions: vec![(validator_index, positions)],
                    is_from_block: true,
                });
            }
        }

        self.apply_payload_attestation_batch(valid_payload_attestations)?;

        Ok(())
    }

    #[must_use]
    pub fn exhibits_equivocation_on_blobs(
        &self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        block_root: H256,
    ) -> bool {
        let phase = self.chain_config().phase_at_slot::<P>(slot);
        if phase.is_peerdas_activated() {
            self.data_column_cache.exhibits_equivocation(
                slot,
                (phase < Phase::Gloas).then_some(proposer_index),
                block_root,
            )
        } else {
            self.blob_cache
                .exhibits_equivocation(slot, proposer_index, block_root)
        }
    }

    #[must_use]
    pub fn exhibits_equivocation_on_blocks(
        &self,
        slot: Slot,
        proposer_index: ValidatorIndex,
        block_root: H256,
    ) -> bool {
        self.unfinalized_locations_full.values().any(|location| {
            let Location {
                segment_id,
                position,
            } = location;

            let chain_link = &self.unfinalized[segment_id][*position].chain_link;

            chain_link.block.message().slot() == slot
                && chain_link.block.message().proposer_index() == proposer_index
                && chain_link.block_root != block_root
        })
    }

    #[must_use]
    pub fn state_by_state_root(&self, state_root: H256) -> Option<WithStatus<Arc<BeaconState<P>>>> {
        self.canonical_chain()
            .find(|chain_link| chain_link.block.message().state_root() == state_root)
            .map(|chain_link| WithStatus {
                value: chain_link.state(self),
                status: chain_link.payload_status,
                finalized: self.is_slot_finalized(chain_link.slot()),
            })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn state_by_block_root(&self, block_root: H256) -> Option<Arc<BeaconState<P>>> {
        self.chain_link_full(block_root)
            .map(|chain_link| chain_link.state(self))
    }

    #[must_use]
    pub fn anchor(&self) -> &ChainLink<P> {
        self.finalized
            .front()
            .expect("the store always contains at least one finalized block")
    }

    #[must_use]
    pub fn last_finalized(&self) -> &ChainLink<P> {
        self.finalized
            .back()
            .expect("the store always contains at least one finalized block")
    }

    #[must_use]
    pub fn justified_chain_link(&self) -> Option<&ChainLink<P>> {
        self.chain_link_full(self.justified_checkpoint.root)
    }

    #[must_use]
    pub fn chain_link_before_or_at(&self, slot: Slot) -> Option<&ChainLink<P>> {
        self.unfinalized_before_or_at(slot)
            .or_else(|| self.finalized_before_or_at(slot))
    }

    #[must_use]
    pub fn finalized_before_or_at(&self, slot: Slot) -> Option<&ChainLink<P>> {
        let index = match self.finalized.binary_search_by_key(&slot, ChainLink::slot) {
            Ok(index) => index,
            Err(0) => return None,
            Err(nonzero) => nonzero - 1,
        };

        Some(&self.finalized[index])
    }

    fn unfinalized_before_or_at(&self, slot: Slot) -> Option<&ChainLink<P>> {
        self.canonical_chain_segments()
            .find_map(|(segment, position)| {
                segment
                    .block_before_or_at(slot, position)
                    .filter(|block| block.non_invalid())
            })
            .map(|unfinalized_block| &unfinalized_block.chain_link)
    }

    #[must_use]
    pub fn unfinalized_chain_link_by_execution_block_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Option<&ChainLink<P>> {
        let Location {
            segment_id,
            position,
        } = self.execution_payload_locations.get(&block_hash)?;

        Some(&self.unfinalized[segment_id][*position].chain_link)
    }

    #[must_use]
    /// Uses unfinalized_locations_full to ensure we only touch FULL variants,
    pub fn unfinalized_chain_link_mut(&mut self, block_root: H256) -> Option<&mut ChainLink<P>> {
        let Location {
            segment_id,
            position,
        } = self.unfinalized_locations_full.get(&block_root)?;

        Some(&mut self.unfinalized[segment_id][*position].chain_link)
    }

    pub fn unfinalized_fork_tips(&self) -> impl Iterator<Item = &ChainLink<P>> {
        self.unfinalized()
            .values()
            .filter_map(Segment::last_non_invalid_block)
            .map(|unfinalized_block| &unfinalized_block.chain_link)
    }

    // TODO(Grandine Team): The Optimistic Sync specification says that a node whose forks are all
    //                      non-viable due to invalid payloads should be considered optimistic, but
    //                      it's not clear if that means Eth Beacon Node API responses should have
    //                      `execution_optimistic` set to `true`. Even if all forks are non-viable,
    //                      the block that is returned as fallback may have `PayloadStatus::Valid`.
    //
    //                      Consider making `head` return `WithStatus<&ChainLink<P>>` and combining
    //                      the two `WithStatus.optimistic` fields in `fork_choice_control::queries`.
    /// Returns the head of the canonical chain, which may be optimistic.
    ///
    /// Corresponds to [`get_head`] from the Fork Choice specification.
    ///
    /// Other [`Store`] methods should only call this when the [`Store`] is in a consistent state.
    /// The assertions about segment viability inside the method may fail otherwise.
    /// See `handles_blocks_after_non_genesis_anchor_and_remains_without_viable_forks_for_1_epoch`
    /// in `fork_choice_control::extra_tests`.
    ///
    /// [`get_head`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_head
    #[must_use]
    pub fn head(&self) -> &ChainLink<P> {
        if let Some(unfinalized_block) = self.unfinalized_head() {
            return &unfinalized_block.chain_link;
        }

        let no_viable_segments = !self
            .unfinalized
            .values()
            .any(|segment| self.is_segment_viable(segment));

        assert!(no_viable_segments);

        if self.unfinalized.is_empty() {
            // This assertion may become incorrect if full persistence is ever implemented.
            assert_eq!(self.finalized.len(), 1);
        }

        if !self.unfinalized.is_empty() && self.anchor_epoch() == GENESIS_EPOCH {
            // There are multiple reasons why a fork choice store may have no viable forks:
            // - There may be no blocks past the anchor.
            // - The anchor may be a non-genesis block.
            // - The fork choice store may be poisoned.
            // The condition above eliminates the first two.
            //
            // See the Optimistic Sync specification for more information:
            // - [Definition of an optimistic node].
            // - [Fork choice poisoning].
            //
            // [Definition of an optimistic node]: https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/sync/optimistic.md#helpers
            // [Fork choice poisoning]:            https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/sync/optimistic.md#fork-choice-poisoning
            assert!(self.is_poisoned());
        }

        if let Some(justified_chain_link) = self.justified_chain_link() {
            // The fork choice rule starts from the justified block.
            // It is returned as fallback if no viable forks exist.
            //
            // Without optimistic sync this would be equivalent to returning the anchor.
            // This would only be reached when the anchor is the justified block.
            return justified_chain_link;
        }

        // This should only be reached if the justified block gets pruned.
        // See `survives_and_recovers_from_justified_block_being_pruned` in
        // `fork_choice_control::extra_tests`.
        //
        // A fully compliant implementation should return an orphaned block as the head.
        // Our implementation cannot do so because it prunes orphaned blocks as soon as possible.
        // The last finalized block would be more recent and potentially more useful,
        // but the anchor is closer to what's specified and potentially safer.
        self.anchor()
    }

    #[must_use]
    pub fn unfinalized_head(&self) -> Option<&UnfinalizedBlock<P>> {
        self.head_segment()?.last_non_invalid_block()
    }

    #[must_use]
    pub fn has_envelope(&self, block_root: H256) -> bool {
        // Pre-Gloas blocks have no envelope concept — treat as always available
        if self.phase() < Phase::Gloas {
            return true;
        }
        // Check FULL location exists AND has execution_payload_state (envelope arrived)
        let Some(location) = self.unfinalized_locations_full.get(&block_root) else {
            return false;
        };
        self.unfinalized[&location.segment_id][location.position]
            .chain_link
            .execution_payload_state
            .is_some()
    }

    /// Get the slot of a block by its root.
    #[must_use]
    pub fn block_slot(&self, block_root: H256) -> Option<Slot> {
        self.chain_link_full(block_root).map(ChainLink::slot)
    }

    /// [`is_data_available`](https://github.com/ethereum/consensus-specs/blob/7e33b9f9de37f02e711aa534dcc72e9880e551e2/specs/gloas/fork-choice.md?plain=1#L756)
    /// note: this currently does not follow spec. reuses contains_block_and_data_available
    /// TBD: clarification on retrieve_column_sidecars_and_kzg_commitments function acc to spec. final chagnes(with is_data_available_for_envelope) after 1.7.2 becasue of major changes
    #[must_use]
    pub fn is_data_available(&self, block_root: H256) -> bool {
        self.contains_block_and_data_available(block_root)
    }

    fn head_segment(&self) -> Option<&Segment<P>> {
        let segment_id = self.head_segment_id?;
        Some(&self.unfinalized[&segment_id])
    }

    pub fn canonical_chain(&self) -> impl Iterator<Item = &ChainLink<P>> {
        self.unfinalized_canonical_chain()
            .chain(self.finalized.iter().rev())
    }

    pub fn unfinalized_canonical_chain(&self) -> impl Iterator<Item = &ChainLink<P>> {
        self.canonical_chain_segments()
            .flat_map(|(segment, position)| segment.chain_ending_at(position))
            .skip_while(|chain_link| chain_link.is_invalid())
    }

    pub fn canonical_chain_segments(&self) -> impl Iterator<Item = (&Segment<P>, Position)> {
        self.head_segment_id
            .into_iter()
            .flat_map(move |head_segment_id| {
                let head_segment = &self.unfinalized[&head_segment_id];
                self.segments_ending_with(head_segment, head_segment.last_position())
            })
    }

    pub fn chain_ending_with(&self, block_root: H256) -> impl Iterator<Item = &ChainLink<P>> {
        if let Some(location) = self.unfinalized_locations_full.get(&block_root).copied() {
            let segment = &self.unfinalized[&location.segment_id];

            return self
                .unfinalized_chain_ending_with(segment, location.position)
                .chain(self.finalized.iter().rev())
                .pipe(Either::Left);
        }

        let length = self
            .finalized_indices
            .get(&block_root)
            .map(|index| index + 1)
            .unwrap_or_default();

        self.finalized.iter().take(length).rev().pipe(Either::Right)
    }

    fn unfinalized_chain_ending_with<'store>(
        &'store self,
        segment: &'store Segment<P>,
        last_included: Position,
    ) -> impl Iterator<Item = &'store ChainLink<P>> {
        self.segments_ending_with(segment, last_included)
            .flat_map(|(segment, position)| segment.chain_ending_at(position))
    }

    fn segments_ending_with<'store>(
        &'store self,
        segment: &'store Segment<P>,
        last_included: Position,
    ) -> impl Iterator<Item = (&'store Segment<P>, Position)> {
        core::iter::successors(Some((segment, last_included)), move |(segment, _)| {
            let parent_location = self.parent_location(segment)?;
            let parent = &self.unfinalized[&parent_location.segment_id];
            Some((parent, parent_location.position))
        })
    }

    fn is_root(&self, segment: &Segment<P>) -> bool {
        segment
            .first_block()
            .chain_link
            .block
            .message()
            .parent_root()
            == self.last_finalized().block_root
    }

    fn parent_location(&self, segment: &Segment<P>) -> Option<Location> {
        segment.parent_location()
    }

    // Finality of a block or state can be determined by comparing its slot with the finalized slot.
    // That should be correct because our implementation prunes orphans as soon as possible.
    #[must_use]
    pub const fn is_slot_finalized(&self, slot: Slot) -> bool {
        slot <= self.finalized_slot()
    }

    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        if self.unfinalized.is_empty() {
            return false;
        }

        self.unfinalized
            .values()
            .map(Segment::last_block)
            .filter(|block| self.is_block_viable(block))
            .all(UnfinalizedBlock::is_invalid)
    }

    #[must_use]
    pub fn is_segment_viable(&self, segment: &Segment<P>) -> bool {
        segment
            .last_non_invalid_block()
            .is_some_and(|block| self.is_block_viable(block))
    }

    // If the anchor is a non-genesis block, no blocks will be viable for at least 2/3 of an epoch.
    // The anchor feature is underdeveloped and poorly specified, so this might not be intended.
    fn is_block_viable(&self, unfinalized_block: &UnfinalizedBlock<P>) -> bool {
        let voting_source = self.voting_source(unfinalized_block);

        // > The voting source should be at the same height as the store's justified checkpoint or
        // > not more than two epochs ago
        let correct_justified = self.justified_epoch() == GENESIS_EPOCH
            || voting_source.epoch == self.justified_checkpoint.epoch
            || voting_source.epoch + 2 >= self.current_epoch();

        // `correct_finalized` should always be true because our implementation prunes orphans as
        // soon as possible. We check it anyway to be safe.
        //
        // A note in the tests for `consensus-specs` implies `correct_finalized` can never be false:
        // <https://github.com/ethereum/consensus-specs/blob/v1.3.0/tests/core/pyspec/eth2spec/test/phase0/fork_choice/test_get_head.py#L628-L636>
        // That is because `filter_block_tree` is only ever called with the justified block or its
        // descendants, which is documented as a precondition in the Fork Choice specification:
        // <https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#filter_block_tree>
        // However, that relies on the invariant that the justified block is always a descendant of
        // the finalized block, which we know to be broken.
        let correct_finalized = 'block: {
            if self.finalized_epoch() == GENESIS_EPOCH {
                break 'block true;
            }

            let ancestor_at_finalized_slot = self
                .ancestor(
                    unfinalized_block.chain_link.block_root,
                    self.finalized_slot(),
                )
                .expect(
                    "every block in the store should have an ancestor at the last finalized slot",
                );

            ancestor_at_finalized_slot == self.finalized_checkpoint.root
        };

        correct_justified && correct_finalized
    }

    /// [`get_voting_source`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_voting_source)
    fn voting_source(&self, unfinalized_block: &UnfinalizedBlock<P>) -> Checkpoint {
        if self.current_epoch() > unfinalized_block.epoch() {
            // > The block is from a prior epoch, the voting source will be pulled-up
            unfinalized_block.chain_link.unrealized_justified_checkpoint
        } else {
            // > The block is not from a prior epoch, therefore the voting source is not pulled up
            unfinalized_block.chain_link.current_justified_checkpoint
        }
    }

    fn should_wait_for_justified_state(&self, checkpoint: Checkpoint) -> bool {
        // The comparison with `self.anchor_epoch()` is needed for two reasons:
        // - All checkpoints in a genesis state have their `root` set to 0x00…00. In contrast, the
        //   fork choice store uses the root of the anchor block to construct the first justified
        //   checkpoint. The latter will almost never equal 0x00…00, but the anchor state should
        //   already be present in `Store.checkpoint_states`.
        // - If the anchor state is not a genesis state, all checkpoints in it are from epochs prior
        //   to the anchor epoch. The corresponding states cannot be computed because that would
        //   require data predating the anchor.
        checkpoint.epoch > self.anchor_epoch() && !self.contains_checkpoint_state(checkpoint)
    }

    fn is_block_from_prior_epoch(&self, chain_link: &ChainLink<P>) -> bool {
        chain_link.epoch() < self.current_epoch()
    }

    /// Like [`get_weight`], but returns the full [`Score`] of a block including the tiebreaker.
    ///
    /// [`get_weight`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_weight
    ///
    /// Modified for Gloas (ePBS) to check `should_apply_proposer_boost` before applying boost.
    /// This prevents equivocating proposers from using proposer boost to reorg builders' payloads.
    fn score(&self, unfinalized_block: &UnfinalizedBlock<P>) -> Score {
        let attestation_score = unfinalized_block.attesting_balance;
        let tiebreaker = unfinalized_block.chain_link.block_root;

        // [Gloas] Equivocation protection may suppress boost.
        // Pre-Gloas: skip — should_apply_proposer_boost uses Gloas-specific checks
        // dev notes: in spec there is a pending check as well n+1 slot check, not required here, as we keep both nodes empty or full placeholder with same
        // slot votes, i.e update_head_segement_id will solve using payload status tiebreaker and root wont be a point of tiebreaking from here
        if self.phase() >= Phase::Gloas && !self.should_apply_proposer_boost() {
            return (attestation_score, tiebreaker);
        }

        // > Boost is applied if ``root`` is an ancestor of ``proposer_boost_root``
        //
        // The call to `Store::contains_unfinalized_block` is needed because `consensus-spec-tests`
        // expects `proposer_boost_root` to be retained even when the corresponding block is pruned.
        //
        // The "unfinalized block" in the `expect` message refers to the boosted block,
        // not the `unfinalized_block` parameter.
        let ancestor_of_boosted_block = self.contains_unfinalized_block(self.proposer_boost_root)
            && self
                .ancestor(self.proposer_boost_root, unfinalized_block.slot())
                .expect("every unfinalized block has an ancestor at every unfinalized slot")
                == unfinalized_block.chain_link.block_root;

        let proposer_score = if ancestor_of_boosted_block {
            // > Calculate proposer score if ``proposer_boost_root`` is set
            self.timely_proposer_score()
        } else {
            // > Return only attestation score if ``proposer_boost_root`` is not set
            0
        };

        // > Ties broken by favoring block with lexicographically higher root
        (attestation_score + proposer_score, tiebreaker)
    }

    fn timely_proposer_score(&self) -> Gwei {
        *self.timely_proposer_score.get_or_init(|| {
            let total_active_balance = self.justified_active_balances.iter().sum::<Gwei>();
            let committee_weight = total_active_balance / P::SlotsPerEpoch::non_zero();
            committee_weight * self.chain_config.proposer_score_boost / 100
        })
    }

    /// Calculate committee weight (total active balance / slots per epoch)
    fn committee_weight(&self) -> Gwei {
        let total_active_balance = self.justified_active_balances.iter().sum::<Gwei>();
        total_active_balance / P::SlotsPerEpoch::non_zero()
    }

    /// [`is_head_weak`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/fork-choice.md#is_head_weak)
    ///
    /// Check if a block is weak (has less than REORG_HEAD_WEIGHT_THRESHOLD% of committee weight).
    /// A weak head can be reorged by a timely proposer with proposer boost.
    ///
    /// Per spec, uses PAYLOAD_STATUS_PENDING (FULL placeholder) for weight calculation:
    /// `head_node = ForkChoiceNode(root=head_root, payload_status=PAYLOAD_STATUS_PENDING)`
    ///
    /// Gloas update: Adds equivocating validator weight from head slot committees for monotonicity.
    /// This ensures more attestations can only increase the weight, not decrease it.
    fn is_head_weak(&self, head_root: H256) -> bool {
        let committee_weight = self.committee_weight();
        let reorg_threshold =
            committee_weight * self.chain_config.reorg_head_weight_threshold / 100;

        // Get FULL placeholder's balance (PENDING state per spec)
        // Spec: head_node = ForkChoiceNode(root=head_root, payload_status=PAYLOAD_STATUS_PENDING)
        let mut head_weight = self
            .unfinalized_locations_full
            .get(&head_root)
            .map(|location| self.unfinalized[&location.segment_id][location.position].attesting_balance)
            .unwrap_or(0);

        // Get chain_link for equivocating weight calculation
        let Some(chain_link) = self.chain_link_full(head_root) else {
            return head_weight < reorg_threshold;
        };

        // [Gloas] Add equivocating validator weight from head slot committees
        // This ensures monotonicity: more attestations can only increase weight
        if let Some(head_state) = &chain_link.block_state {
            let head_slot = chain_link.slot();
            let epoch = misc::compute_epoch_at_slot::<P>(head_slot);
            let relative_epoch = if epoch == accessors::get_current_epoch(head_state) {
                RelativeEpoch::Current
            } else {
                RelativeEpoch::Previous
            };

            let justified_state = self.justified_state();
            let committee_count =
                accessors::get_committee_count_per_slot(head_state, relative_epoch);

            for index in 0..committee_count {
                if let Ok(committee) = accessors::beacon_committee(head_state, head_slot, index) {
                    for validator_index in committee.into_iter() {
                        if self.equivocating_indices.contains(&validator_index) {
                            // Add effective balance from justified state
                            if let Ok(validator) = justified_state.validators().get(validator_index)
                            {
                                head_weight += validator.effective_balance;
                            }
                        }
                    }
                }
            }
        }

        head_weight < reorg_threshold
    }

    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/fork-choice.md#new-should_apply_proposer_boost                            
    ///                                                                                                                                                           
    /// Returns false when the boosted block's parent is weak AND another PTC-timely                                                                                
    /// block from the same proposer exists (equivocation). True otherwise.
    fn should_apply_proposer_boost(&self) -> bool {
        // No boost root set means nothing to apply
        if self.proposer_boost_root == H256::zero() {
            return false;
        }

        // Get the boosted block
        let Some(boosted_chain_link) = self.chain_link_full(self.proposer_boost_root) else {
            return false;
        };

        let boosted_block = boosted_chain_link.block.message();
        let parent_root = boosted_block.parent_root();
        let slot = boosted_block.slot();

        // Get the parent block
        let Some(parent_chain_link) = self.chain_link_full(parent_root) else {
            warn_with_peers!(
                "missing parent for proposer boost evaluation: boost_root={:?}, parent_root={:?}",
                self.proposer_boost_root,
                parent_root,
            );
            return false; // Missing parent: cannot safely evaluate boost conditions
        };

        let parent_slot = parent_chain_link.slot();

        // Case 1: Apply proposer boost if parent is not from the previous slot
        // (i.e., there's a gap, so equivocation in previous slot doesn't affect us)
        if parent_slot + 1 < slot {
            return true;
        }

        // Case 2: Apply proposer boost if parent is not weak
        // (strong parent means equivocation can't cause a reorg anyway)
        // Per spec: is_head_weak uses PAYLOAD_STATUS_PENDING (FULL placeholder)
        if !self.is_head_weak(parent_root) {
            return true;
        }

        // Case 3: Parent is weak and from previous slot.
        // Check for equivocations from the same proposer that arrived before PTC deadline.
        let parent_proposer_index = parent_chain_link.block.message().proposer_index();

        let has_equivocation = self.unfinalized.values().any(|segment| {
            segment.into_iter().any(|unfinalized_block| {
                let block = unfinalized_block.chain_link.block.message();
                let equivocating_root = unfinalized_block.chain_link.block_root;
                let ptc_timely = self.ptc_timely_blocks.contains(&equivocating_root);

                ptc_timely
                    && block.proposer_index() == parent_proposer_index
                    && block.slot() == parent_slot
                    && equivocating_root != parent_root
            })
        });

        // Apply boost only if no equivocations detected
        !has_equivocation
    }

    /// [`get_ancestor`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_ancestor)
    ///
    /// This should never return `None` in normal operation, but the reasons for that are slightly
    /// different at each call site, so we call `Option::expect` every time we use this instead of
    /// changing the type.
    ///
    /// spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.0/specs/gloas/fork-choice.md#modified-get_ancestor
    /// Returns the block root of the ancestor at `ancestor_slot` on the chain ending at
    /// `descendant_root`. Returns `None` if no such ancestor exists.
    ///
    /// Note: The spec's ePBS version returns `(root, payload_status)`, but Grandine handles
    /// payload status via variant-aware segment structure, so we only return the root.
    /// This is not a major change, because even if an empty node is present, `extend_empty_segment`
    /// makes it a sibling of FULL. So when it is not a same-slot case, it is okay to traverse
    /// `unfinalized_full` (for the starting location); their parents/ancestors match.
    fn ancestor(&self, descendant_root: H256, ancestor_slot: Slot) -> Option<H256> {
        if let Some(location) = self
            .unfinalized_locations_full
            .get(&descendant_root)
            .copied()
        {
            let descendant_segment = &self.unfinalized[&location.segment_id];

            let chain_link = self
                .segments_ending_with(descendant_segment, location.position)
                .find_map(|(segment, position)| segment.block_before_or_at(ancestor_slot, position))
                .map(|unfinalized_block| &unfinalized_block.chain_link)
                .or_else(|| self.finalized_before_or_at(ancestor_slot))?;

            return Some(chain_link.block_root);
        }

        assert!(
            self.finalized_indices.contains_key(&descendant_root),
            "Store::ancestor should only be called with roots of blocks known to be in the store",
        );

        self.finalized_before_or_at(ancestor_slot)
            .map(|chain_link| chain_link.block_root)
    }

    #[must_use]
    pub fn common_ancestor(&self, a_root: H256, b_root: H256) -> Option<&ChainLink<P>> {
        itertools::merge_join_by(
            self.chain_ending_with(a_root),
            self.chain_ending_with(b_root),
            |a, b| a.slot().cmp(&b.slot()).reverse(),
        )
        .find_map(|either_or_both| match either_or_both {
            EitherOrBoth::Both(a, b) => core::ptr::eq(a, b).then_some(a),
            _ => None,
        })
    }

    fn justified_state(&self) -> &BeaconState<P> {
        self.checkpoint_states
            .get(&self.justified_checkpoint)
            .expect(
                "the waiting mechanism in the mutator combined with the checks in \
                 Store::validate_block should ensure that the justified state exists",
            )
    }

    pub fn contains_checkpoint_state(&self, checkpoint: Checkpoint) -> bool {
        self.checkpoint_states.contains_key(&checkpoint)
    }

    pub fn checkpoint_state(&self, checkpoint: Checkpoint) -> Option<&Arc<BeaconState<P>>> {
        self.checkpoint_states.get(&checkpoint)
    }

    pub fn insert_checkpoint_state(&mut self, checkpoint: Checkpoint, state: Arc<BeaconState<P>>) {
        self.checkpoint_states
            .insert(checkpoint, state)
            .expect_none(
                "the state corresponding to a particular checkpoint should only be inserted once; \
                 the mutator should only spawn one CheckpointStateTask per checkpoint",
            )
    }

    /// [`get_safe_execution_payload_hash`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/fork_choice/safe-block.md#get_safe_execution_payload_hash)
    #[must_use]
    pub fn safe_execution_payload_hash(&self) -> ExecutionBlockHash {
        self.justified_chain_link()
            .and_then(ChainLink::execution_block_hash)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn finalized_execution_payload_hash(&self) -> ExecutionBlockHash {
        // > As per EIP-3675, before a post-transition block is finalized,
        // > `notify_forkchoice_updated` MUST be called with `finalized_block_hash = Hash32()`.
        self.last_finalized()
            .execution_block_hash()
            .unwrap_or_default()
    }

    pub fn validate_block(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        state_root_policy: StateRootPolicy,
        data_availability_policy: DataAvailabilityPolicy,
        execution_engine: impl ExecutionEngine<P> + Send,
        verifier: impl Verifier + Send,
    ) -> Result<BlockAction<P>> {
        self.validate_block_with_custom_state_transition(block, data_availability_policy, |block_root, parent| {
            // > Make a copy of the state to avoid mutability issues
            let mut state = self
                .state_cache
                .before_or_at_slot(self, parent.block_root, block.message().slot())
                .unwrap_or_else(|| {
                    if Feature::WarnOnStateCacheSlotProcessing.is_enabled() && self.is_forward_synced()
                    {
                        // `Backtrace::force_capture` can be costly and a warning may be excessive,
                        // but this is controlled by a `Feature` that should be disabled by default.
                        warn_with_peers!(
                            "processing slots for beacon state not found in state cache before state transition \
                            (block root: {block_root:?}, parent block root: {:?}, from slot {} to {})\n{}",
                            parent.block_root,
                            parent.slot(),
                            block.message().slot(),
                            Backtrace::force_capture(),
                        );
                    }

                    parent.state(self)
                });

            // This validation was removed from Capella in `consensus-specs` v1.4.0-alpha.0.
            // See <https://github.com/ethereum/consensus-specs/pull/3232>.
            // It is unclear when modifications to fork choice logic should come into effect.
            // We check the phase of the block rather than the current slot.
            if block.phase() < Phase::Capella {
                // > [New in Bellatrix]
                //
                // The Fork Choice specification does this after the state transition.
                // We don't because that would require keeping around a clone of the pre-state.
                if let Some(body) = block
                    .message()
                    .body()
                    .with_execution_payload()
                    .filter(|body| predicates::is_merge_transition_block(&state, *body))
                {
                    match validate_merge_block(&self.chain_config, block, body, &execution_engine)?
                    {
                        PartialBlockAction::Accept => {}
                        PartialBlockAction::Ignore => return Ok((state, Some(BlockAction::Ignore(false)))),
                    }
                }
            }

            // > Check the block is valid and compute the post-state
            combined::custom_state_transition(
                &self.chain_config,
                &self.pubkey_cache,
                state.make_mut(),
                block,
                ProcessSlots::IfNeeded,
                state_root_policy,
                execution_engine,
                verifier,
                NullSlotReport,
            )?;

            Ok((state, None))
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn validate_gossip_rules(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        block_root: H256,
    ) -> Option<BlockAction<P>> {
        // Skip blocks that are already known.
        //
        // This is a slight deviation from `consensus-specs`, but it appears to be compatible with
        // both the fork choice rule and the Networking specification.
        if self.contains_block(block_root) {
            return Some(BlockAction::Ignore(true));
        }

        // > Blocks cannot be in the future.
        // > If they are, their consideration must be delayed until the are in the past.
        if self.slot() < block.message().slot() {
            return Some(BlockAction::DelayUntilSlot(block.clone_arc()));
        }

        // > Check that block is later than the finalized epoch slot
        //
        // This is redundant but may be faster than loading the parent block.
        if block.message().slot() <= self.finalized_slot() {
            return Some(BlockAction::Ignore(false));
        }

        // > Parent block must be known
        let Some(parent) = self.chain_link_full(block.message().parent_root()) else {
            return Some(BlockAction::DelayUntilParent(block.clone_arc()));
        };

        // > Check block is a descendant of the finalized block at the checkpoint finalized slot
        //
        // Checking the slot is sufficient because orphans are pruned as soon as possible.
        if parent.slot() < self.finalized_slot() {
            return Some(BlockAction::Ignore(false));
        }

        None
    }

    pub fn validate_block_for_gossip(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        state_transition_for_gossip: impl FnOnce(&ChainLink<P>) -> Result<Option<BlockAction<P>>>,
    ) -> Result<Option<BlockAction<P>>> {
        let block_root = block.message().hash_tree_root();

        if self.blacklisted_blocks.contains(&block_root) {
            bail!("blacklisted beacon block: (block root: {block_root:?})");
        }

        let block_action = self.validate_gossip_rules(block, block_root);

        if let Some(action) = block_action {
            return Ok(Some(action));
        }

        // > Parent block must be known
        let Some(parent) = self.chain_link_full(block.message().parent_root()) else {
            return Ok(Some(BlockAction::DelayUntilParent(block.clone_arc())));
        };

        // > Check the block is valid and compute the post-state
        state_transition_for_gossip(parent)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn validate_block_with_custom_state_transition(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        data_availability_policy: DataAvailabilityPolicy,
        state_transition: impl FnOnce(
            H256,
            &ChainLink<P>,
        ) -> Result<(Arc<BeaconState<P>>, Option<BlockAction<P>>)>,
    ) -> Result<BlockAction<P>> {
        let block_root = block.message().hash_tree_root();

        if self.blacklisted_blocks.contains(&block_root) {
            bail!("blacklisted beacon block: (block root: {block_root:?})");
        }

        let block_action = self.validate_gossip_rules(block, block_root);

        if let Some(action) = block_action {
            return Ok(action);
        }

        // > Parent(consensus parent) block must be known
        let Some(parent) = self.chain_link_full(block.message().parent_root()) else {
            return Ok(BlockAction::DelayUntilParent(block.clone_arc()));
        };

        // ePBS: If block claims to build on parent's FULL variant,
        // delay processing until the parent FULL chain_link has `execution_payload_state`.
        // (A different path in `insert_block` may resolve FULL parent via
        // `execution_payload_locations` using bid.parent_block_hash.)
        // note: most likely will be added in the spec as a validation rule for beacon block
        if block.message().body().with_payload_bid().is_some() {
            // Block builds on FULL if parent_block_hash matches parent's bid.block_hash
            let parent_full = self.is_parent_node_full_for_block(block);
            let has_parent_exec = parent.execution_payload_state.is_some();

            // Skip delay for pre-Gloas or finalized parents: their execution payload
            // has already been processed, so no envelope will arrive separately.
            let parent_root = block.message().parent_root();
            let parent_is_pre_gloas = parent.block.phase() < Phase::Gloas;
            let parent_is_finalized = self.finalized_indices.contains_key(&parent_root);

            if parent_full && !has_parent_exec && !parent_is_pre_gloas && !parent_is_finalized {
                return Ok(BlockAction::DelayUntilParentEnvelope(
                    block.clone_arc(),
                    block.message().parent_root(),
                ));
            }
        }

        // > Check the block is valid and compute the post-state
        let (state, block_action) = state_transition(block_root, parent)?;

        if let Some(action) = block_action {
            return Ok(action);
        }

        if self.should_check_data_availability_at_slot(block.message().slot())
            && data_availability_policy.check()
        {
            if state.phase().is_peerdas_activated() {
                if !self.indices_of_missing_data_columns(block).is_empty() {
                    return Ok(BlockAction::DelayUntilBlobs(block.clone_arc(), state));
                }
            } else if !self.indices_of_missing_blobs(block).is_empty() {
                return Ok(BlockAction::DelayUntilBlobs(block.clone_arc(), state));
            }
        }

        let attester_slashing_results = block
            .message()
            .body()
            .combined_attester_slashings()
            .map(|attester_slashing| {
                self.validate_attester_slashing(&attester_slashing, AttesterSlashingOrigin::Block)
            })
            .collect();

        let justified_checkpoint = state.current_justified_checkpoint();
        let finalized_checkpoint = state.finalized_checkpoint();

        // TODO(Grandine Team): Optimize computation of unrealized checkpoints.
        //                      Unrealized checkpoints must be computed for every block,
        //                      but `process_justification_and_finalization` is slow.
        //                      Lighthouse has a check that avoids calling it 1/3 of the time.
        //                      Calculating balances incrementally is probably a better way to do it,
        //                      as it would make `process_justification_and_finalization` nearly free.
        //                      Specializing the `statistics` functions might help too.
        // > Eagerly compute unrealized justification and finality
        let (unrealized_justified_checkpoint, unrealized_finalized_checkpoint) = {
            let mut state = state.clone_arc();

            // > Pull up the post-state of the block to the next epoch boundary
            combined::process_justification_and_finalization(state.make_mut())?;

            let justified = state.current_justified_checkpoint();
            let finalized = state.finalized_checkpoint();

            (justified, finalized)
        };

        let payload_status = Self::initial_payload_status(&state);

        let chain_link = ChainLink {
            block_root,
            block: block.clone_arc(),
            block_state: Some(state),
            execution_payload_state: None,
            current_justified_checkpoint: justified_checkpoint,
            finalized_checkpoint,
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
            payload_status,
        };

        // Ensure that the new justified state is present in the store when
        // `Store::update_balances_after_justification` is executed. This prevents the problem
        // described in <https://github.com/ethereum/consensus-specs/issues/1887>.
        if self.should_wait_for_justified_state(justified_checkpoint) {
            return Ok(BlockAction::WaitForJustifiedState(
                chain_link,
                attester_slashing_results,
                justified_checkpoint,
            ));
        }

        // > If the block is from a prior epoch, apply the realized values
        if self.is_block_from_prior_epoch(&chain_link)
            && self.should_wait_for_justified_state(unrealized_justified_checkpoint)
        {
            return Ok(BlockAction::WaitForJustifiedState(
                chain_link,
                attester_slashing_results,
                unrealized_justified_checkpoint,
            ));
        }

        // > Add new block to the store
        //
        // > Add new state for this block to the store
        Ok(BlockAction::Accept(chain_link, attester_slashing_results))
    }

    #[expect(clippy::too_many_lines)]
    pub fn validate_execution_payload_bid(
        &self,
        payload_bid: Arc<SignedExecutionPayloadBid<P>>,
        origin: &ExecutionPayloadBidOrigin,
    ) -> Result<ExecutionPayloadBidAction<P>> {
        let bid = &payload_bid.message;
        let builder_index = bid.builder_index;

        // > off-protocol payment is disallowed in gossip, the `bid.execution_payment` MUST be zero
        if origin.off_protocol_bid_disallowed() {
            ensure!(
                bid.execution_payment == 0,
                Error::<P>::ExecutionPayloadBidOffProtocolPaymentDisallowed { payload_bid }
            );
        }

        // > the `bid.slot` is the current slot or the next slot
        if bid.slot > self.slot() + 1 {
            return Ok(ExecutionPayloadBidAction::Ignore(false));
        }

        let bid_epoch = misc::compute_epoch_at_slot::<P>(bid.slot);
        let in_bid = bid.blob_kzg_commitments.len();
        let maximum = self
            .chain_config
            .get_blob_schedule_entry(bid_epoch)
            .max_blobs_per_block;
        ensure!(
            in_bid <= maximum,
            Error::<P>::TooManyBlobKzgCommitments { maximum, in_bid }
        );

        // > the `bid.parent_block_hash` is the block hash of a known execution payload in fork choice
        if !self
            .execution_payload_locations
            .contains_key(&bid.parent_block_hash)
        {
            return Ok(ExecutionPayloadBidAction::Ignore(true));
        }

        // > the `bid.parent_block_root` is the hash tree root of a known beacon block in fork choice
        let Some(state) = self.state_by_block_root(bid.parent_block_root) else {
            return Ok(ExecutionPayloadBidAction::Ignore(true));
        };

        if builder_index == BUILDER_INDEX_SELF_BUILD {
            ensure!(
                payload_bid.signature.is_empty(),
                Error::<P>::ExecutionPayloadBidSignatureNotEmpty
            );

            ensure!(
                bid.value == 0,
                Error::<P>::ExecutionPayloadBidValueNonZero { value: bid.value }
            );
        } else {
            let Some(post_gloas_state) = state.post_gloas() else {
                return Ok(ExecutionPayloadBidAction::Ignore(true));
            };
            let builder = post_gloas_state.builders().get(builder_index)?;

            // > the `bid.builder_index` is a valid/active builder index
            let current_epoch = accessors::get_current_epoch(&state);
            ensure!(
                predicates::is_active_builder(builder, state.finalized_checkpoint().epoch),
                Error::<P>::ExecutionPayloadBidBuilderInactive {
                    payload_bid,
                    epoch: current_epoch
                }
            );

            // > the `bid.value` is less or equal than the builder's excess balance
            if !predicates::can_builder_cover_bid(post_gloas_state, builder_index, bid.value)? {
                return Ok(ExecutionPayloadBidAction::Ignore(false));
            }

            if origin.verify_signatures() {
                let pubkey = self.pubkey_cache.get_or_insert(builder.pubkey)?;

                // > `signed_execution_payload_bid.signature` is valid builder's signature
                if let Err(error) =
                    bid.verify(&self.chain_config, &state, payload_bid.signature, pubkey)
                {
                    bail!(error
                        .context(Error::<P>::InvalidExecutionPayloadBidSignature { payload_bid }));
                }
            }
        }

        if let Some(payload_bids) = self.accepted_payload_bids.get(&bid.slot) {
            // > this is the first signed bid seen from the given builder for this slot
            if payload_bids.contains_key(&builder_index) {
                return Ok(ExecutionPayloadBidAction::Ignore(true));
            }

            // > this bid is the highest value bid seen for the corresponding slot and the given parent block hash.
            if let Some(highest_bid) = payload_bids
                .values()
                .filter(|b| b.message.parent_block_hash == bid.parent_block_hash)
                .max_by_key(|b| b.message.value)
            {
                if bid.value <= highest_bid.message.value {
                    // This bid doesn't have a higher value than the existing bid
                    return Ok(ExecutionPayloadBidAction::Ignore(true));
                }
            }
        }

        Ok(ExecutionPayloadBidAction::Accept(payload_bid))
    }

    #[expect(clippy::too_many_lines)]
    pub fn validate_aggregate_and_proof<I>(
        &self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        origin: &AggregateAndProofOrigin<I>,
        signature_validated: bool,
    ) -> Result<AggregateAndProofAction<P>> {
        let signature = aggregate_and_proof.signature();
        let message = aggregate_and_proof.message();
        let aggregator_index = message.aggregator_index();
        let selection_proof = message.selection_proof();
        let aggregate = Arc::new(message.aggregate());

        match self.validate_attestation_internal(&aggregate, false)? {
            PartialAttestationAction::Accept => {}
            PartialAttestationAction::Ignore => {
                return Ok(AggregateAndProofAction::Ignore);
            }
            PartialAttestationAction::DelayUntilBlock(block_root) => {
                return Ok(AggregateAndProofAction::DelayUntilBlock(
                    aggregate_and_proof,
                    block_root,
                ));
            }
            PartialAttestationAction::DelayUntilSlot => {
                return Ok(AggregateAndProofAction::DelayUntilSlot(aggregate_and_proof));
            }
            PartialAttestationAction::DelayUntilEnvelope(block_root) => {
                return Ok(AggregateAndProofAction::DelayUntilEnvelope(
                    aggregate_and_proof,
                    block_root,
                ));
            }
        }

        let AttestationData { slot, target, .. } = aggregate.data();

        let index = misc::committee_index(&aggregate);

        // TODO(feature/deneb): Figure out why this validation is split over 2 methods.
        // TODO(feature/deneb): This appears to be unfinished.
        //                      Deneb replaces the old validation with 2 new ones.
        //                      One of them is in `Store::validate_attestation_internal`.
        if self.phase() < Phase::Deneb {
            // > `aggregate.data.slot` is within the last `ATTESTATION_PROPAGATION_SLOT_RANGE` slots
            //
            // The other half of this validation is performed in
            // `Store::validate_attestation_internal`.
            //
            // `ATTESTATION_PROPAGATION_SLOT_RANGE` happens to be equal to `SLOTS_PER_EPOCH` in the
            // mainnet preset, but `ATTESTATION_PROPAGATION_SLOT_RANGE` is not configurable, so this
            // is not a full replacement for the `target.epoch` validation in
            // `Store::validate_attestation_internal`.
            if slot + ATTESTATION_PROPAGATION_SLOT_RANGE < self.slot() {
                return Ok(AggregateAndProofAction::Ignore);
            }
        }

        // > The attestation has participants
        ensure!(
            aggregate.count_aggregation_bits() > 0,
            Error::AggregateAttestationHasNoAggregationBitsSet {
                aggregate_and_proof,
            }
        );

        // > Get state at the `target` to fully validate attestation
        //
        // This should only be done after `Store::validate_attestation_internal` to ensure that the
        // block corresponding to the FFG vote target is present in the store.
        //
        // Computing the target state is potentially resource intensive, so validations that don't
        // need it should be performed first.
        let target_state = if Feature::CacheTargetStates.is_enabled() {
            let Some(state) = self.checkpoint_states.get(&target) else {
                return Ok(AggregateAndProofAction::WaitForTargetState(
                    aggregate_and_proof,
                ));
            };

            state.clone_arc()
        } else {
            let Some(state) = self.state_before_or_at_slot(
                target.root,
                misc::compute_start_slot_at_epoch::<P>(target.epoch),
            ) else {
                return Ok(AggregateAndProofAction::DelayUntilBlock(
                    aggregate_and_proof,
                    target.root,
                ));
            };

            state
        };

        if accessors::relative_epoch(&target_state, target.epoch).is_err() {
            return Ok(AggregateAndProofAction::Ignore);
        }

        // > `aggregate_and_proof.selection_proof` selects the validator as an aggregator for the
        // > slot
        ensure!(
            predicates::is_aggregator(&target_state, slot, index, selection_proof)?,
            Error::ValidatorNotAggregator {
                aggregate_and_proof,
            },
        );

        let index = aggregate
            .committee_bits()
            .and_then(|bits| misc::get_committee_indices::<P>(bits).next())
            .unwrap_or(index);

        let committee = accessors::beacon_committee(&target_state, slot, index)?;

        // > The aggregator's validator index is within the committee
        ensure!(
            committee.into_iter().contains(&aggregator_index),
            Error::AggregatorNotInCommittee {
                aggregate_and_proof,
                committee: committee.into_iter().collect(),
            },
        );

        let public_key = &target_state.validators().get(aggregator_index)?.pubkey;

        if !signature_validated && origin.verify_signatures() {
            let chain_config = &self.chain_config;
            let pubkey = self.pubkey_cache.get_or_insert(*public_key)?;

            // > The `aggregate_and_proof.selection_proof` is a valid signature of the
            // > `aggregate.data.slot` by the validator with index
            // > `aggregate_and_proof.aggregator_index`.
            if let Err(error) = slot.verify(
                chain_config,
                &target_state,
                selection_proof,
                pubkey.clone_arc(),
            ) {
                bail!(error.context(Error::InvalidSelectionProof {
                    aggregate_and_proof,
                }));
            }

            // > The aggregator signature, `signed_aggregate_and_proof.signature`, is valid.
            if let Err(error) = message.verify(chain_config, &target_state, signature, pubkey) {
                bail!(error.context(Error::InvalidAggregateAndProofSignature {
                    aggregate_and_proof,
                }));
            }
        }

        let attesting_indices = self.attesting_indices(
            &target_state,
            &aggregate,
            !signature_validated && origin.verify_signatures(),
        )?;

        // https://github.com/ethereum/consensus-specs/pull/2847
        let is_subset_aggregate = !self.aggregate_and_proof_supersets.check(&aggregate);

        Ok(AggregateAndProofAction::Accept {
            aggregate_and_proof,
            attesting_indices,
            is_subset_aggregate,
        })
    }

    #[expect(clippy::too_many_lines)]
    pub fn validate_attestation<I>(
        &self,
        attestation: AttestationItem<P, I>,
        skip_signatures_verification: bool,
    ) -> Result<AttestationAction<P, I>, AttestationValidationError<P, I>> {
        match self
            .validate_attestation_internal(&attestation.item, attestation.origin.is_from_block())
        {
            Ok(PartialAttestationAction::Accept) => {}
            Ok(PartialAttestationAction::Ignore) => {
                return Ok(AttestationAction::Ignore(attestation));
            }
            Ok(PartialAttestationAction::DelayUntilBlock(block_root)) => {
                return Ok(AttestationAction::DelayUntilBlock(attestation, block_root));
            }
            Ok(PartialAttestationAction::DelayUntilSlot) => {
                return Ok(AttestationAction::DelayUntilSlot(attestation));
            }
            Ok(PartialAttestationAction::DelayUntilEnvelope(block_root)) => {
                return Ok(AttestationAction::DelayUntilEnvelope(attestation, block_root));
            }
            Err(source) => {
                return Err(AttestationValidationError::Other {
                    attestation: Box::new(attestation),
                    source,
                })
            }
        }

        let index = misc::committee_index(&attestation.item);

        let AttestationData { slot, target, .. } = attestation.data();

        // TODO(feature/deneb): Figure out why this validation is split over 2 methods.
        // TODO(feature/deneb): This appears to be unfinished.
        //                      Deneb replaces the old validation with 2 new ones.
        //                      One of them is in `Store::validate_attestation_internal`.
        if self.phase() < Phase::Deneb && attestation.origin.validate_as_gossip() {
            // > `aggregate.data.slot` is within the last `ATTESTATION_PROPAGATION_SLOT_RANGE` slots
            //
            // The other half of this validation is performed in
            // `Store::validate_attestation_internal`.
            //
            // `ATTESTATION_PROPAGATION_SLOT_RANGE` happens to be equal to `SLOTS_PER_EPOCH` in the
            // mainnet preset, but `ATTESTATION_PROPAGATION_SLOT_RANGE` is not configurable, so this
            // is not a full replacement for the `target.epoch` validation in
            // `Store::validate_attestation_internal`.
            if slot + ATTESTATION_PROPAGATION_SLOT_RANGE < self.slot() {
                return Ok(AttestationAction::Ignore(attestation));
            }
        }

        if attestation.origin.must_be_singular() {
            // > The attestation is unaggregated
            if attestation.item.count_aggregation_bits() != 1 {
                return Err(
                    AttestationValidationError::SingularAttestationHasMultipleAggregationBitsSet {
                        attestation: Box::new(attestation),
                    },
                );
            }
        }

        // > Get state at the `target` to fully validate attestation
        //
        // This should only be done after `Store::validate_attestation_internal` to ensure that the
        // block corresponding to the FFG vote target is present in the store.
        //
        // Computing the target state is potentially resource intensive, so validations that don't
        // need it should be performed first.
        let target_state = if Feature::CacheTargetStates.is_enabled() {
            let Some(state) = self.checkpoint_states.get(&target) else {
                return Ok(AttestationAction::WaitForTargetState(attestation));
            };

            state.clone_arc()
        } else {
            let mut target_state = self
                .state_cache
                .before_or_at_slot_in_cache_only(target.root, slot);

            if let AttestationOrigin::Block(block_root) = attestation.origin {
                if target_state.is_none() {
                    // During state transition, all block attestations are validated against block state.
                    // Same logic applies here.
                    target_state = self
                        .chain_link_full(block_root)
                        .map(|chain_link| chain_link.state(self));
                }
            }

            let Some(state) = target_state.or_else(|| {
                self.state_before_or_at_slot(
                    target.root,
                    misc::compute_start_slot_at_epoch::<P>(target.epoch),
                )
            }) else {
                return Ok(AttestationAction::DelayUntilBlock(attestation, target.root));
            };

            state
        };

        let Ok(relative_epoch) = accessors::relative_epoch(&target_state, target.epoch) else {
            return Ok(AttestationAction::Ignore(attestation));
        };

        if let Some(actual) = attestation.origin.subnet_id() {
            let committees_per_slot =
                accessors::get_committee_count_per_slot(&target_state, relative_epoch);

            let expected =
                match misc::compute_subnet_for_attestation::<P>(committees_per_slot, slot, index) {
                    Ok(subnet) => subnet,
                    Err(source) => {
                        return Err(AttestationValidationError::Other {
                            attestation: Box::new(attestation),
                            source,
                        })
                    }
                };

            // > The attestation is for the correct subnet
            if actual != expected {
                return Err(
                    AttestationValidationError::SingularAttestationOnIncorrectSubnet {
                        attestation: Box::new(attestation),
                        expected,
                        actual,
                    },
                );
            }
        }

        let attesting_indices = match self.attesting_indices(
            &target_state,
            &attestation.item,
            !skip_signatures_verification && attestation.origin.verify_signatures(),
        ) {
            Ok(indices) => indices,
            Err(source) => {
                return Err(AttestationValidationError::Other {
                    source,
                    attestation: Box::new(attestation),
                })
            }
        };

        Ok(AttestationAction::Accept {
            attestation,
            attesting_indices,
        })
    }

    /// Performs validations needed for both singular attestations and aggregates.
    ///
    /// Roughly corresponds to [`validate_on_attestation`] from the Fork Choice specification.
    ///
    /// [`validate_on_attestation`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#validate_on_attestation
    fn validate_attestation_internal(
        &self,
        attestation: &Arc<Attestation<P>>,
        is_from_block: bool,
    ) -> Result<PartialAttestationAction> {
        let AttestationData {
            slot,
            beacon_block_root,
            target,
            index,
            ..
        } = attestation.data();

        // > If the given attestation is not from a beacon block message,
        // > we have to check the target epoch scope.
        //
        // The finalization atomicity bugfix in `consensus-specs` version 1.1.6 sneakily added the
        // flag `is_from_block` to the function `validate_on_attestation`. The release documentation
        // mentions the flag being added and states that its use is under consideration.
        // The Fork Choice specification still doesn't make it clear if `is_from_block` is supposed
        // to be used in normal operation, but optimistic sync test cases in `consensus-spec-tests`
        // fail without it starting with version 1.3.0-rc.0.
        if !is_from_block {
            // TODO(feature/deneb): Figure this out.
            //                      This validation appears to do the same as the one below.
            if self.phase() >= Phase::Deneb {
                let epoch = Self::epoch_at_slot(slot);

                // The `ATTESTATION_PROPAGATION_SLOT_RANGE` check is loosened in Deneb.
                if self.previous_epoch() != epoch && self.current_epoch() != epoch {
                    return Ok(PartialAttestationAction::Ignore);
                }
            }

            if self.phase() >= Phase::Gloas {
                ensure!(
                    index < 2,
                    Error::AttestationDataInvalidPayloadStatus {
                        attestation: attestation.clone_arc()
                    }
                );
            } else if self.phase() >= Phase::Electra {
                ensure!(
                    index == 0,
                    Error::AttestationDataIndexNotZero {
                        attestation: attestation.clone_arc()
                    }
                );

                if let Attestation::Electra(electra_attestation) = attestation.as_ref() {
                    let committee_indices =
                        misc::get_committee_indices::<P>(electra_attestation.committee_bits);

                    ensure!(
                        committee_indices.count() == 1,
                        Error::AttestationFromMultipleCommittees {
                            attestation: attestation.clone_arc()
                        }
                    );
                }
            }

            // > Attestations must be from the current or previous epoch
            if target.epoch < self.previous_epoch() {
                return Ok(PartialAttestationAction::Ignore);
            }

            // TODO(feature/deneb): `IGNORE`ing appears to be specified behavior for aggregates
            //                      starting with Deneb. See the Deneb Networking specification.
            // > If attestation target is from a future epoch,
            // > delay consideration until the epoch arrives
            if self.slot() < slot {
                if Feature::IgnoreFutureAttestations.is_enabled() {
                    return Ok(PartialAttestationAction::Ignore);
                }

                return Ok(PartialAttestationAction::DelayUntilSlot);
            }
        }

        // > Check that the epoch number and slot number are matching
        //
        // This validation is redundant for attestations in blocks because it's already performed in
        // the state transition, but it's cheap and still required for gossiped attestations.
        ensure!(
            target.epoch == Self::epoch_at_slot(slot),
            Error::AttestationTargetsWrongEpoch {
                attestation: attestation.clone_arc(),
            },
        );

        // > Attestation target must be for a known block.
        // > If target block is unknown, delay consideration until block is found
        if !self.contains_block(target.root) {
            if Feature::IgnoreAttestationsForUnknownBlocks.is_enabled() {
                return Ok(PartialAttestationAction::Ignore);
            }

            return Ok(PartialAttestationAction::DelayUntilBlock(target.root));
        }

        // > Attestations must be for a known block.
        // > If block is unknown, delay consideration until the block is found
        let Some(ghost_vote_block) = self.block(beacon_block_root).map(WithStatus::value) else {
            if Feature::IgnoreAttestationsForUnknownBlocks.is_enabled() {
                return Ok(PartialAttestationAction::Ignore);
            }

            return Ok(PartialAttestationAction::DelayUntilBlock(beacon_block_root));
        };

        // > Attestations must not be for blocks in the future.
        // > If not, the attestation should not be considered
        //
        // This validation is present in the fork choice rule but not the Networking specification.
        ensure!(
            ghost_vote_block.message().slot() <= slot,
            Error::AttestationForFutureBlock {
                attestation: attestation.clone_arc(),
                block: ghost_vote_block.clone_arc(),
            },
        );

        // [New in EIP7732]
        // If the attested block is from the same slot as the attestation,
        // the payload status is unknown so index must be 0.
        if self.phase() >= Phase::Gloas && ghost_vote_block.message().slot() == slot {
            ensure!(
                index == 0,
                Error::AttestationDataPayloadPresenceForCurrentSlot {
                    attestation: attestation.clone_arc()
                }
            );
        }
        // deleted the previous rule for this it was comparing current slot with attestation's  slot and not attested block's slot
        // Note: index < 2 is guaranteed here — enforced by !is_from_block check
        // for gossip attestations, and by state transition for block attestations.
        // (raise in review if incorrect)

        // [New in EIP7732]
        // If attesting for a full node, the payload must be known.
        //
        // Delay gossip attestation with payload_present=1 until envelope arrives.
        // Spec(gloas): https://github.com/ethereum/consensus-specs/commit/6b3aedc5367981721a4620feaf4a2fd3438b1f54
        // Block-packed attestations are currently allowed to affect forkchoice.
        // TODO(gloas): revisit !is_from_block after 1.7.0-alpha.4 spec test changes. now if removed gives a failrue at 
        // spec_tests::gloas_minimal_get_head_consensus_spec_tests_tests_minimal_gloas_fork_choice_get_head_pyspec_tests_voting_source_within_two_epoch
        // also at that point recheck finalized block getting attestaion can be handled via has_envelope without calling unfinalized_locations_full or not

        if !is_from_block && index == 1 {
            if let Some(location) = self.unfinalized_locations_full.get(&beacon_block_root) {
                let chain_link = &self.unfinalized[&location.segment_id][location.position].chain_link;
                if chain_link.block.message().body().with_payload_bid().is_some()
                    && chain_link.execution_payload_state.is_none()
                {
                    return Ok(PartialAttestationAction::DelayUntilEnvelope(beacon_block_root));
                }
            }
        }

        let ancestor_at_target_epoch_start = self
            .ancestor(beacon_block_root, Self::start_of_epoch(target.epoch))
            .expect(
                "the validation for attestation.data.beacon_block_root above ensures \
                 that the block corresponding to LMD GHOST vote is present in the store",
            );

        // > LMD vote must be consistent with FFG vote target
        ensure!(
            target.root == ancestor_at_target_epoch_start,
            Error::LmdGhostInconsistentWithFfgTarget {
                attestation: attestation.clone_arc(),
            },
        );

        Ok(PartialAttestationAction::Accept)
    }

    fn attesting_indices(
        &self,
        target_state: &BeaconState<P>,
        attestation: &Attestation<P>,
        validate_indexed: bool,
    ) -> Result<AttestingIndices<P>> {
        match attestation {
            Attestation::Phase0(attestation) => {
                let indexed_attestation =
                    phase0::get_indexed_attestation(target_state, attestation)?;

                if validate_indexed {
                    predicates::validate_constructed_indexed_attestation(
                        &self.chain_config,
                        &self.pubkey_cache,
                        target_state,
                        &indexed_attestation,
                        SingleVerifier,
                    )?;
                }

                Ok(AttestingIndices::Phase0(
                    indexed_attestation.attesting_indices,
                ))
            }
            Attestation::Electra(attestation) => {
                let indexed_attestation =
                    electra::get_indexed_attestation(target_state, attestation)?;

                if validate_indexed {
                    predicates::validate_constructed_indexed_attestation(
                        &self.chain_config,
                        &self.pubkey_cache,
                        target_state,
                        &indexed_attestation,
                        SingleVerifier,
                    )?;
                }

                Ok(AttestingIndices::Electra(
                    indexed_attestation.attesting_indices,
                ))
            }
            Attestation::Single(attestation) => {
                let indexed_attestation: ElectraIndexedAttestation<P> =
                    (*attestation).try_into()?;

                if validate_indexed {
                    predicates::validate_constructed_indexed_attestation(
                        &self.chain_config,
                        &self.pubkey_cache,
                        target_state,
                        &indexed_attestation,
                        SingleVerifier,
                    )?;
                }

                Ok(AttestingIndices::Electra(
                    indexed_attestation.attesting_indices,
                ))
            }
        }
    }

    pub fn validate_attester_slashing(
        &self,
        attester_slashing: &AttesterSlashing<P>,
        origin: AttesterSlashingOrigin,
    ) -> Result<Vec<ValidatorIndex>> {
        match attester_slashing {
            AttesterSlashing::Phase0(attester_slashing) => {
                if origin.verify_signatures() {
                    unphased::validate_attester_slashing(
                        &self.chain_config,
                        &self.pubkey_cache,
                        self.justified_state(),
                        attester_slashing,
                    )
                } else {
                    unphased::validate_attester_slashing_with_verifier(
                        &self.chain_config,
                        &self.pubkey_cache,
                        self.justified_state(),
                        attester_slashing,
                        NullVerifier,
                    )
                }
            }
            AttesterSlashing::Electra(attester_slashing) => {
                if origin.verify_signatures() {
                    unphased::validate_attester_slashing(
                        &self.chain_config,
                        &self.pubkey_cache,
                        self.justified_state(),
                        attester_slashing,
                    )
                } else {
                    unphased::validate_attester_slashing_with_verifier(
                        &self.chain_config,
                        &self.pubkey_cache,
                        self.justified_state(),
                        attester_slashing,
                        NullVerifier,
                    )
                }
            }
        }
    }

    // TODO(feature/deneb): Format quotes and log message like everything else.
    #[expect(clippy::too_many_lines)]
    pub fn validate_blob_sidecar_with_state(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        block_seen: bool,
        origin: &BlobSidecarOrigin,
        parent_info: impl FnOnce() -> Option<(Arc<SignedBeaconBlock<P>>, PayloadStatus)>,
        state_fn: impl FnOnce() -> Option<Arc<BeaconState<P>>>,
    ) -> Result<BlobSidecarAction<P>> {
        let block_header = blob_sidecar.signed_block_header.message;
        let block_root = block_header.hash_tree_root();

        // No need to validate and import blob sidecars for blocks that are already in fork choice,
        // i.e. already have all the blobs validated
        if self.contains_block(block_root) {
            return Ok(BlobSidecarAction::Ignore(false));
        }

        // [REJECT] The sidecar's index is consistent with MAX_BLOBS_PER_BLOCK -- i.e. blob_sidecar.index < MAX_BLOBS_PER_BLOCK.
        let max_blobs_per_block = self
            .chain_config()
            .max_blobs_per_block(Self::epoch_at_slot(block_header.slot));

        ensure!(
            blob_sidecar.index < max_blobs_per_block,
            Error::BlobSidecarInvalidIndex { blob_sidecar },
        );

        // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_blob_sidecar(blob_sidecar.index) == subnet_id.
        if let Some(actual) = origin.subnet_id() {
            let expected = misc::compute_subnet_for_blob_sidecar(&self.chain_config, &blob_sidecar);

            ensure!(
                actual == expected,
                Error::BlobSidecarOnIncorrectSubnet {
                    blob_sidecar,
                    expected,
                    actual,
                },
            );
        }

        // [IGNORE] The sidecar is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that block_header.slot <= current_slot
        // (a client MAY queue future sidecars for processing at the appropriate slot).
        if self.slot() < block_header.slot {
            return Ok(BlobSidecarAction::DelayUntilSlot(blob_sidecar));
        }

        // [IGNORE] The sidecar is from a slot greater than the latest finalized slot -- i.e. validate that block_header.slot > compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
        if !origin.is_from_back_sync() && block_header.slot <= self.finalized_slot() {
            return Ok(BlobSidecarAction::Ignore(false));
        }

        // [IGNORE] The sidecar is the first sidecar for the tuple (block_header.slot, block_header.proposer_index, blob_sidecar.index) with valid header signature, sidecar inclusion proof, and kzg proof.
        // Adjustment: Ignore blob sidecars for unseen blocks only
        if self.accepted_blob_sidecars.contains_key(&(
            block_header.slot,
            block_header.proposer_index,
            blob_sidecar.index,
        )) && !block_seen
        {
            return Ok(BlobSidecarAction::Ignore(true));
        }

        let Some(state) = state_fn() else {
            // Delay blob validations until the state is available.
            // Alternatively, we could allow slot processing to obtain states for blob sidecar validations,
            // however, that introduces opportunity for DoS attacks with fake blob sidecars.
            return Ok(BlobSidecarAction::DelayUntilState(blob_sidecar, block_root));
        };

        // [REJECT] The proposer signature of blob_sidecar.signed_block_header, is valid with respect to the block_header.proposer_index pubkey.
        SingleVerifier.verify_singular(
            blob_sidecar
                .signed_block_header
                .message
                .signing_root(&self.chain_config, &state),
            blob_sidecar.signed_block_header.signature,
            self.pubkey_cache
                .get_or_insert(*accessors::public_key(&state, block_header.proposer_index)?)?,
            SignatureKind::BlockInBlobSidecar,
        )?;

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 1/2:
        // Since our fork choice store's implementation doesn't preserve invalid blocks,
        // it needs to check this before sidecar's block's parent's presence check
        ensure!(
            !self
                .rejected_block_roots
                .contains(&block_header.parent_root),
            Error::BlobSidecarInvalidParentOfBlock { blob_sidecar },
        );

        // [IGNORE] The sidecar's block's parent (defined by block_header.parent_root) has been seen (via both gossip and non-gossip sources)
        // (a client MAY queue sidecars for processing once the parent block is retrieved).
        let Some((parent, parent_payload_status)) = parent_info() else {
            return Ok(BlobSidecarAction::DelayUntilParent(blob_sidecar));
        };

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 2/2:
        ensure!(
            !parent_payload_status.is_invalid(),
            Error::BlobSidecarInvalidParentOfBlock { blob_sidecar },
        );

        // [REJECT] The sidecar is from a higher slot than the sidecar's block's parent (defined by block_header.parent_root).
        let parent_slot = parent.message().slot();

        ensure!(
            block_header.slot > parent_slot,
            Error::BlobSidecarNotNewerThanBlockParent {
                blob_sidecar,
                parent_slot,
            }
        );

        if !origin.is_from_back_sync() {
            // [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block
            // -- i.e. get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root.
            let ancestor_at_finalized_slot = self
                .ancestor(block_header.parent_root, self.finalized_slot())
                .expect(
                    "every block in the store should have an ancestor at the last finalized slot",
                );

            ensure!(
                ancestor_at_finalized_slot == self.finalized_checkpoint.root,
                Error::BlobSidecarBlockNotADescendantOfFinalized { blob_sidecar },
            );
        }

        // > _[REJECT]_ The sidecar's inclusion proof is valid as
        // > verified by `verify_blob_sidecar_inclusion_proof(blob_sidecar)`.
        ensure!(
            predicates::is_valid_blob_sidecar_inclusion_proof(&blob_sidecar),
            Error::BlobSidecarInvalidInclusionProof { blob_sidecar },
        );

        // [REJECT] The sidecar's blob is valid as verified by verify_blob_kzg_proof(blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof).
        ensure!(
            kzg_utils::eip_4844::verify_blob_kzg_proof::<P>(
                &blob_sidecar.blob,
                blob_sidecar.kzg_commitment,
                blob_sidecar.kzg_proof,
                self.store_config.kzg_backend,
            )
            .unwrap_or(false),
            Error::BlobSidecarInvalid { blob_sidecar }
        );

        if !origin.is_from_back_sync() {
            // [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot in the context of the current shuffling
            // (defined by block_header.parent_root/block_header.slot).
            // If the proposer_index cannot immediately be verified against the expected shuffling,
            // the sidecar MAY be queued for later processing while proposers for the block's branch are calculated --
            // in such a case do not REJECT, instead IGNORE this message.
            let computed = accessors::get_beacon_proposer_index(&self.chain_config, &state)?;

            ensure!(
                block_header.proposer_index == computed,
                Error::BlobSidecarProposerIndexMismatch {
                    blob_sidecar,
                    computed,
                }
            );
        }

        Ok(BlobSidecarAction::Accept(blob_sidecar))
    }

    pub fn validate_blob_sidecar(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        state: Option<Arc<BeaconState<P>>>,
        block_seen: bool,
        origin: &BlobSidecarOrigin,
    ) -> Result<BlobSidecarAction<P>> {
        let block_header = blob_sidecar.signed_block_header.message;

        let parent_info = || {
            self.chain_link_full(block_header.parent_root)
                .map(|chain_link| (chain_link.block.clone_arc(), chain_link.payload_status))
        };

        if let Some(state) = state {
            self.validate_blob_sidecar_with_state(
                blob_sidecar,
                block_seen,
                origin,
                parent_info,
                || Some(state),
            )
        } else {
            self.validate_blob_sidecar_with_state(
                blob_sidecar,
                block_seen,
                origin,
                parent_info,
                || {
                    self.state_cache.existing_state_at_slot(
                        self,
                        block_header.parent_root,
                        block_header.slot,
                    )
                },
            )
        }
    }

    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    pub fn validate_fulu_data_column_sidecar_with_state(
        &self,
        data_column_sidecar: FuluDataColumnSidecar<P>,
        block_seen: bool,
        origin: &DataColumnSidecarOrigin,
        validate_block_presence: bool,
        parent_info: impl FnOnce() -> Option<(Arc<SignedBeaconBlock<P>>, PayloadStatus)>,
        state_fn: impl FnOnce() -> Option<Arc<BeaconState<P>>>,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<DataColumnSidecarAction<P>> {
        let column_index = data_column_sidecar.index;
        let kzg_commitments = data_column_sidecar.kzg_commitments.clone();
        let block_header = data_column_sidecar.signed_block_header.message;
        let block_signature = data_column_sidecar.signed_block_header.signature;
        let block_root = block_header.hash_tree_root();
        let data_column_sidecar = Arc::new(data_column_sidecar.into());

        // No need to validate and import data column sidecars for blocks that are already in fork choice,
        // i.e. already have all the data columns validated
        // The exception to this is data column sidecars from custody group column backfill,
        // where additional columns are being downloaded for blocks already in fork choice.
        if validate_block_presence && self.contains_block(block_root) {
            return Ok(DataColumnSidecarAction::Ignore(false));
        }

        // Validate data column sidecars submitted via beacon API even
        // if they are not part of the sampling group.
        // This ensures that correct data columns are published to the network.
        let mut is_non_sampled_with_full_validation = false;

        // Ignore non-sampling data column sidecars unless they are submitted to beacon API
        // for publishing after proposal
        if !self.sampling_columns.contains(&column_index) {
            if origin.is_from_api() {
                is_non_sampled_with_full_validation = true;
            } else {
                return Ok(DataColumnSidecarAction::Ignore(false));
            }
        }

        // [REJECT] The sidecar is valid as verified by verify_data_column_sidecar(sidecar)
        ensure!(
            verify_data_column_sidecar(&self.chain_config, &data_column_sidecar, &kzg_commitments),
            Error::DataColumnSidecarInvalid {
                data_column_sidecar
            },
        );

        // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_data_column_sidecar(sidecar.index) == subnet_id.
        if let Some(actual) = origin.subnet_id() {
            let expected =
                misc::compute_subnet_for_data_column_sidecar(&self.chain_config, column_index);
            ensure!(
                actual == expected,
                Error::DataColumnSidecarOnIncorrectSubnet {
                    data_column_sidecar,
                    expected,
                    actual,
                },
            );
        }

        // [IGNORE] The sidecar is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that block_header.slot <= current_slot
        // (a client MAY queue future sidecars for processing at the appropriate slot).
        if self.slot() < block_header.slot {
            return Ok(DataColumnSidecarAction::DelayUntilSlot(data_column_sidecar));
        }

        // [IGNORE] The sidecar is from a slot greater than the latest finalized slot -- i.e. validate that block_header.slot > compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
        if !origin.is_from_back_sync() && block_header.slot <= self.finalized_slot() {
            return Ok(DataColumnSidecarAction::Ignore(false));
        }

        // [IGNORE] The sidecar is the first sidecar for the tuple (block_header.slot, block_header.proposer_index, sidecar.index) with valid header signature, sidecar inclusion proof, and kzg proof.
        // Adjustment: Ignore data column sidecars for unseen blocks only
        if self.accepted_data_column_sidecars.contains_key(&(
            block_header.slot,
            block_header.proposer_index,
            column_index,
        )) && !block_seen
        {
            return Ok(DataColumnSidecarAction::Ignore(true));
        }

        let Some(state) = state_fn() else {
            // Delay data column validations until the state is available.
            // Alternatively, we could allow slot processing to obtain states for data column sidecar validations,
            // however, that introduces opportunity for DoS attacks with fake data column sidecars.
            return Ok(DataColumnSidecarAction::DelayUntilState(
                data_column_sidecar,
                block_root,
            ));
        };

        // [REJECT] The proposer signature of sidecar.signed_block_header, is valid with respect to the block_header.proposer_index pubkey.
        SingleVerifier.verify_singular(
            block_header.signing_root(&self.chain_config, &state),
            block_signature,
            self.pubkey_cache
                .get_or_insert(*accessors::public_key(&state, block_header.proposer_index)?)?,
            SignatureKind::BlockInBlobSidecar,
        )?;

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 1/2:
        // Since our fork choice store's implementation doesn't preserve invalid blocks,
        // it needs to check this before sidecar's block's parent's presence check
        ensure!(
            !self
                .rejected_block_roots
                .contains(&block_header.parent_root),
            Error::DataColumnSidecarInvalidParentOfBlock {
                data_column_sidecar
            },
        );

        // [IGNORE] The sidecar's block's parent (defined by block_header.parent_root) has been seen (via both gossip and non-gossip sources)
        // (a client MAY queue sidecars for processing once the parent block is retrieved).
        let Some((parent, parent_payload_status)) = parent_info() else {
            return Ok(DataColumnSidecarAction::DelayUntilParent(
                data_column_sidecar,
            ));
        };

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 2/2:
        ensure!(
            !parent_payload_status.is_invalid(),
            Error::DataColumnSidecarInvalidParentOfBlock {
                data_column_sidecar
            }
        );

        // [REJECT] The sidecar is from a higher slot than the sidecar's block's parent (defined by block_header.parent_root).
        let parent_slot = parent.message().slot();

        ensure!(
            block_header.slot > parent_slot,
            Error::DataColumnSidecarNotNewerThanBlockParent {
                data_column_sidecar,
                parent_slot,
            }
        );

        if !origin.is_from_back_sync() {
            // [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block
            // -- i.e. get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root.
            let ancestor_at_finalized_slot = self
                .ancestor(block_header.parent_root, self.finalized_slot())
                .expect(
                    "every block in the store should have an ancestor at the last finalized slot",
                );

            ensure!(
                ancestor_at_finalized_slot == self.finalized_checkpoint.root,
                Error::DataColumnSidecarBlockNotADescendantOfFinalized {
                    data_column_sidecar
                },
            );
        }

        if !origin.is_from_el() {
            if let Some(fulu_data_column_sidecar) = data_column_sidecar.pre_gloas() {
                // [REJECT] The sidecar's kzg_commitments field inclusion proof is valid as verified by verify_data_column_sidecar_inclusion_proof(sidecar).
                ensure!(
                    verify_sidecar_inclusion_proof(fulu_data_column_sidecar, metrics),
                    Error::DataColumnSidecarInvalidInclusionProof {
                        data_column_sidecar
                    }
                );
            }

            // [REJECT] The sidecar's column data is valid as verified by verify_data_column_sidecar_kzg_proofs(sidecar).
            let verify_result = verify_kzg_proofs(
                &data_column_sidecar,
                &kzg_commitments,
                self.store_config.kzg_backend,
                metrics,
            )
            .map_err(|error| Error::DataColumnSidecarInvalidKzgProofs {
                data_column_sidecar: data_column_sidecar.clone_arc(),
                error,
            })?;

            ensure!(
                verify_result,
                Error::DataColumnSidecarInvalidKzgProofs {
                    data_column_sidecar,
                    error: anyhow!("invalid KZG proofs verification result"),
                }
            );
        }

        if !origin.is_from_back_sync() {
            // [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot in the context of the current shuffling
            // (defined by block_header.parent_root/block_header.slot).
            // If the proposer_index cannot immediately be verified against the expected shuffling,
            // the sidecar MAY be queued for later processing while proposers for the block's branch are calculated --
            // in such a case do not REJECT, instead IGNORE this message.
            let computed = accessors::get_beacon_proposer_index(&self.chain_config, &state)?;

            ensure!(
                block_header.proposer_index == computed,
                Error::DataColumnSidecarProposerIndexMismatch {
                    data_column_sidecar,
                    computed,
                }
            );
        }

        if is_non_sampled_with_full_validation {
            return Ok(DataColumnSidecarAction::Ignore(true));
        }

        Ok(DataColumnSidecarAction::Accept(data_column_sidecar))
    }

    #[instrument(level = "debug", skip_all)]
    pub fn validate_gloas_data_column_sidecar_with_state(
        &self,
        data_column_sidecar: GloasDataColumnSidecar<P>,
        block_seen: bool,
        origin: &DataColumnSidecarOrigin,
        validate_block_presence: bool,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<DataColumnSidecarAction<P>> {
        let block_root = data_column_sidecar.beacon_block_root;
        let column_index = data_column_sidecar.index;
        let slot = data_column_sidecar.slot;
        let data_column_sidecar = Arc::new(data_column_sidecar.into());

        // No need to validate and import data column sidecars for blocks that are already in fork choice,
        // i.e. already have all the data columns validated
        // The exception to this is data column sidecars from custody group column backfill,
        // where additional columns are being downloaded for blocks already in fork choice.
        // TODO: (gloas): gloas block can be imported without sidecars
        if validate_block_presence && self.contains_block_and_data_available(block_root) {
            return Ok(DataColumnSidecarAction::Ignore(false));
        }

        // Validate data column sidecars submitted via beacon API even
        // if they are not part of the sampling group.
        // This ensures that correct data columns are published to the network.
        let mut is_non_sampled_with_full_validation = false;

        // Ignore non-sampling data column sidecars unless they are submitted to beacon API
        // for publishing after proposal
        if !self.sampling_columns.contains(&column_index) {
            if origin.is_from_api() {
                is_non_sampled_with_full_validation = true;
            } else {
                return Ok(DataColumnSidecarAction::Ignore(false));
            }
        }

        let Some(block) = self.block(block_root).map(WithStatus::value) else {
            return Ok(DataColumnSidecarAction::DelayUntilState(
                data_column_sidecar,
                block_root,
            ));
        };

        // [REJECT] The sidecars's `slot` matches the slot of the block with root `beacon_block_root`.
        ensure!(
            slot == block.message().slot(),
            Error::DataColumnSidecarSlotMismatch {
                data_column_sidecar,
                block_slot: block.message().slot(),
            }
        );

        let Some(kzg_commitments) = block
            .message()
            .body()
            .with_payload_bid()
            .map(|body| body.signed_execution_payload_bid().blob_kzg_commitments())
        else {
            return Err(Error::DataColumnSidecarBlockWithoutPayloadBid {
                data_column_sidecar
            }
            .into());
        };

        // [REJECT] The sidecar is valid as verified by verify_data_column_sidecar(sidecar)
        ensure!(
            verify_data_column_sidecar(&self.chain_config, &data_column_sidecar, kzg_commitments),
            Error::DataColumnSidecarInvalid {
                data_column_sidecar
            },
        );

        // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_data_column_sidecar(sidecar.index) == subnet_id.
        if let Some(actual) = origin.subnet_id() {
            let expected =
                misc::compute_subnet_for_data_column_sidecar(&self.chain_config, column_index);
            ensure!(
                actual == expected,
                Error::DataColumnSidecarOnIncorrectSubnet {
                    data_column_sidecar,
                    expected,
                    actual,
                },
            );
        }

        // [IGNORE] The sidecar is the first sidecar for the tuple (sidecar.beacon_block_root, sidecar.index) with valid kzg proof
        // Adjustment: Ignore data column sidecars for unseen blocks only
        if self
            .accepted_gloas_data_column_sidecars
            .contains_key(&(block_root, column_index))
            && !block_seen
        {
            return Ok(DataColumnSidecarAction::Ignore(true));
        }

        if !origin.is_from_el() {
            // [REJECT] The sidecar's column data is valid as verified by verify_data_column_sidecar_kzg_proofs(sidecar).
            let verify_result = verify_kzg_proofs(
                &data_column_sidecar,
                kzg_commitments,
                self.store_config.kzg_backend,
                metrics,
            )
            .map_err(|error| Error::DataColumnSidecarInvalidKzgProofs {
                data_column_sidecar: data_column_sidecar.clone_arc(),
                error,
            })?;

            ensure!(
                verify_result,
                Error::DataColumnSidecarInvalidKzgProofs {
                    data_column_sidecar,
                    error: anyhow!("invalid KZG proofs verification result"),
                }
            );
        }

        if is_non_sampled_with_full_validation {
            return Ok(DataColumnSidecarAction::Ignore(true));
        }

        Ok(DataColumnSidecarAction::Accept(data_column_sidecar))
    }

    #[instrument(level = "debug", skip_all)]
    pub fn validate_data_column_sidecar(
        &self,
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        state: Option<Arc<BeaconState<P>>>,
        block_seen: bool,
        origin: &DataColumnSidecarOrigin,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<DataColumnSidecarAction<P>> {
        match Arc::unwrap_or_clone(data_column_sidecar) {
            DataColumnSidecar::Fulu(data_column_sidecar) => {
                let block_header = data_column_sidecar.signed_block_header.message;

                let parent_info = || {
                    self.chain_link_full(block_header.parent_root)
                        .map(|chain_link| (chain_link.block.clone_arc(), chain_link.payload_status))
                };

                self.validate_fulu_data_column_sidecar_with_state(
                    data_column_sidecar,
                    block_seen,
                    origin,
                    true,
                    parent_info,
                    || {
                        state.or_else(|| {
                            self.state_cache.existing_state_at_slot(
                                self,
                                block_header.parent_root,
                                block_header.slot,
                            )
                        })
                    },
                    metrics,
                )
            }
            DataColumnSidecar::Gloas(data_column_sidecar) => self
                .validate_gloas_data_column_sidecar_with_state(
                    data_column_sidecar,
                    block_seen,
                    origin,
                    true,
                    metrics,
                ),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn validate_execution_payload_envelope(
        &self,
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        state: Option<Arc<BeaconState<P>>>,
        origin: &ExecutionPayloadEnvelopeOrigin,
    ) -> Result<ExecutionPayloadEnvelopeAction<P>> {
        let slot = envelope.message.slot;
        let block_root = envelope.message.beacon_block_root;

        self.validate_execution_payload_envelope_with_state(
            envelope,
            origin,
            || {
                self.chain_link_full(block_root)
                    .map(|chain_link| (chain_link.block.clone_arc(), chain_link.payload_status))
            },
            || {
                state.or_else(|| {
                    self.state_cache
                        .existing_state_at_slot(self, block_root, slot)
                })
            },
        )
    }

    pub fn validate_execution_payload_envelope_with_state(
        &self,
        envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        origin: &ExecutionPayloadEnvelopeOrigin,
        block_info: impl FnOnce() -> Option<(Arc<SignedBeaconBlock<P>>, PayloadStatus)>,
        state_fn: impl FnOnce() -> Option<Arc<BeaconState<P>>>,
    ) -> Result<ExecutionPayloadEnvelopeAction<P>> {
        let slot = envelope.message.slot;
        let beacon_block_root = envelope.message.beacon_block_root;
        let builder_index = envelope.message.builder_index;

        // [IGNORE] The envelope is from a slot greater than or equal to the latest finalized slot
        // Spec: envelope.slot >= compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)
        if !origin.is_from_back_sync() && slot < self.finalized_slot() {
            return Ok(ExecutionPayloadEnvelopeAction::Ignore(false));
        }

        // [IGNORE] The node has not seen another valid SignedExecutionPayloadEnvelope
        // for this block root from this builder (spec line 230-231)
        if self.accepted_execution_payload_envelopes.contains(&(
            slot,
            beacon_block_root,
            builder_index,
        )) {
            return Ok(ExecutionPayloadEnvelopeAction::Ignore(true));
        }

        // [REJECT] block passes validation.
        // Part 1/2:
        ensure!(
            !self.rejected_block_roots.contains(&beacon_block_root),
            Error::<P>::PayloadEnvelopeInvalidBlock {
                payload_envelope: envelope
            },
        );

        let Some(state) = state_fn() else {
            return Ok(ExecutionPayloadEnvelopeAction::DelayUntilState(
                envelope,
                beacon_block_root,
                slot,
            ));
        };

        if origin.verify_signatures() {
            // [REJECT] The builder signature envelope.signature is valid
            let pubkey = if builder_index == BUILDER_INDEX_SELF_BUILD {
                let validator_index = state.latest_block_header().proposer_index;
                accessors::public_key(&state, validator_index)?
            } else {
                // dev notes: changed the previous code as it was looking for builder index at accessors::public_key
                // which checks the validator set from accessors::public_key i.e Ok(&state.validators().get(validator_index)?.pubkey). now uses state.builders
                //(raise  in review if wrong)
                let post_gloas_state = state
                    .post_gloas()
                    .ok_or_else(|| anyhow!("expected post-Gloas state for envelope validation"))?;
                &post_gloas_state.builders().get(builder_index)?.pubkey
            };
            SingleVerifier.verify_singular(
                envelope.message.signing_root(&self.chain_config, &state),
                envelope.signature,
                self.pubkey_cache.get_or_insert(*pubkey)?,
                SignatureKind::ExecutionPayloadEnvelope,
            )?;
        }

        // > Check if blob data is available
        // > If not, this payload MAY be queued and subsequently considered when blob data becomes available
        if !self.is_data_available_for_envelope(&envelope) {
            return Ok(ExecutionPayloadEnvelopeAction::DelayUntilData(envelope));
        }

        // [IGNORE] The envelope's beacon_block_root has been seen (via gossip or non-gossip sources)
        // (a client MAY queue envelope for processing once the block is retrieved)
        let Some((block, block_payload_status)) = block_info() else {
            // Block not available yet, delay until it arrives
            return Ok(ExecutionPayloadEnvelopeAction::DelayUntilBeaconBlock(
                envelope,
                beacon_block_root,
            ));
        };

        // [REJECT] block passes validation.
        // Part 2/2:
        ensure!(
            !block_payload_status.is_invalid(),
            Error::<P>::PayloadEnvelopeInvalidBlock {
                payload_envelope: envelope
            },
        );

        // [REJECT] block.slot equals envelope.slot
        ensure!(
            block.message().slot() == slot,
            Error::<P>::ExecutionPayloadEnvelopeSlotMismatch {
                expected: block.message().slot(),
                actual: slot,
            },
        );

        let Some(bid) = block
            .message()
            .body()
            .with_payload_bid()
            .map(|body| body.signed_execution_payload_bid().message.clone())
        else {
            return Err(Error::PayloadEnvelopeInvalidBlock {
                payload_envelope: envelope,
            }
            .into());
        };

        // [REJECT] envelope.builder_index == bid.builder_index
        ensure!(
            builder_index == bid.builder_index,
            Error::<P>::BuilderIndexMismatch {
                expected: bid.builder_index,
                actual: builder_index,
            },
        );

        // [REJECT] payload.block_hash == bid.block_hash
        ensure!(
            envelope.message.payload.block_hash == bid.block_hash,
            Error::<P>::ExecutionPayloadBlockHashMismatch {
                envelope: envelope.clone(),
                expected: Box::new(bid.block_hash),
            },
        );

        Ok(ExecutionPayloadEnvelopeAction::Accept(envelope))
    }

    pub fn validate_payload_attestation(
        &self,
        payload_attestation: PayloadAttestationItem<P>,
        skip_signatures_verification: bool,
    ) -> Result<PayloadAttestationAction<P>, PayloadAttestationValidationError<P>> {
        let data = payload_attestation.data();
        let block_root = data.beacon_block_root;

        if !payload_attestation.origin.is_from_block() {
            // [IGNORE] The message's slot is for the current slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance), i.e. data.slot == current_slot
            if data.slot != self.slot() {
                return Ok(PayloadAttestationAction::Ignore(payload_attestation));
            }
        }

        // [IGNORE] The payload_attestation_message is the first valid message received from the
        // validator with index payload_attestation_message.validate_index
        // TODO: (gloas): check if the first valid message

        // [REJECT] The message's block data.beacon_block_root passes validation.
        // Part 1/2:
        if self.rejected_block_roots.contains(&block_root) {
            return Err(
                PayloadAttestationValidationError::PayloadAttestationInvalidBlock {
                    payload_attestation: Box::new(payload_attestation),
                },
            );
        }

        // [IGNORE] The message's block data.beacon_block_root has been seen (via gossip or non-gossip sources)
        // (a client MAY queue attestation for processing once the block is retrieved. Note a client might want to request payload after).
        let Some(chain_link) = self.chain_link_full(block_root) else {
            return Ok(PayloadAttestationAction::DelayUntilBlock(
                payload_attestation,
                block_root,
            ));
        };

        // [REJECT] The message's block data.beacon_block_root passes validation.
        // Part 2/2:
        if chain_link.payload_status.is_invalid() {
            return Err(
                PayloadAttestationValidationError::PayloadAttestationInvalidBlock {
                    payload_attestation: Box::new(payload_attestation),
                },
            );
        }

        let Some(ref state) = chain_link.block_state else {
            return Ok(PayloadAttestationAction::DelayUntilBlock(
                payload_attestation,
                block_root,
            ));
        };

        // > PTC votes can only change the vote for their assigned beacon block, return early otherwise
        if data.slot != state.slot() {
            return Ok(PayloadAttestationAction::Ignore(payload_attestation));
        }

        let attesting_indices = match self.payload_attesting_indices(
            state,
            &payload_attestation.item,
            !skip_signatures_verification && payload_attestation.origin.verify_signatures(),
        ) {
            Ok(attesting_indices) => attesting_indices,
            Err(source) => {
                return Err(PayloadAttestationValidationError::Other {
                    source,
                    payload_attestation: Box::new(payload_attestation),
                });
            }
        };

        let Ok(ptc_members) = accessors::get_ptc(state, data.slot) else {
            return Ok(PayloadAttestationAction::Ignore(payload_attestation));
        };

        // [REJECT] The message's validator index is within the payload committee in get_ptc(state, data.slot).
        // The state is the head state corresponding to processing the block up to the current slot as determined by the fork choice.
        let attesting_indices_positions = match attesting_indices
            .into_iter()
            .map(|validator_index| {
                let positions = ptc_members
                    .iter()
                    .positions(|&member| validator_index == member)
                    .collect_vec();

                ensure!(
                    !positions.is_empty(),
                    Error::<P>::PayloadAttestationNotInCommittee {
                        validator_index,
                        slot: data.slot,
                    }
                );

                Ok((validator_index, positions))
            })
            .collect::<Result<Vec<_>>>()
        {
            Ok(indices) => indices,
            Err(source) => {
                return Err(PayloadAttestationValidationError::Other {
                    source,
                    payload_attestation: Box::new(payload_attestation),
                });
            }
        };

        Ok(PayloadAttestationAction::Accept {
            payload_attestation,
            attesting_indices_positions,
        })
    }

    fn payload_attesting_indices(
        &self,
        state: &Arc<BeaconState<P>>,
        payload_attestation: &CombinedPayloadAttestation<P>,
        validate_signature: bool,
    ) -> Result<Vec<ValidatorIndex>> {
        let data = payload_attestation.data();

        match payload_attestation {
            CombinedPayloadAttestation::Attestation(payload_attestation) => {
                let indexed_payload_attestation =
                    accessors::get_indexed_payload_attestation(state, payload_attestation)?;
                let attesting_indices = indexed_payload_attestation.attesting_indices.to_vec();

                if validate_signature {
                    predicates::validate_constructed_indexed_payload_attestation(
                        &self.chain_config,
                        &self.pubkey_cache,
                        state,
                        &indexed_payload_attestation,
                        SingleVerifier,
                    )?;
                }

                Ok(attesting_indices)
            }
            CombinedPayloadAttestation::Message(payload_attestation) => {
                let validator_index = payload_attestation.validator_index;

                if validate_signature {
                    SingleVerifier.verify_singular(
                        data.signing_root(&self.chain_config, state),
                        payload_attestation.signature,
                        self.pubkey_cache
                            .get_or_insert(*accessors::public_key(state, validator_index)?)?,
                        SignatureKind::PayloadAttestation,
                    )?;
                }

                Ok(vec![validator_index])
            }
        }
    }

    /// [`on_tick`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_tick)
    pub fn apply_tick(&mut self, new_tick: Tick) -> Result<Option<ApplyTickChanges<P>>> {
        let old_tick = self.tick;

        // If multiple tick updates are performed in quick succession, they can come in any order.
        if new_tick <= old_tick {
            return Ok(None);
        }

        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        // > update store time
        self.tick = new_tick;

        if new_tick.slot <= old_tick.slot {
            // `new_tick` is a later tick in the same slot.
            return Ok(Some(ApplyTickChanges::TickUpdated));
        }

        // > Reset store.proposer_boost_root if this is a new slot
        self.proposer_boost_root = H256::zero();

        let mut finalized_checkpoint_updated = false;

        // > If a new epoch, pull-up justification and finalization from previous epoch
        let is_new_epoch = new_tick.epoch::<P>() > old_tick.epoch::<P>();

        if is_new_epoch {
            let old_justified_checkpoint = self.justified_checkpoint;
            let old_finalized_checkpoint = self.finalized_checkpoint;

            self.update_checkpoints(
                self.unrealized_justified_checkpoint,
                self.unrealized_finalized_checkpoint,
            );

            let justified_checkpoint_updated =
                old_justified_checkpoint != self.justified_checkpoint;

            finalized_checkpoint_updated = old_finalized_checkpoint != self.finalized_checkpoint;

            if justified_checkpoint_updated {
                self.update_balances_after_justification()?;
            }

            if finalized_checkpoint_updated {
                self.extend_latest_messages_after_finalization();
            }
        }

        let current_slot_attestations = core::mem::take(&mut self.current_slot_attestations);
        let (differences_empty, differences_full) =
            self.attestation_balance_differences(current_slot_attestations)?;

        self.apply_balance_differences(differences_empty, differences_full)?;
        self.update_head_segment_id();

        // Pruning the state cache requires the head slot, which depends on head_segment_id
        // pointing to the correct head. Therefore, prune state cache after the head_segment_id
        // is updated.
        if is_new_epoch && finalized_checkpoint_updated {
            self.prune_after_finalization();
        }

        self.blob_cache.on_slot(new_tick.slot);
        self.prune_state_cache(true);

        let changes = if self.reorganized(old_head_segment_id) {
            ApplyTickChanges::Reorganized {
                finalized_checkpoint_updated,
                old_head: Box::new(old_head),
            }
        } else {
            ApplyTickChanges::SlotUpdated {
                finalized_checkpoint_updated,
            }
        };

        Ok(Some(changes))
    }

    /// Applies a block previously validated using [`Self::validate_block`].
    ///
    /// Roughly corresponds to [`on_block`] from the Fork Choice specification.
    ///
    /// [`on_block`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_block
    pub fn apply_block(&mut self, chain_link: ChainLink<P>) -> Result<ApplyBlockChanges<P>> {
        let block_root = chain_link.block_root;

        // `Store::insert_block` assumes the block is not present in the store.
        // `fork_choice_control::Mutator::accept_block` ensures this is true.
        assert!(!self.contains_block(block_root));

        // TODO(Grandine Team): Try moving reorganization checks outside `Store::apply_*` methods.
        // The old head must be obtained before making any modifications to the `Store`.
        // Inserting the new block may extend the current head segment, making the head different.
        // Pruning orphans may prune the current head. `Store::head` contains assertions about
        // segment viability that may fail when the `Store` is in an inconsistent state.
        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        // Apply proposer boost to first block in case of equivocation.
        // See <https://github.com/ethereum/consensus-specs/pull/3352>.
        // Check if we're in the first interval according to spec
        // For Gloas: 16 ticks/slot, 4 intervals → first interval is ticks 0-4 (0-3s boundary)
        // For pre-Gloas: 12 ticks/slot, 3 intervals → first interval is ticks 0-3 (0-4s)
        //(temporary fix: needs change in TickKind to not follow strcict before attesting time for gloas)
        let tick_index = self.tick.kind as usize;
        let is_before_attesting_interval = if self.phase() >= Phase::Gloas {
            // Gloas: At exactly 3s, tick_index = 4 (Attest), which should still get boost
            tick_index <= 4
        } else {
            // Pre-Gloas: At exactly 4s, tick_index = 4 (Attest), which should NOT get boost
            tick_index < 4
        };

        let is_current_slot = self.slot() == chain_link.slot();
        let attestation_timely = is_current_slot && is_before_attesting_interval;

        // [Gloas] Record PTC timeliness — block arrived before PayloadAttest deadline
        if self.phase() >= Phase::Gloas
            && is_current_slot
            && self.tick.kind < TickKind::PayloadAttest
        {
            self.ptc_timely_blocks.insert(block_root);
        }

        let is_first_block = self.proposer_boost_root.is_zero();

        // > Add proposer score boost if the block is timely
        //
        // Updating `Store.proposer_boost_root` and the checkpoints before calling
        // `Store::insert_block` can leave the `Store` in an inconsistent state if
        // `Store::insert_block` fails, but only if segment IDs or positions in a segment run out,
        // which is extremely unlikely and at which point the `Store` is unusable anyway.
        if attestation_timely && is_first_block {
            // Verify block's proposer matches expected proposer on canonical chain.
            // Spec: update_proposer_boost_root checks block.proposer_index == get_beacon_proposer_index(head_state)
            // This prevents boost for blocks from wrong proposers (e.g., on non-viable forks).
            let mut head_state = self.head().state(self);
            let slot = self.slot();
            // dev notes: not completerly sure why tests fail when i remove process_slots given that in pre gloas the tests were working without it.
            // but even this code is not wrong given its a spec(https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/fork-choice.md#modified-update_proposer_boost_root)
            // step which can be skipped if called somewhere around same time.
            // the same is true when i move self.proposer_boost_root = block_root out of the propser check. most probable answer is this part of code is now hitting before process_headaer
            // and another factor is with gloas the new block is sent by the propser much earlier.
            if head_state.slot() < slot {
                let _unused = combined::process_slots(
                    &self.chain_config,
                    &self.pubkey_cache,
                    head_state.make_mut(),
                    slot,
                );
            }
            let expected_proposer =
                accessors::get_beacon_proposer_index(&self.chain_config, &head_state).ok();

            if expected_proposer == Some(chain_link.block.message().proposer_index()) {
                self.proposer_boost_root = block_root;

                // [Gloas] Create EMPTY segment for parent if payload hasn't arrived yet.
                // Both variants must exist in the tree for head selection to compare them.
                if self.phase() >= Phase::Gloas {
                    let parent_root = chain_link.block.message().parent_root();
                    if let Some(location) = self.unfinalized_locations_full.get(&parent_root).copied() {
                        let parent_has_payload = self.unfinalized[&location.segment_id][location.position]
                            .chain_link
                            .execution_payload_state
                            .is_some();
                        if !parent_has_payload
                            && !self.unfinalized_locations_empty.contains_key(&parent_root)
                        {
                            if let Err(error) = self.extend_empty_segment(parent_root) {
                                error_with_peers!(
                                    "failed to extend EMPTY segment for parent {parent_root:?}: {error:?}"
                                );
                            }
                        }
                    }
                }
            }
        }

        let old_justified_checkpoint = self.justified_checkpoint;
        let old_finalized_checkpoint = self.finalized_checkpoint;

        // > Update checkpoints in store if necessary
        self.update_checkpoints(
            chain_link.current_justified_checkpoint,
            chain_link.finalized_checkpoint,
        );

        self.update_unrealized_checkpoints(
            chain_link.unrealized_justified_checkpoint,
            chain_link.unrealized_finalized_checkpoint,
        );

        // > If the block is from a prior epoch, apply the realized values
        if self.is_block_from_prior_epoch(&chain_link) {
            self.update_checkpoints(
                chain_link.unrealized_justified_checkpoint,
                chain_link.unrealized_finalized_checkpoint,
            );
        }

        let justified_checkpoint_updated = old_justified_checkpoint != self.justified_checkpoint;
        let finalized_checkpoint_updated = old_finalized_checkpoint != self.finalized_checkpoint;

        let log_imported_block_info = || {
            if let Some(post_deneb_block_body) = chain_link
                .block
                .message()
                .body()
                .with_blob_kzg_commitments()
            {
                if self.should_check_data_availability_at_slot(chain_link.slot()) {
                    let blob_count = post_deneb_block_body.blob_kzg_commitments().len();

                    info_with_peers!(
                        "imported beacon block with {blob_count} blobs (slot: {}, {block_root:?}",
                        chain_link.slot(),
                    );

                    return;
                }
            }

            info_with_peers!(
                "imported beacon block (slot: {}, {block_root:?})",
                chain_link.slot(),
            );
        };

        log_imported_block_info();

        // ePBS: Extract PTC votes from payload_attestations
        if let Some(ref state) = chain_link.block_state {
            if let Err(error) =
                self.notify_ptc_messages(block_root, chain_link.block.as_ref(), state)
            {
                warn_with_peers!("failed to apply payload attestations from block: {error:?}");
            }
        }

        // Ensure the block's payload bid is in accepted_payload_bids so that
        // is_data_available_for_envelope can find commitments for any block,
        // including self-built blocks (BUILDER_INDEX_SELF_BUILD) which bypass
        // the gossip bid path and never call apply_execution_payload_bid.
        if let Some(body) = chain_link.block.message().body().with_payload_bid() {
            let bid = body.signed_execution_payload_bid();
            let slot = bid.message.slot;
            let builder_index = bid.message.builder_index;
            if !self
                .accepted_payload_bids
                .get(&slot)
                .is_some_and(|bids| bids.contains_key(&builder_index))
            {
                self.apply_execution_payload_bid(Arc::new(bid.clone()));
            }
        }

        self.insert_block(chain_link)?;

        if justified_checkpoint_updated {
            self.update_balances_after_justification()?;
        }

        // The head segment does not need to be updated every time a block is added.
        // As of `consensus-specs` 1.1.7 it appears to be necessary only in the following cases:
        // - The block causes a new viable segment to be added.
        // - The block is added to an existing nonviable segment and makes it viable.
        // - The block causes either `Store.justified_checkpoint` or `Store.finalized_checkpoint` to
        //   be updated. This case overlaps with the previous one and may be completely covered by
        //   it depending on how they are implemented. Updating the checkpoints also makes the newly
        //   added block the only viable one, which can be used to speed up the head computation.
        // - The block is timely.
        // However, updating the head segment unconditionally is both easier and more robust,
        // while the cost of it is negligible. Being too clever about it forced us to do some
        // debugging when implementing proposer score boosting.
        self.update_head_segment_id();

        // Pruning the state cache requires the head slot, which depends on head_segment_id
        // pointing to the correct head. Therefore, prune state cache after the head_segment_id
        // is updated.
        if finalized_checkpoint_updated {
            self.extend_latest_messages_after_finalization();
            self.prune_after_finalization();
        }

        if !self.finished_initial_forward_sync && self.head().slot() >= self.slot() {
            self.finished_initial_forward_sync = true;
            self.state_cache.set_log_lock_timeouts(true);
        }

        let changes = if self.reorganized(old_head_segment_id) {
            ApplyBlockChanges::Reorganized {
                finalized_checkpoint_updated,
                old_head: Box::new(old_head),
            }
        } else if old_head.block_root == self.head().block_root {
            ApplyBlockChanges::AlternateChainExtended {
                finalized_checkpoint_updated,
            }
        } else {
            ApplyBlockChanges::CanonicalChainExtended {
                finalized_checkpoint_updated,
            }
        };

        Ok(changes)
    }

    /// [`update_checkpoints`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#update_checkpoints)
    const fn update_checkpoints(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
    ) {
        // > Update justified checkpoint
        if justified_checkpoint.epoch > self.justified_checkpoint.epoch {
            self.justified_checkpoint = justified_checkpoint;
        }

        // > Update finalized checkpoint
        if finalized_checkpoint.epoch > self.finalized_checkpoint.epoch {
            self.finalized_checkpoint = finalized_checkpoint;
        }
    }

    /// [`update_unrealized_checkpoints`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#update_unrealized_checkpoints)
    const fn update_unrealized_checkpoints(
        &mut self,
        unrealized_justified_checkpoint: Checkpoint,
        unrealized_finalized_checkpoint: Checkpoint,
    ) {
        // > Update unrealized justified checkpoint
        if unrealized_justified_checkpoint.epoch > self.unrealized_justified_checkpoint.epoch {
            self.unrealized_justified_checkpoint = unrealized_justified_checkpoint;
        }

        // > Update unrealized finalized checkpoint
        if unrealized_finalized_checkpoint.epoch > self.unrealized_finalized_checkpoint.epoch {
            self.unrealized_finalized_checkpoint = unrealized_finalized_checkpoint;
        }
    }

    /// Applies an attestation previously validated using [`Self::validate_attestation`] or
    /// [`Self::validate_aggregate_and_proof`].
    ///
    /// Roughly corresponds to [`on_attestation`] from the Fork Choice specification.
    ///
    /// [`on_attestation`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_attestation
    pub fn apply_attestation(
        &mut self,
        valid_attestation: ValidAttestation<P>,
    ) -> Result<Option<ChainLink<P>>> {
        self.apply_attestation_batch(core::iter::once(valid_attestation))
    }

    // Note that attestation processing never updates justified or finalized checkpoints even though
    // it may produce checkpoint states with later checkpoints. Updating them would make all known
    // forks non-viable.
    pub fn apply_attestation_batch(
        &mut self,
        valid_attestations: impl IntoIterator<Item = ValidAttestation<P>>,
    ) -> Result<Option<ChainLink<P>>> {
        let (differences_empty, differences_full) =
            self.attestation_balance_differences(valid_attestations)?;

        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        self.apply_balance_differences(differences_empty, differences_full)?;
        self.update_head_segment_id();

        self.reorganized(old_head_segment_id)
            .then_some(old_head)
            .pipe(Ok)
    }

    /// Applies a payload attestation previously validated using [`Self::validate_payload_attestation`].
    ///
    /// Roughly corresponds to [`on_payload_attestation_message`] from the Fork Choice specification.
    ///
    /// [`on_payload_attestation_message`]: https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#new-on_payload_attestation_message
    pub fn apply_payload_attestation(
        &mut self,
        valid_payload_attestation: ValidPayloadAttestation,
    ) -> Result<()> {
        self.apply_payload_attestation_batch(core::iter::once(valid_payload_attestation))
    }

    pub fn apply_payload_attestation_batch(
        &mut self,
        valid_payload_attestations: impl IntoIterator<Item = ValidPayloadAttestation>,
    ) -> Result<()> {
        // spec: https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/fork-choice.md#new-on_payload_attestation_message
        let mut updated = false;

        for valid in valid_payload_attestations {
            let block_root = valid.data.beacon_block_root;
            let ptc_votes = self
                .ptc_vote
                .entry(block_root)
                .or_insert_with(BitVector::default);

            for (_validator_index, positions) in valid.attesting_indices_positions {
                for position in positions {
                    let index = usize::try_from(position)?;
                    ptc_votes.set(index, valid.data.payload_present);
                    // TODO(gloas): https://github.com/ethereum/consensus-specs/blame/e8b77415ffce13ee2b14a5c22417a1f77f1dca34/specs/gloas/fork-choice.md#L153
                    //Track blob-data-availability votes separately from payload-presence votes.
                    updated = true;
                }
            }
        }

        if updated {
            self.update_head_segment_id();
        }

        Ok(())
    }

    /// [`on_attester_slashing`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_attester_slashing)
    pub fn apply_attester_slashing(
        &mut self,
        slashable_indices: Vec<ValidatorIndex>,
    ) -> Result<Option<ChainLink<P>>> {
        let mut differences_empty = Self::difference_map();
        let mut differences_full = Self::difference_map();

        for validator_index in slashable_indices {
            // Votes of slashed validators should not be used to compute the head.
            self.equivocating_indices.insert(validator_index);

            let index = usize::try_from(validator_index)?;

            let Some(Some(latest_message)) = &self.latest_messages.get(index) else {
                continue;
            };

            let balance = self.justified_active_balance(index);

            // [Gloas] Route to correct map based on payload_present
            if latest_message.payload_present {
                differences_full
                    .entry(latest_message.beacon_block_root)
                    .or_default()
                    .sub_assign(balance);
            } else {
                differences_empty
                    .entry(latest_message.beacon_block_root)
                    .or_default()
                    .sub_assign(balance);
            }
        }

        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        self.apply_balance_differences(differences_empty, differences_full)?;
        self.update_head_segment_id();

        self.reorganized(old_head_segment_id)
            .then_some(old_head)
            .pipe(Ok)
    }

    // TODO: Implement apply_execution_payload_envelope
    // This should:
    // 1. Insert (slot, beacon_block_root, builder_index) into accepted_execution_payload_envelopes
    // 2. Add envelope to execution_payload_envelope_cache
    // 3. Update ChainLink from empty variant to full variant with execution payload
    // 4. Integrate with execution engine for payload validation

    pub fn apply_blob_sidecar(&mut self, blob_sidecar: Arc<BlobSidecar<P>>) {
        let block_header = blob_sidecar.signed_block_header.message;
        let block_root = block_header.hash_tree_root();

        let commitments = self
            .accepted_blob_sidecars
            .entry((
                block_header.slot,
                block_header.proposer_index,
                blob_sidecar.index,
            ))
            .or_default();

        commitments.insert(block_root, blob_sidecar.kzg_commitment);

        self.blob_cache.insert(blob_sidecar);
    }

    pub fn apply_execution_payload_bid(&mut self, payload_bid: Arc<SignedExecutionPayloadBid<P>>) {
        let accepted_bids = self
            .accepted_payload_bids
            .entry(payload_bid.message.slot)
            .or_default();

        accepted_bids.insert(payload_bid.message.builder_index, payload_bid);
    }

    pub fn apply_data_column_sidecar(&mut self, data_sidecar: Arc<DataColumnSidecar<P>>) {
        if let Some(data_sidecar) = data_sidecar.pre_gloas() {
            let block_header = data_sidecar.signed_block_header.message;
            let block_root = block_header.hash_tree_root();

            let commitments = self
                .accepted_data_column_sidecars
                .entry((
                    block_header.slot,
                    block_header.proposer_index,
                    data_sidecar.index,
                ))
                .or_default();

            commitments.insert(block_root, data_sidecar.kzg_commitments.clone());
        } else {
            let block_root = data_sidecar.beacon_block_root();
            let column_index = data_sidecar.index();

            self.accepted_gloas_data_column_sidecars
                .insert((block_root, column_index), data_sidecar.slot());
        }

        self.data_column_cache.insert(data_sidecar);
    }

    /// Implements `on_execution_payload` from fork choice spec
    ///
    /// Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice#on_execution_payload
    /// ePBS: Apply execution payload envelope to create full variant.
    /// Called after validation passes. Processes execution payload and inserts via insert_payload().
    pub fn apply_execution_payload_envelope(
        &mut self,
        signed_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
        execution_engine: impl ExecutionEngine<P>,
    ) -> Result<()> {
        let envelope = &signed_envelope.message;
        let key = (
            envelope.slot,
            envelope.beacon_block_root,
            envelope.builder_index,
        );
        let beacon_block_root = envelope.beacon_block_root;
        let payload = &envelope.payload;

        self.accepted_execution_payload_envelopes.insert(key);

        // Cache envelope so is_data_available() can find it.
        // Must happen before the is_data_available check below (TODO from handle payload PR step 2).
        // TODO: handle apply fail early insert scenario
        self.execution_payload_envelope_cache
            .insert(signed_envelope.clone());

        // Get FULL placeholder (Pending state — payload not yet arrived)
        let chain_link = self.chain_link_full(beacon_block_root).ok_or_else(|| {
            anyhow::anyhow!(
                "FULL placeholder not found for beacon_block_root {beacon_block_root:?}"
            )
        })?;

        // Payload already processed — duplicate envelope
        if chain_link.execution_payload_state.is_some() {
            return Ok(());
        }

        // Get block_state from FULL placeholder (pre-execution state)
        let block_state = chain_link.state(self);

        ensure!(
            self.is_data_available(beacon_block_root),
            "blob/data not available for beacon_block_root {beacon_block_root:?}"
        );

        // Clone state for execution payload processing
        let mut execution_state = block_state.clone_arc();

        // Process execution payload (state transition)
        // Spec: https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice#on_execution_payload
        // process_execution_payload()
        // This validates payload consistency, processes for gossip, notifies EL, updates state
        if let BeaconState::Gloas(gloas_state) = execution_state.make_mut() {
            transition_functions::gloas::process_execution_payload(
                &self.chain_config,
                &self.pubkey_cache,
                gloas_state,
                &signed_envelope,
                execution_engine,
                NullVerifier, // Signature already verified in validate_execution_payload_envelope
            )?;
        } else {
            bail!("Execution payload envelope requires Gloas state");
        }
        // Fill the FULL placeholder with execution_payload_state
        self.insert_payload(beacon_block_root, execution_state, payload.block_hash)?;
        // Re-run head selection - full variant may now win via tiebreaker
        self.update_head_segment_id();

        Ok(())
    }

    /// Fill existing FULL placeholder with execution payload state.
    ///
    /// The FULL placeholder was created by insert_block(). This method fills
    /// the execution_payload_state on the existing UnfinalizedBlock.
    /// No new segment is created - we just update the placeholder in place.
    fn insert_payload(
        &mut self,
        beacon_block_root: H256,
        execution_payload_state: Arc<BeaconState<P>>,
        execution_block_hash: ExecutionBlockHash,
    ) -> Result<()> {
        // Find existing FULL placeholder
        let Some(&location) = self.unfinalized_locations_full.get(&beacon_block_root) else {
            bail!(
                "insert_payload: FULL placeholder not found for beacon_block_root: {beacon_block_root:?}"
            );
        };

        // Get the UnfinalizedBlock and fill execution_payload_state
        let segment = self
            .unfinalized
            .get_mut(&location.segment_id)
            .expect("segment should exist for location in unfinalized_locations_full");
        let unfinalized_block = &mut segment[location.position];

        // Fill the placeholder with execution state
        unfinalized_block.chain_link.execution_payload_state = Some(execution_payload_state);

        // Update execution_payload_locations map
        self.execution_payload_locations
            .insert(execution_block_hash, location);

        Ok(())
    }

    /// Create EMPTY segment as sibling of existing FULL placeholder.
    ///
    /// Called lazily when EMPTY variant is needed:
    /// 1. Attestation arrives with payload_present=false
    /// 2. Proposer boost targets EMPTY variant
    /// 3. Child block arrives with execution parent mismatch
    /// 4. should_extend_payload returns false
    ///
    /// Caller should check unfinalized_locations_empty.contains_key() first.
    fn extend_empty_segment(&mut self, block_root: H256) -> Result<()> {
        // Guard: never create EMPTY segments for already-finalized blocks.
        // Their FULL variant has already been processed and finalized;
        // creating an EMPTY sibling would insert stale locations into
        // unfinalized_locations_empty, causing position underflows during
        // later finalization rounds.
        if self.finalized_indices.contains_key(&block_root) {
            // Already finalized — no-op if location still exists in maps.
            if self
                .unfinalized_locations_empty
                .get(&block_root)
                .or_else(|| self.unfinalized_locations_full.get(&block_root))
                .is_some()
            {
                return Ok(());
            }
            bail!("extend_empty_segment: block {block_root:?} is already finalized");
        }

        // Find FULL placeholder
        let Some(&full_location) = self.unfinalized_locations_full.get(&block_root) else {
            bail!(
                "extend_empty_segment: FULL placeholder not found for block_root: {block_root:?}"
            );
        };

        // Get the FULL placeholder's chain_link
        let full_segment = &self.unfinalized[&full_location.segment_id];
        let full_block = &full_segment[full_location.position];
        let chain_link = full_block.chain_link.clone();

        // Guard: never create EMPTY segments for pre-Gloas blocks.
        // Pre-Gloas blocks always include execution payloads and have no
        // FULL/EMPTY variant semantics. Creating EMPTY siblings for them
        // causes the head selection to follow dead-end branches.
        if chain_link.block.phase() < Phase::Gloas {
            bail!("extend_empty_segment: skipping pre-Gloas block {block_root:?}");
        }

        // EMPTY has same chain_link but execution_payload_state stays None
        // (which it already is in the placeholder)
        let empty_chain_link = ChainLink {
            execution_payload_state: None,
            ..chain_link
        };

        // Get parent location for the sibling segment
        // EMPTY forks from the same parent as FULL
        let parent_location = if full_location.position == Position::default() {
            // FULL is first in its segment - use segment's parent_location
            full_segment.parent_location()
        } else {
            // FULL extends a segment - parent is previous position in same segment
            Some(Location {
                segment_id: full_location.segment_id,
                position: full_location.position.prev()?,
            })
        };

        // Create EMPTY sibling segment
        let empty_location = Location {
            segment_id: self.lowest_unused_segment_id()?,
            position: Position::default(),
        };

        let mut empty_segment = Segment::new(empty_chain_link);
        empty_segment.set_parent_location(parent_location);

        self.unfinalized
            .insert(empty_location.segment_id, empty_segment)
            .unwrap_none();

        // Register EMPTY location
        self.unfinalized_locations_empty
            .insert(block_root, empty_location)
            .unwrap_none();

        Ok(())
    }

    pub fn accepted_data_column_sidecars_count(
        &self,
        block_root: H256,
        data_column_sidecar: &Arc<DataColumnSidecar<P>>,
    ) -> usize {
        if let Some(data_column_sidecar) = data_column_sidecar.pre_gloas() {
            let block_header = data_column_sidecar.signed_block_header.message;

            self.accepted_data_column_sidecars
                .iter()
                .filter(|((slot, proposer_index, _), commitments)| {
                    *slot == block_header.slot
                        && *proposer_index == block_header.proposer_index
                        && commitments.contains_key(&block_root)
                })
                .count()
        } else {
            self.accepted_gloas_data_column_sidecars
                .iter()
                .filter(|((root, _), slot)| {
                    *root == block_root && **slot == data_column_sidecar.slot()
                })
                .count()
        }
    }

    pub fn accepted_data_column_sidecar(
        &self,
        block_root: H256,
        data_column_sidecar: &Arc<DataColumnSidecar<P>>,
    ) -> bool {
        if let Some(data_column_sidecar) = data_column_sidecar.pre_gloas() {
            let block_header = data_column_sidecar.signed_block_header.message;

            if let Some(accepted) = self.accepted_data_column_sidecars.get(&(
                block_header.slot,
                block_header.proposer_index,
                data_column_sidecar.index,
            )) {
                return accepted.contains_key(&block_root);
            }

            false
        } else {
            self.accepted_gloas_data_column_sidecars
                .contains_key(&(block_root, data_column_sidecar.index()))
        }
    }

    pub fn is_reconstruction_enabled_for(&self, block_root: &H256) -> bool {
        // samples enough columns for reconstruction
        self.sampling_columns_count() * 2 >= P::NumberOfColumns::USIZE
            // reconstruction not started for given blocks
            && !self.is_sidecars_construction_started(block_root)
            // reconstruction is enabled during syncing (if syncing)
            && (self.is_forward_synced()
                || !self.store_config().sync_without_reconstruction)
    }

    fn insert_block(&mut self, chain_link: ChainLink<P>) -> Result<()> {
        let block_root = chain_link.block_root;
        let block = &chain_link.block;
        let parent_root = block.message().parent_root();
        let execution_block_hash = block.execution_block_hash();

        let new_block_location;

        // ePBS: For Gloas blocks, determine if child builds on EMPTY or FULL variant of parent.
        // Pre-Gloas blocks always use unfinalized_locations_full (where all blocks are stored).
        let parent = if let Some(gloas_body) = block.message().body().with_payload_bid() {
            let builds_on_full = self.is_parent_node_full_for_block(block);

            if !builds_on_full {
                // EMPTY: Create EMPTY segment for parent if needed
                if !self.unfinalized_locations_empty.contains_key(&parent_root) {
                    self.extend_empty_segment(parent_root)?;
                }
                self.unfinalized_locations_empty.get(&parent_root).copied()
            } else {
                self.unfinalized_locations_full.get(&parent_root).copied()
            }
        } else {
            // Pre-Gloas: all blocks live in unfinalized_locations_full
            self.unfinalized_locations_full.get(&parent_root).copied()
        };

        if let Some(parent) = parent {
            let parent_is_invalid =
                self.unfinalized[&parent.segment_id][parent.position].is_invalid();

            let payload_status = if parent_is_invalid {
                PayloadStatus::Invalid
            } else {
                chain_link.payload_status
            };

            let chain_link = ChainLink {
                payload_status,
                ..chain_link
            };

            if parent.position == self.unfinalized[&parent.segment_id].last_position() {
                new_block_location = Location {
                    segment_id: parent.segment_id,
                    position: parent.position.next()?,
                };

                self.unfinalized[&parent.segment_id].push(UnfinalizedBlock::new(chain_link));
            } else {
                new_block_location = Location {
                    segment_id: self.lowest_unused_segment_id()?,
                    position: Position::default(),
                };
                let mut segment = Segment::new(chain_link);
                segment.set_parent_location(Some(parent));
                self.unfinalized
                    .insert(new_block_location.segment_id, segment)
                    .unwrap_none();
            }
        } else {
            assert!(self.finalized_indices.contains_key(&parent_root));

            new_block_location = Location {
                segment_id: self.lowest_unused_segment_id()?,
                position: Position::default(),
            };

            // parent_location is None for segments rooted at finalized checkpoint
            self.unfinalized
                .insert(new_block_location.segment_id, Segment::new(chain_link))
                .unwrap_none();
        }

        // ePBS: Insert into unfinalized_locations_full (FULL placeholder)
        // This is the default/optimistic path - payload expected to arrive.
        // EMPTY variant created lazily via extend_empty_segment() when triggered.
        self.unfinalized_locations_full
            .insert(block_root, new_block_location)
            .unwrap_none();

        if let Some(block_hash) = execution_block_hash {
            self.execution_payload_locations
                .insert(block_hash, new_block_location);
        }

        Ok(())
    }

    fn finalize_blocks(&mut self) -> Option<Location> {
        let finalized_root = self.finalized_checkpoint.root;

        // Collect canonical segment IDs by walking from head back through parent_locations.
        // In Gloas without execution payload envelopes, the canonical chain flows through
        // EMPTY segments. The FULL-only segment is orphaned and must not be finalized.
        let canonical_segments: HashSet<SegmentId> =
            core::iter::successors(self.head_segment_id, |seg_id| {
                self.unfinalized
                    .get(seg_id)
                    .and_then(|seg| seg.parent_location())
                    .map(|location| location.segment_id)
            })
            .collect();

        // Find finalized root on the canonical chain. Check both EMPTY and FULL maps;
        // use whichever location is on a canonical segment. If neither is canonical
        // (shouldn't happen), fall back to the FULL map for pre-existing behavior.
        let finalized_location = [
            self.unfinalized_locations_empty.get(&finalized_root),
            self.unfinalized_locations_full.get(&finalized_root),
        ]
        .into_iter()
        .flatten()
        .find(|location| canonical_segments.contains(&location.segment_id))
        .or_else(|| self.unfinalized_locations_full.get(&finalized_root))
        .copied();

        let locations_from_newest_to_root =
            core::iter::successors(finalized_location, |location| {
                self.parent_location(&self.unfinalized[&location.segment_id])
            })
            .collect_vec();

        // Updating the finalized checkpoint does not always result in new finalized blocks.
        let locations = locations_from_newest_to_root.split_first()?;
        let (partially_finalized_location, completely_finalized_locations) = locations;

        for completely_finalized_location in completely_finalized_locations.iter().rev() {
            let segment = self
                .unfinalized
                .remove(&completely_finalized_location.segment_id)
                .expect(
                    "self.unfinalized_locations_empty and Segment.parent \
                     should only refer to segments in self.unfinalized",
                );

            let (finalized, orphaned) = segment.split_at(completely_finalized_location.position);

            assert!(!finalized.is_empty());
            assert!(!orphaned.is_empty());

            self.move_to_finalized(finalized);
            self.remove_orphaned(orphaned);
        }

        let finalized = self.unfinalized[&partially_finalized_location.segment_id]
            .finalize_up_to(partially_finalized_location.position);

        self.move_to_finalized(finalized);

        // Invalidate cached parent_locations that are stale:
        // 1. Parent segment was removed (completely finalized or orphaned)
        // 2. Parent segment's first_position advanced past the cached position
        let segments_to_invalidate: Vec<_> = self
            .unfinalized
            .iter()
            .filter_map(|(segment_id, segment)| {
                segment.parent_location().and_then(|parent_loc| {
                    let stale = match self.unfinalized.get(&parent_loc.segment_id) {
                        None => true, // parent segment removed
                        Some(parent_seg) => {
                            parent_loc.position < parent_seg.first_position() // position finalized away
                        }
                    };
                    stale.then_some(*segment_id)
                })
            })
            .collect();

        for segment_id in segments_to_invalidate {
            self.unfinalized
                .get_mut(&segment_id)
                .expect("segment exists")
                .set_parent_location(None);
        }

        Some(*partially_finalized_location)
    }

    fn move_to_finalized(&mut self, unfinalized_blocks: Vector<UnfinalizedBlock<P>>) {
        let Self {
            finalized,
            finalized_indices,
            unfinalized_locations_empty,
            unfinalized_locations_full,
            execution_payload_locations,
            ptc_vote,
            ptc_timely_blocks,
            ..
        } = self;

        let old_len = finalized.len();

        finalized.extend(unfinalized_blocks.into_iter().enumerate().map(
            |(offset, unfinalized_block)| {
                let block_root = unfinalized_block.chain_link.block_root;

                finalized_indices
                    .insert(block_root, old_len + offset)
                    .unwrap_none();

                // ePBS: Need to clean up ALL possible entries for this block:
                // 1. Empty variant (if exists) - keyed by block_root
                // 2. Full variant (if exists) - keyed by block_root
                // 3. execution_payload_locations - keyed by execution_block_hash
                // 4. Both EMPTY and FULL could exist for the same beacon block
                //
                // Use remove() without expect - gracefully handle missing entries

                // Remove from both variant maps (both keyed by block_root)
                unfinalized_locations_empty.remove(&block_root);
                unfinalized_locations_full.remove(&block_root);

                // Remove from execution_payload_locations (keyed by execution_block_hash)
                if let Some(block_hash) = unfinalized_block.chain_link.execution_block_hash() {
                    execution_payload_locations.remove(&block_hash);
                }

                // ePBS: Clean up Gloas-specific maps (keyed by block_root)
                ptc_vote.remove(&block_root);
                ptc_timely_blocks.remove(&block_root);

                unfinalized_block.chain_link
            },
        ));
    }

    fn prune_orphans(&mut self, partially_finalized_location: Location) {
        let mut previous_segment_id = None;

        while let Some((segment_id, segment)) = self.next_segment(previous_segment_id) {
            previous_segment_id = Some(segment_id);

            if self.should_prune_segment(segment, partially_finalized_location) {
                let segment = self
                    .unfinalized
                    .remove(&segment_id)
                    .expect("segment_id was obtained from self.unfinalized");

                self.remove_orphaned(segment.into());
            }
        }
    }

    fn next_segment(
        &self,
        previous_segment_id: Option<SegmentId>,
    ) -> Option<(SegmentId, &Segment<P>)> {
        if let Some(previous_segment_id) = previous_segment_id {
            let (segment_id, segment) = self
                .unfinalized
                .range((Bound::Excluded(previous_segment_id), Bound::Unbounded))
                .next()?;

            return Some((*segment_id, segment));
        }

        let (segment_id, segment) = self.unfinalized.get_min()?;

        Some((*segment_id, segment))
    }

    fn should_prune_segment(
        &self,
        segment: &Segment<P>,
        partially_finalized_location: Location,
    ) -> bool {
        if self.is_root(segment) {
            return false;
        }

        let Some(parent) = self.parent_location(segment) else {
            return true;
        };

        assert!(self.unfinalized.contains_key(&parent.segment_id));

        if parent.segment_id != partially_finalized_location.segment_id {
            return false;
        }

        parent.position < partially_finalized_location.position
    }

    fn remove_orphaned(&mut self, orphaned_blocks: Vector<UnfinalizedBlock<P>>) {
        for block in orphaned_blocks {
            let block_root = block.chain_link.block_root;

            // ePBS: For each orphaned block, need to clean up ALL possible entries:
            // 1. Empty variant (if exists) - keyed by block_root
            // 2. Full variant (if exists) - keyed by block_root
            // 3. execution_payload_locations - keyed by execution_block_hash
            // 4. Both EMPTY and FULL could exist for the same beacon block
            // Remove from both variant maps (both keyed by block_root) but only expect on FULL and debug_assert on empty.
            // TODO: try on using `.expect`after testing more on post finalization cleanup. currently reaching this point multiple times.
            self.unfinalized_locations_empty.remove(&block_root);
            self.unfinalized_locations_full.remove(&block_root);

            // Remove from execution_payload_locations (keyed by execution_block_hash)
            if let Some(block_hash) = block.chain_link.execution_block_hash() {
                self.execution_payload_locations.remove(&block_hash);
            }

            // ePBS: Clean up Gloas-specific maps (keyed by block_root)
            self.ptc_vote.remove(&block_root);
            self.ptc_timely_blocks.remove(&block_root);
        }
    }

    fn prune_checkpoint_states(&mut self) {
        let finalized_epoch = self.finalized_epoch();

        self.checkpoint_states
            .retain(|target, _| finalized_epoch <= target.epoch);
    }

    pub fn unload_old_states(&mut self, unfinalized_states_in_memory: Slot) -> Vec<ChainLink<P>> {
        let head_slot = self.head().slot();

        // `OrdMap` has no `iter_mut` or `values_mut` methods or `IntoIterator` impl for `&mut`.
        // See <https://github.com/bodil/im-rs/issues/138>.
        let segment_ids = self.unfinalized.keys().copied().collect_vec();

        let mut to_persist = vec![];

        for segment_id in segment_ids {
            let segment = &self.unfinalized[&segment_id];
            let segment_last_slot = segment
                .last_non_invalid_block()
                .map(UnfinalizedBlock::slot)
                .unwrap_or_else(|| segment.last_block().slot());
            let far_ahead_non_canonical_segment =
                segment_last_slot >= head_slot + P::SlotsPerEpoch::U64;

            for unfinalized_block in &mut self.unfinalized[&segment_id] {
                let chain_link = &mut unfinalized_block.chain_link;

                if far_ahead_non_canonical_segment {
                    // Keep only one epoch of states in memory for far ahead (relative to head) non-canonical chains
                    if chain_link.slot() + P::SlotsPerEpoch::U64 > segment_last_slot {
                        break;
                    }
                } else if chain_link.slot() + unfinalized_states_in_memory > head_slot {
                    break;
                }

                // Checking whether `chain_link` is justified is neither necessary nor sufficient.
                // It is not necessary because the justified state can be computed from the anchor
                // (as long as the justified block is not orphaned, which is possible according to
                // the Fork Choice specification). It is not sufficient because it does not prevent
                // `ChainLink`s with unloaded states from becoming justified or finalized later.
                if let Some(block_state) = chain_link.block_state.take() {
                    if misc::is_epoch_start::<P>(chain_link.slot()) {
                        let execution_payload_state = chain_link.execution_payload_state.take();
                        to_persist.push(ChainLink {
                            block_state: Some(block_state),
                            execution_payload_state,
                            ..chain_link.clone()
                        });
                    }
                }
            }
        }

        to_persist
    }

    fn update_balances_after_justification(&mut self) -> Result<()> {
        // `Store.timely_proposer_score` is derived from `Store.justified_active_balances`.
        self.timely_proposer_score.take();

        let new_balances = Self::active_balances(self.justified_state());
        let old_balances = core::mem::replace(&mut self.justified_active_balances, new_balances);
        let new_balances = self.justified_active_balances.as_ref();

        let mut differences_empty = Self::difference_map();
        let mut differences_full = Self::difference_map();

        for (validator_index, latest_message, old_balance, new_balance) in izip!(
            0..,
            self.latest_messages.iter(),
            old_balances.iter().copied(),
            new_balances.iter().copied(),
        ) {
            let Some(latest_message) = latest_message else {
                continue;
            };

            // Update `differences` only if the balance changed.
            // This does not affect the result but improves performance.
            if old_balance == new_balance {
                continue;
            }

            // Check `Store.equivocating_indices` last because it's slow.
            // The check is not covered by `consensus-spec-tests` as of version 1.3.0.
            if self.equivocating_indices.contains(&validator_index) {
                continue;
            }

            // [Gloas] Route to correct map based on payload_present
            // Skip FULL-side latest message if FULL execution state is unavailable.
            // If `payload_present = true` but `execution_payload_state` is missing,
            // this vote weight was never applied to the FULL path.
            if self.phase() >= Phase::Gloas && latest_message.payload_present {
                let can_apply_full = self
                    .chain_link_full(latest_message.beacon_block_root)
                    .map(|link: &ChainLink<P>| link.execution_payload_state.is_some())
                    .unwrap_or(false);
                if !can_apply_full {
                    continue;
                }
            }
            let difference = if latest_message.payload_present {
                differences_full
                    .entry(latest_message.beacon_block_root)
                    .or_default()
            } else {
                differences_empty
                    .entry(latest_message.beacon_block_root)
                    .or_default()
            };

            *difference = difference
                .checked_sub_unsigned(old_balance)
                .expect("the combined balances of the planned validators fit in i64");

            *difference = difference
                .checked_add_unsigned(new_balance)
                .expect("the combined balances of the planned validators fit in i64");
        }

        self.apply_balance_differences(differences_empty, differences_full)
    }

    // `Vector` has no `resize` method as of `im` version 15.1.0.
    fn extend_latest_messages_after_finalization(&mut self) {
        let old_length = self.latest_messages.len();
        let new_length = self.last_finalized().state(self).validators().len_usize();
        let added_vacancies = core::iter::repeat_n(None, new_length - old_length);

        self.latest_messages.extend(added_vacancies);
    }

    fn prune_after_finalization(&mut self) {
        if let Some(partially_finalized_location) = self.finalize_blocks() {
            self.prune_orphans(partially_finalized_location);
        }

        let finalized_slot = self.finalized_slot();

        self.execution_payload_envelope_cache
            .prune_finalized(finalized_slot);
        self.accepted_blob_sidecars
            .retain(|(slot, _, _), _| finalized_slot <= *slot);
        self.accepted_data_column_sidecars
            .retain(|(slot, _, _), _| finalized_slot <= *slot);
        self.accepted_gloas_data_column_sidecars
            .retain(|(_, _), slot| finalized_slot <= *slot);
        // TODO: (gloas): prune after block imported, as it's no longer relevant
        self.accepted_payload_bids
            .retain(|slot, _| finalized_slot <= *slot);
        self.accepted_execution_payload_envelopes
            .retain(|(slot, _, _)| finalized_slot <= *slot);
        self.sidecars_construction_started
            .retain(|_, slot| finalized_slot <= *slot);
        self.requested_blobs_from_el
            .retain(|_, slot| finalized_slot <= *slot);
        self.prune_checkpoint_states();
        self.prune_state_cache(false);
        self.aggregate_and_proof_supersets
            .prune(self.finalized_epoch());
    }

    pub fn prune_state_cache(&self, preserve_unfinalized_fork_tips: bool) {
        let retain_slots =
            self.store_config.max_epochs_to_retain_states_in_cache * P::SlotsPerEpoch::U64;

        let prune_slot = self
            .head()
            .slot()
            .saturating_sub(retain_slots)
            .max(self.finalized_slot());

        let preserved_older_states = if preserve_unfinalized_fork_tips {
            self.unfinalized_fork_tips()
                .map(|chain_link| chain_link.block_root)
                .collect()
        } else {
            [].into()
        };

        let head_slot = self.head().slot();
        let mut pruned_newer_states = StdHashSet::new();
        let slots_to_retain = P::SlotsPerEpoch::U64;

        let far_ahead_non_canonical_segments = self
            .unfinalized
            .values()
            .map(|segment| {
                (
                    segment,
                    segment
                        .last_non_invalid_block()
                        .map(UnfinalizedBlock::slot)
                        .unwrap_or_else(|| segment.last_block().slot()),
                )
            })
            .filter(|(_, last_slot)| *last_slot >= head_slot + slots_to_retain);

        for (segment, last_slot) in far_ahead_non_canonical_segments {
            for unfinalized_block in segment {
                let chain_link = &unfinalized_block.chain_link;

                if chain_link.slot() + slots_to_retain < last_slot {
                    pruned_newer_states.insert(chain_link.block_root);
                }
            }
        }

        let prune_result =
            self.state_cache
                .prune(prune_slot, &preserved_older_states, &pruned_newer_states);

        if let Err(error) = prune_result {
            error_with_peers!("failed to prune beacon state cache: {error:?}");
        }
    }

    /// Applies changes to [`Store.latest_messages`] and computes changes to attesting balances.
    ///
    /// Roughly corresponds to [`update_latest_messages`] from the Fork Choice specification.
    ///
    /// [`Store.latest_messages`]:  Store#structfield.latest_messages
    /// [`update_latest_messages`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#update_latest_messages
    fn attestation_balance_differences(
        &mut self,
        valid_attestations: impl IntoIterator<Item = ValidAttestation<P>>,
    ) -> Result<(HashedMap<H256, Difference>, HashedMap<H256, Difference>)> {
        let mut differences_empty: HashedMap<H256, Difference> = Self::difference_map();
        let mut differences_full: HashedMap<H256, Difference> = Self::difference_map();

        // > Update latest messages for attesting indices
        for valid_attestation in valid_attestations {
            let ValidAttestation {
                data,
                ref attesting_indices,
                is_from_block,
            } = valid_attestation;

            let AttestationData {
                slot,
                beacon_block_root,
                target: Checkpoint { epoch, .. },
                ..
            } = data;

            // > Attestations can only affect the fork choice of subsequent slots.
            // > Delay consideration in the fork choice until their slot is in the past.
            //
            // 1 happens to be the value of `MIN_ATTESTATION_INCLUSION_DELAY` in every preset, but
            // that appears to be coincidence. The Fork Choice specification does not reference
            // `MIN_ATTESTATION_INCLUSION_DELAY` in any way.
            if self.slot() <= slot {
                self.current_slot_attestations.push_back(valid_attestation);
                continue;
            }

            if !is_from_block && epoch < self.previous_epoch() {
                continue;
            }

            // Route vote semantics by the voted block phase, not the store phase.
            // At the Fulu->Gloas boundary, attestations can still reference pre-Gloas roots.
            let block_uses_empty_full_variant = self
                .chain_link_full(beacon_block_root)
                .is_some_and(|link| link.block.phase() >= Phase::Gloas);
            let payload_present = !block_uses_empty_full_variant || data.index == 1;

            let latest_message = Arc::new(LatestMessage {
                slot,
                beacon_block_root,
                payload_present,
            });

            // The indices must be filtered here rather than in a task to avoid race conditions.
            // The filtering is not covered by `consensus-spec-tests` as of version 1.3.0.
            // [Gloas] Collect to Vec to allow mutable borrows (extend_empty_segment) in loop
            let attesting_indices: Vec<ValidatorIndex> = attesting_indices
                .into_iter()
                .copied()
                .filter(|index| !self.equivocating_indices.contains(index))
                .collect();

            for validator_index in attesting_indices {
                let index = usize::try_from(validator_index)?;
                let balance = self.justified_active_balance(index);

                // [Gloas] Same-slot votes are pending and stay neutral until a later settled vote.
                let mut same_slot_pending = false;
                if block_uses_empty_full_variant {
                    let voted_block_slot = self
                        .chain_link_full(beacon_block_root)
                        .map(|link| link.block.message().slot());
                    if let Some(voted_block_slot) = voted_block_slot {
                        if slot <= voted_block_slot {
                            same_slot_pending = true;
                        }
                    }
                }

                if let Some(Some(old_message)) = &self.latest_messages.get(index) {
                    let LatestMessage {
                        slot: old_slot,
                        beacon_block_root: old_beacon_block_root,
                        payload_present: old_payload_present,
                    } = **old_message;

                    // Pre-Gloas: compare by epoch
                    // Gloas: compare by slot (ePBS spec)
                    let should_skip = if self.phase() >= Phase::Gloas {
                        slot <= old_slot
                    } else {
                        epoch <= misc::compute_epoch_at_slot::<P>(old_slot)
                    };
                    if should_skip {
                        continue;
                    }

                    // [Gloas] Only skip if BOTH root AND payload_present are same.
                    // Pre-Gloas: payload_present is always true, so this is equivalent to old behavior.
                    // Gloas: same root but different payload_present means vote moved between variants
                    if old_beacon_block_root == beacon_block_root
                        && old_payload_present == payload_present
                    {
                        continue;
                    }
                }

                // Remove previously applied settled vote.
                if let Some(Some(old_message)) = &self.latest_messages.get(index) {
                    let old_root = old_message.beacon_block_root;
                    let old_payload_present = old_message.payload_present;
                    let old_slot = old_message.slot;
                    let old_block_uses_empty_full_variant = self
                        .chain_link_full(old_root)
                        .is_some_and(|link| link.block.phase() >= Phase::Gloas);

                    // Re-derive same-slot status: was the old vote for the same slot as the block?
                    let old_same_slot = if old_block_uses_empty_full_variant {
                        self.chain_link_full(old_root)
                            .is_some_and(|link| old_slot <= link.block.message().slot())
                    } else {
                        false
                    };

                    // Old vote removal:
                    //    - old same-slot vote: subtract BOTH FULL and EMPTY (both were credited earlier).
                    //    - old FULL vote: subtract FULL (envelope guaranteed present via delay-until-envelope).
                    //    - old EMPTY vote: subtract EMPTY.
                    // New vote addition:
                    //    - same-slot pending: add BOTH FULL and EMPTY.
                    //    - FULL vote: add FULL (envelope guaranteed present via delay-until-envelope).
                    //    - EMPTY vote: add EMPTY.
                    if old_same_slot {
                        // [Gloas] Same-slot was added to both Full and Empty; subtract from both.
                        // note that the additon logic is not here. because that is controlled by can_apply_full
                        differences_full
                            .entry(old_root)
                            .or_default()
                            .sub_assign(balance);
                        if old_block_uses_empty_full_variant {
                            differences_empty
                                .entry(old_root)
                                .or_default()
                                .sub_assign(balance);
                        }
                    } else if old_payload_present || !old_block_uses_empty_full_variant {
                        differences_full
                            .entry(old_root)
                            .or_default()
                            .sub_assign(balance);
                    } else {
                        differences_empty
                            .entry(old_root)
                            .or_default()
                            .sub_assign(balance);
                    }
                }
                // spec(gloas): https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/fork-choice.md#new-is_supporting_vote
                // The approach below inlines the behaviour of `is_supporting_vote``
                if same_slot_pending {
                    // [Gloas] Same-slot: apply to both Full and Empty only for post-Gloas blocks.
                    if block_uses_empty_full_variant {
                        let had_empty = self
                            .unfinalized_locations_empty
                            .contains_key(&beacon_block_root);
                        if !had_empty {
                            if let Err(error) = self.extend_empty_segment(beacon_block_root) {
                                error_with_peers!(
                                    "failed to extend EMPTY segment for block {beacon_block_root:?}: {error:?}"
                                );
                            }
                        }
                    }
                    differences_full
                        .entry(beacon_block_root)
                        .or_default()
                        .add_assign(balance);
                    if block_uses_empty_full_variant {
                        differences_empty
                            .entry(beacon_block_root)
                            .or_default()
                            .add_assign(balance);
                    }
                } else if payload_present || !block_uses_empty_full_variant {
                    // TODO(gloas): The vote additon part will be simplified just like the substraction part after v1.7.0-alpha.4
                    let can_apply_full = if block_uses_empty_full_variant {
                        self.chain_link_full(beacon_block_root)
                            .is_some_and(|chain_link: &ChainLink<P>| {
                                chain_link.execution_payload_state.is_some()
                            })
                    } else {
                        true
                    };

                    if can_apply_full {
                        differences_full
                            .entry(beacon_block_root)
                            .or_default()
                            .add_assign(balance);
                    }
                } else {
                    differences_empty
                        .entry(beacon_block_root)
                        .or_default()
                        .add_assign(balance);
                }

                // Note that we mutate `Store.latest_messages` as we go along.
                // This prevents duplicate attestations from being counted more than once.
                if index < self.latest_messages.len() {
                    self.latest_messages[index] = Some(latest_message.clone_arc());
                }
            }
        }

        Ok((differences_empty, differences_full))
    }

    fn apply_balance_differences(
        &mut self,
        differences_empty: impl IntoIterator<Item = (H256, Difference)>,
        differences_full: impl IntoIterator<Item = (H256, Difference)>,
    ) -> Result<()> {
        // This could be parallelized by making `Store::propagate_and_dissolve_differences` return
        // an `Ordmap<SegmentId, DissolvedDifference>`, but it would almost certainly not be worth
        // the overhead.

        // [Gloas] Collect differences_empty and create EMPTY segments lazily
        // We need to collect first because extend_empty_segment needs &mut self
        let differences_empty: Vec<_> = differences_empty.into_iter().collect();

        // Create EMPTY segments for any block receiving positive attestation balance
        for &(block_root, difference) in &differences_empty {
            if difference > 0 && !self.unfinalized_locations_empty.contains_key(&block_root) {
                if let Err(error) = self.extend_empty_segment(block_root) {
                    error_with_peers!(
                        "failed to extend EMPTY segment for block {block_root:?}: {error:?}"
                    );
                }
            }
        }

        for (segment_id, group) in &self
            .propagate_and_dissolve_differences(differences_empty, differences_full)?
            .into_iter()
            .chunk_by(|dissolved_difference| dissolved_difference.segment_id)
        {
            let segment = &mut self.unfinalized[&segment_id];

            for dissolved_difference in group {
                let DissolvedDifference {
                    start,
                    end,
                    difference,
                    ..
                } = dissolved_difference;

                assert_ne!(difference, 0);

                let start = start.unwrap_or_else(|| segment.first_position());

                // Balance updates within a single segment can be easily parallelized with Rayon,
                // but it adds enough overhead to slow down block processing by around 10% even with
                // blocks from the Medalla roughtime incident.
                for unfinalized_block in segment.iter_mut_range(start..=end) {
                    // TODO(Grandine Team): Investigate and fix issue why balances become negative
                    let new_balance = match unfinalized_block
                        .attesting_balance
                        .checked_add_signed(difference)
                    {
                        Some(balance) => balance,
                        None => {
                            error_with_peers!(
                                "{:?}",
                                anyhow!("attesting balance should never go below zero"),
                            );

                            0
                        }
                    };

                    unfinalized_block.attesting_balance = new_balance;
                }
            }
        }

        Ok(())
    }

    // ePBS: Propagate balance differences for both empty and full variants.
    // Converts map keys to Locations using direct lookups, then processes segment tree.
    fn propagate_and_dissolve_differences(
        &self,
        differences_empty: impl IntoIterator<Item = (H256, Difference)>,
        differences_full: impl IntoIterator<Item = (H256, Difference)>,
    ) -> Result<Vec<DissolvedDifference>> {
        let mut difference_queue = BinaryHeap::new();

        // Convert empty map: H256 → Location (direct lookup, tag as empty variant)
        difference_queue.extend(
            differences_empty
                .into_iter()
                .filter(|(_, difference)| *difference != 0)
                .filter_map(|(block_root, difference)| {
                    let location = *self.unfinalized_locations_empty.get(&block_root)?;
                    Some(DifferenceAtLocation {
                        difference,
                        location,
                    })
                }),
        );

        // Convert full map: H256 → Location (direct lookup, tag as full variant)
        difference_queue.extend(
            differences_full
                .into_iter()
                .filter(|(_, difference)| *difference != 0)
                .filter_map(|(beacon_block_root, difference)| {
                    let location = *self.unfinalized_locations_full.get(&beacon_block_root)?;
                    Some(DifferenceAtLocation {
                        difference,
                        location,
                    })
                }),
        );

        let mut propagated_and_dissolved_differences = vec![];

        while let Some(last_in_segment) = difference_queue.pop() {
            let segment_id = last_in_segment.location.segment_id;

            let mut previous = last_in_segment;

            while let Some(current) = difference_queue.peek_mut() {
                if current.location.segment_id != segment_id {
                    break;
                }

                let current = PeekMut::pop(current);

                if previous.location.position != current.location.position {
                    if previous.difference != 0 {
                        propagated_and_dissolved_differences
                            .push(previous.apply_after(current.location.position)?);
                    }

                    previous.location.position = current.location.position;
                }

                previous.difference += current.difference;
            }

            if previous.difference != 0 {
                propagated_and_dissolved_differences.push(previous.apply_from_start());

                if let Some(parent) = self.parent_location(&self.unfinalized[&segment_id]) {
                    difference_queue.push(DifferenceAtLocation {
                        difference: previous.difference,
                        location: parent,
                    });
                }
            }
        }

        Ok(propagated_and_dissolved_differences)
    }
    fn should_follow_branch_point(
        &self,
        segment_id: SegmentId,
        segment: &Segment<P>,
        branch_point: &BranchPoint,
    ) -> bool {
        let next_position_in_segment = branch_point
            .parent
            .position
            .next()
            .expect("next position in segment must be valid because it is already filled");
        let sibling = &segment[next_position_in_segment];
        let sibling_score = self.score(sibling);
        let (sibling_bal, branch_bal) = (sibling_score.0, branch_point.score.0);

        if sibling_bal < branch_bal || sibling.is_invalid() {
            return true;
        }

        if sibling_bal > branch_bal {
            return false;
        }

        // Equal balance:
        // - same root (FULL/EMPTY variants): payload-status tiebreak, then root
        // - different roots: root-only tiebreak (pre-Gloas behavior)
        let sibling_root = sibling.chain_link.block_root;
        let sibling_location = Location {
            segment_id,
            position: next_position_in_segment,
        };
        let sibling_status = self.node_payload_status_at(sibling_location);
        let sibling_tiebreaker = self.get_payload_status_tiebreaker(sibling_root, sibling_status);

        // Compare against the branch point entry root, not the deepest descendant root.
        let branch_root = branch_point.score.1;
        let branch_location = branch_point.root_location;
        let branch_status = self.node_payload_status_at(branch_location);
        let branch_tiebreaker = self.get_payload_status_tiebreaker(branch_root, branch_status);

        if sibling_root == branch_root {
            return (sibling_tiebreaker, sibling_root) < (branch_tiebreaker, branch_root);
        }

        sibling_root < branch_root
    }

    fn should_choose_next_branch_point(
        &self,
        best_branch_for_parent: &BranchPoint,
        next_branch: &BranchPoint,
    ) -> bool {
        let next_viable = self.is_segment_viable(&self.unfinalized[&next_branch.best_descendant]);
        let best_viable =
            self.is_segment_viable(&self.unfinalized[&best_branch_for_parent.best_descendant]);

        if next_viable && !best_viable {
            return true;
        }
        if next_viable != best_viable {
            return false;
        }

        if next_branch.score != best_branch_for_parent.score {
            return next_branch.score > best_branch_for_parent.score;
        }

        let next_root = next_branch.score.1;
        let best_root = best_branch_for_parent.score.1;
        if next_root == best_root && self.phase() >= Phase::Gloas {
            let next_status = self.node_payload_status_at(next_branch.root_location);
            let best_status = self.node_payload_status_at(best_branch_for_parent.root_location);
            let next_tiebreaker = self.get_payload_status_tiebreaker(next_root, next_status);
            let best_tiebreaker = self.get_payload_status_tiebreaker(best_root, best_status);
            return (next_tiebreaker, next_root) > (best_tiebreaker, best_root);
        }

        next_root > best_root
    }

    fn root_segment_tiebreaker(&self, segment_id: SegmentId, segment: &Segment<P>) -> u8 {
        let root = segment.first_block_root();
        let first_location = Location {
            segment_id,
            position: segment.first_position(),
        };
        let status = self.node_payload_status_at(first_location);
        self.get_payload_status_tiebreaker(root, status)
    }
    // Head selection for the current `segment_id` (one-pass grouped branch-point comparison):
    //
    // Baseline:
    // - Start with sibling/same-segment continuation when viable:
    //   `best_descendant_of_segment = viable.then_some(*segment_id)`.
    //(same as existing implementation)
    //
    // Single loop over branch points for this segment:
    // - While heap top belongs to this `segment_id`, pop one entry (`next_branch`).
    // - Maintain `best_branch_for_parent: Option<BranchPoint>` as running winner for the
    //   current exact parent location (`Location`, not just parent segment id).
    // Branch-point reduction for this segment:
    // 1) Pop branch points while heap top belongs to this `segment_id`.
    // 2) Reduce branch points that share the same parent `Location` using
    //    `should_choose_next_branch_point`.
    // 3) When parent group changes, compare that group winner against sibling once via
    //    `should_follow_branch_point`, and update `best_descendant_of_segment` if it wins.
    //
    // Final group flush:
    // - After loop, compare the last pending parent-group winner against sibling once.
    //
    // Why this structure:
    // - Prevents order-dependent behavior where every popped branch point competes directly
    //   with sibling.
    // - Ensures per-parent branch points are first reduced to one best candidate before sibling
    //   competition.
    // - Preserves default sibling behavior: if branch candidate does not win, sibling remains best
    //   without extra assignment.
    // - operationally:  following the same sibling vs each branchpoint comparision was followed but it gave mulitple glaos test failures.
    // - previous appraoch was more pop order sensitive within a segment. reducing the branch points locaiton first avoids low scoring later
    //   pops replacing stronger earlier candidates better. this was more visible after EMPY/FULL expansion added branhcpoint no per segment.
    // Complexity / heap traffic:
    // - Each branch point is still popped exactly once.
    // - Push/pop volume is effectively unchanged from prior approach.
    // - Improvement is comparison ordering clarity/correctness, not heap cost.
    //
    // Output of this stage:
    // - Chosen `best_descendant_of_segment` is pushed upward as the branch-point descendant for
    //   parent comparison in higher segments (or used as root-segment candidate at top).
    fn update_head_segment_id(&mut self) {
        let mut branch_points = BinaryHeap::<BranchPoint>::new();
        let mut best: Option<(Score, u8, SegmentId)> = None;

        for (segment_id, segment) in self.unfinalized.iter().rev() {
            let viable = self.is_segment_viable(segment);

            // Default winner is the sibling/same-segment continuation when this segment is viable.
            let mut best_descendant_of_segment = viable.then_some(*segment_id);

            // One-pass branch-point handling:
            // keep a running best candidate for the current parent location, and only compare
            // against sibling when that parent-group closes (or at loop end).
            let mut best_branch_for_parent: Option<BranchPoint> = None;
            while let Some(branch_point) = branch_points.peek_mut() {
                if branch_point.parent.segment_id != *segment_id {
                    break;
                }

                let next_branch = PeekMut::pop(branch_point);
                match best_branch_for_parent.take() {
                    None => {
                        best_branch_for_parent = Some(next_branch);
                    }
                    Some(current_best) if current_best.parent == next_branch.parent => {
                        best_branch_for_parent = Some(
                            if self.should_choose_next_branch_point(&current_best, &next_branch) {
                                next_branch
                            } else {
                                current_best
                            },
                        );
                    }
                    Some(current_best) => {
                        if best_descendant_of_segment.is_none() {
                            best_descendant_of_segment = Some(current_best.best_descendant);
                        } else if self.should_follow_branch_point(
                            *segment_id,
                            segment,
                            &current_best,
                        ) {
                            best_descendant_of_segment = Some(current_best.best_descendant);
                        }
                        best_branch_for_parent = Some(next_branch);
                    }
                }
            }

            if let Some(current_best) = best_branch_for_parent {
                if best_descendant_of_segment.is_none() {
                    best_descendant_of_segment = Some(current_best.best_descendant);
                } else if self.should_follow_branch_point(*segment_id, segment, &current_best) {
                    best_descendant_of_segment = Some(current_best.best_descendant);
                }
            }

            if let Some(best_descendant) = best_descendant_of_segment {
                let first_block = segment.first_block();
                let score = self.score(first_block);
                // Use cached first block root.
                let root = segment.first_block_root();

                if let Some(parent) = self.parent_location(segment) {
                    let root_location = Location {
                        segment_id: *segment_id,
                        position: segment.first_position(),
                    };
                    branch_points.push(BranchPoint {
                        parent,
                        best_descendant,
                        score: score.clone(),
                        root_location,
                    });
                    continue;
                }

                // Root segment comparison: use score balance, then root.
                let new_key = (score.0, root);
                let mut new_tiebreaker = None;

                // Replace current best when score is higher, then payload-status tiebreaker, then root.
                let should_update = match &best {
                    None => true,
                    Some((best_score, best_tiebreaker, _best_seg)) => {
                        let best_key = (best_score.0, best_score.1);
                        if new_key > best_key {
                            true
                        } else if new_key < best_key {
                            false
                        } else {
                            // Only compute tiebreaker when (balance, root) ties.
                            let tiebreaker = self.root_segment_tiebreaker(*segment_id, segment);
                            new_tiebreaker = Some(tiebreaker);
                            tiebreaker > *best_tiebreaker
                        }
                    }
                };

                if should_update {
                    let tiebreaker = new_tiebreaker
                        .unwrap_or_else(|| self.root_segment_tiebreaker(*segment_id, segment));
                    best = Some((score, tiebreaker, best_descendant));
                }
            }
        }

        assert!(branch_points.is_empty());

        // Fork choice poisoning may cause all forks to become non-viable.
        // When that happens, it may be more useful to stay on the current fork.
        // That would arguably be a deviation from `consensus-specs`.
        // <https://github.com/ethereum/hive/pull/637#issuecomment-1219219657> claims otherwise.
        self.head_segment_id = best.map(|(_, _, segment_id)| segment_id);
    }

    fn active_balances(state: &BeaconState<P>) -> Arc<[Gwei]> {
        let epoch = accessors::get_current_epoch(state);

        state
            .validators()
            .into_iter()
            .map(|validator| {
                // The `Validator.slashed` check was added in `consensus-specs` version 1.3.0-rc.4.
                if predicates::is_active_validator(validator, epoch) && !validator.slashed {
                    validator.effective_balance
                } else {
                    0
                }
            })
            .collect()
    }

    fn justified_active_balance(&self, index: usize) -> Difference {
        self.justified_active_balances[index]
            .try_into()
            .expect("the effective balance of a single validator should fit in i64")
    }

    fn difference_map() -> HashedMap<H256, Difference> {
        // The original implementation used `im::OrdMap` based on findings in
        // `benches/benches/lookup_in_collection.rs`.
        //
        // `std::collections::HashMap` made the loop in `Store::update_balances_after_justification`
        // roughly twice as fast. It outperformed all other map types from `std` and `im`.
        //
        // `hash_hasher::HashedMap` is slightly faster than `std::collections::HashMap`.
        // It should be safe because block roots are already hashed.
        // A deliberate attack would require publishing blocks.
        //
        // Preallocating memory appears to help when using `std::collections::HashMap`,
        // but has the opposite effect with `hash_hasher::HashedMap`.
        HashedMap::default()
    }

    fn reorganized(&self, old_head_segment_id: Option<SegmentId>) -> bool {
        let new_head_segment_id = self.head_segment_id;
        old_head_segment_id.is_some() && old_head_segment_id != new_head_segment_id
    }

    #[must_use]
    pub fn latest_archivable_index(&self) -> Option<usize> {
        let next_archivable_epoch = self.anchor_epoch() + 1;

        // Restrict the search to valid blocks to avoid archiving optimistic ones.
        // They would be lost because we currently store only valid blocks in the database.
        self.finalized
            .focus()
            .into_iter()
            .enumerate()
            .rev()
            .take_while(|(_, chain_link)| {
                next_archivable_epoch <= Self::epoch_at_slot(chain_link.slot())
            })
            .find(|(_, chain_link)| misc::is_epoch_start::<P>(chain_link.slot()))
            .map(|(index, _)| index)
    }

    pub fn archive_finalized(&mut self, new_anchor_index: usize) -> Vector<ChainLink<P>> {
        let archived = self.finalized.slice(..new_anchor_index);

        self.finalized_indices = self
            .finalized
            .iter()
            .map(|chain_link| chain_link.block_root)
            .enumerate()
            .map(|(index, block_root)| (block_root, index))
            .collect();

        archived
    }

    const fn start_of_epoch(epoch: Epoch) -> Slot {
        misc::compute_start_slot_at_epoch::<P>(epoch)
    }

    fn epoch_at_slot(slot: Slot) -> Epoch {
        misc::compute_epoch_at_slot::<P>(slot)
    }

    fn initial_payload_status(state: &BeaconState<P>) -> PayloadStatus {
        let is_post_merge = state
            .post_bellatrix()
            .is_some_and(predicates::is_merge_transition_complete);

        if is_post_merge && state.slot() != GENESIS_SLOT {
            return PayloadStatus::Optimistic;
        }

        PayloadStatus::Valid
    }

    pub fn load_beacon_state(
        &self,
        block_root: H256,
        slot: Slot,
        state: Option<&Arc<BeaconState<P>>>,
    ) -> Arc<BeaconState<P>> {
        if let Some(state) = state {
            return state.clone_arc();
        }

        let load_result = self
            .state_cache
            .get_or_insert_with(block_root, slot, true, || {
                let stored_state_opt = match self.stored_state_by_block_root(block_root) {
                    Ok(state_opt) => state_opt,
                    Err(error) => {
                        error_with_peers!("failed to load persisted beacon state: {error:?}");
                        None
                    }
                };

                let loaded_state = stored_state_opt
                    .unwrap_or_else(|| self.load_beacon_state_by_state_transition(block_root));

                Ok((loaded_state, None))
            });

        match load_result {
            Ok(state_with_rewards) => state_with_rewards.0,
            Err(error) => {
                error_with_peers!("failed to load beacon state: {error:?}");
                self.load_beacon_state_by_state_transition(block_root)
            }
        }
    }

    fn load_beacon_state_by_state_transition(&self, block_root: H256) -> Arc<BeaconState<P>> {
        let mut blocks_to_process = vec![];

        let mut state = self
            .chain_ending_with(block_root)
            .find_map(|chain_link| {
                let state = chain_link.block_state.clone().or_else(|| {
                    match self.stored_state_by_block_root(chain_link.block_root) {
                        Ok(state_opt) => state_opt,
                        Err(error) => {
                            error_with_peers!("failed to load persisted beacon state: {error:?}");
                            None
                        }
                    }
                });

                if state.is_none() {
                    blocks_to_process.push(&chain_link.block);
                }

                state
            })
            .expect("at least one ancestor should have a state in memory or persisted");

        assert!(!blocks_to_process.is_empty());

        for block in blocks_to_process.into_iter().rev() {
            combined::trusted_state_transition(
                self.chain_config(),
                &self.pubkey_cache,
                state.make_mut(),
                block,
            )
            .expect("state transition should succeed because block is already in store");
        }

        state
    }

    pub fn state_before_or_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        self.state_cache.before_or_at_slot(self, block_root, slot)
    }

    pub fn stored_state_by_block_root(
        &self,
        block_root: H256,
    ) -> Result<Option<Arc<BeaconState<P>>>> {
        self.storage.stored_state_by_block_root(block_root)
    }

    #[must_use]
    pub fn is_forward_synced(&self) -> bool {
        self.head().slot() + self.store_config.max_empty_slots >= self.slot()
    }

    #[must_use]
    pub const fn is_back_synced(&self) -> bool {
        self.finished_back_sync
    }

    pub const fn set_back_synced(&mut self, finished_back_sync: bool) {
        self.finished_back_sync = finished_back_sync;
    }

    fn set_block_payload_status(
        &mut self,
        block_hash: ExecutionBlockHash,
        payload_status: PayloadStatus,
    ) -> bool {
        if let Some(location) = self.execution_payload_locations.get(&block_hash) {
            let Location {
                segment_id,
                position,
            } = location;

            self.unfinalized[segment_id][*position]
                .chain_link
                .payload_status = payload_status;

            true
        } else {
            false
        }
    }

    fn set_block_ancestor_payload_statuses(
        &mut self,
        block_hash: ExecutionBlockHash,
        payload_status: PayloadStatus,
    ) {
        // TODO(Grandine Team): Try to avoid the intermediate `HashSet` and redundant lookups.
        if let Some(location) = self.execution_payload_locations.get(&block_hash) {
            let Location {
                segment_id,
                position,
            } = location;

            let segment = &self.unfinalized[segment_id];

            self.unfinalized_chain_ending_with(segment, *position)
                .skip(1)
                .map_while(ChainLink::execution_block_hash)
                .collect::<HashSet<_>>()
                .into_iter()
                .for_each(|hash| {
                    self.set_block_payload_status(hash, payload_status);
                });

            if self.last_finalized().payload_status != payload_status {
                for chain_link in self.finalized.iter_mut() {
                    chain_link.payload_status = payload_status;
                }
            }
        }
    }

    fn set_block_descendant_payload_statuses(
        &mut self,
        ancestor: ExecutionBlockHash,
        payload_status: PayloadStatus,
    ) {
        // TODO(Grandine Team): Try to avoid the intermediate `HashSet` and redundant lookups.
        self.unfinalized
            .values()
            .flat_map(|segment| {
                self.unfinalized_execution_chain_hashes(ancestor, segment, segment.last_position())
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .for_each(|hash| {
                self.set_block_payload_status(hash, payload_status);
            });
    }

    fn unfinalized_execution_chain_hashes(
        &self,
        ancestor: ExecutionBlockHash,
        ending_segment: &Segment<P>,
        last_included: Position,
    ) -> Vec<ExecutionBlockHash> {
        let mut hashes = vec![];

        for hash in self
            .unfinalized_chain_ending_with(ending_segment, last_included)
            .map_while(ChainLink::execution_block_hash)
        {
            if hash == ancestor {
                return hashes;
            }

            hashes.push(hash);
        }

        vec![]
    }

    pub fn invalidate_block_and_descendant_payloads(&mut self, block_root: H256) {
        let invalidate_blocks_with_roots = self
            .unfinalized
            .values()
            .filter_map(|segment| {
                let chain_block_roots = self
                    .unfinalized_chain_ending_with(segment, segment.last_position())
                    .map(|chain_link| chain_link.block_root)
                    .take_while_inclusive(|root| *root != block_root)
                    .collect::<HashSet<H256>>();

                chain_block_roots
                    .contains(&block_root)
                    .then_some(chain_block_roots)
            })
            .flatten()
            .collect::<HashSet<H256>>();

        for root in invalidate_blocks_with_roots {
            if let Some(chain_link) = self.unfinalized_chain_link_mut(root) {
                chain_link.payload_status = PayloadStatus::Invalid;
            }
        }

        self.update_head_segment_id();
    }

    /// not used yet/ to be tested
    /// brute force traversal approach for reference behaviour: root(source invalidation) to leaf
    /// ePBS: Invalidate FULL variant and all its descendants.
    /// for example in the original function the tree coming out of a valid empty node(as no envelope was seen) will be wiped out
    /// because of using block_root. `  .contains(&block_root)` is satisfied by both.
    /// note: the intended operation is not invalidate every full or every empty in the path. so a flag approach wouldn't help
    ///
    ///
    /// Unlike `invalidate_block_and_descendant_payloads` which uses block_root (ambiguous
    /// for EMPTY/FULL variants), this function:
    /// 1. Starts from FULL's specific Location (via unfinalized_locations_full)
    /// 2. Invalidates from that position to segment end
    /// 3. Finds child segments that fork from the invalidated region
    /// 4. Recursively invalidates those child segments
    ///
    /// This correctly handles the case where EMPTY and FULL variants have different
    /// descendant chains - only FULL's descendants are invalidated.
    pub fn invalidate_block_and_descendant_payloads2(&mut self, block_root: H256) {
        // 1. Get FULL's specific location - only proceed if FULL exists
        let Some(full_loc) = self.unfinalized_locations_full.get(&block_root).copied() else {
            return;
        };

        // 2. Collect all (segment_id, start_position) pairs to invalidate
        //    Using BFS: start from FULL's location, find children, recurse
        let mut to_invalidate: Vec<(SegmentId, Position)> =
            vec![(full_loc.segment_id, full_loc.position)];
        let mut processed_segments: HashSet<SegmentId> = HashSet::new();
        let mut i = 0;

        while i < to_invalidate.len() {
            let (seg_id, start_pos) = to_invalidate[i];
            i += 1;

            // im::HashSet::insert returns new set, use contains to check
            if processed_segments.contains(&seg_id) {
                continue; // Already processed this segment
            }
            processed_segments = processed_segments.update(seg_id);

            // 3. Find child segments that fork from invalidated region
            //    A segment is a child if its parent_location is in [start_pos, segment_end]
            for (child_seg_id, child_segment) in self.unfinalized.iter() {
                if let Some(parent_loc) = self.parent_location(child_segment) {
                    // there is no index to map parent to child relationship. so iteratate all segments. get the parent location.
                    // check the the segment id of the initial-to-be invalidated segment againt the current parent. push to queue
                    if parent_loc.segment_id == seg_id && parent_loc.position >= start_pos {
                        // This segment forks from the invalidated region
                        // Invalidate entire child segment (from position 0)
                        to_invalidate.push((*child_seg_id, child_segment.first_position()));
                    }
                }
            }
        }

        // 4. Invalidate all collected regions
        for (seg_id, start_pos) in to_invalidate {
            if let Some(segment) = self.unfinalized.get_mut(&seg_id) {
                let end_pos = segment.last_position();
                for unfinalized_block in segment.iter_mut_range(start_pos..=end_pos) {
                    unfinalized_block.chain_link.payload_status = PayloadStatus::Invalid;
                }
            }
        }

        self.update_head_segment_id();
    }

    pub fn update_chain_payload_statuses(
        &mut self,
        latest_valid_hash: ExecutionBlockHash,
        block_hash: Option<ExecutionBlockHash>,
    ) -> PayloadAction {
        if self.set_block_payload_status(latest_valid_hash, PayloadStatus::Valid) {
            self.set_block_ancestor_payload_statuses(latest_valid_hash, PayloadStatus::Valid);

            if let Some(block_hash) = block_hash {
                if block_hash != latest_valid_hash {
                    if let Some(location) = self.execution_payload_locations.get(&block_hash) {
                        let Location {
                            segment_id,
                            position,
                        } = location;

                        let segment = &self.unfinalized[segment_id];

                        let descendant_chain_hashes = self.unfinalized_execution_chain_hashes(
                            latest_valid_hash,
                            segment,
                            *position,
                        );

                        if let Some(hash) = descendant_chain_hashes.last() {
                            self.set_block_payload_status(*hash, PayloadStatus::Invalid);
                            self.set_block_descendant_payload_statuses(
                                *hash,
                                PayloadStatus::Invalid,
                            );
                        }
                    } else {
                        return PayloadAction::DelayUntilBlock(block_hash);
                    }
                }
            }

            self.update_head_segment_id();

            return PayloadAction::Accept;
        }

        PayloadAction::DelayUntilBlock(latest_valid_hash)
    }

    pub fn indices_of_missing_blobs(&self, block: &SignedBeaconBlock<P>) -> Vec<BlobIndex> {
        let block = block.message();

        let Some(body) = block.body().with_blob_kzg_commitments() else {
            return vec![];
        };

        let block_root = block.hash_tree_root();

        body.blob_kzg_commitments()
            .into_iter()
            .zip(0..)
            .filter(|(block_commitment, index)| {
                // Since blob store only accepts fully verified blobs from network,
                // beacon block only needs to have the same kzg commitments as all of the matching blob sidecars
                // to know if blobs are valid for the beacon block
                !self
                    .accepted_blob_sidecars
                    .get(&(block.slot(), block.proposer_index(), *index))
                    .is_some_and(|kzg_commitments| {
                        kzg_commitments.get(&block_root) == Some(*block_commitment)
                    })
            })
            .map(|(_, index)| index)
            .collect()
    }

    pub fn indices_of_missing_data_columns(
        &self,
        block: &SignedBeaconBlock<P>,
    ) -> Vec<ColumnIndex> {
        let phase = block.phase();
        let block = block.message();
        let block_root = block.hash_tree_root();

        if phase >= Phase::Gloas {
            let Some(blob_kzg_commitments) = block
                .body()
                .with_payload_bid()
                .map(|body| body.signed_execution_payload_bid().blob_kzg_commitments())
            else {
                return vec![];
            };

            if blob_kzg_commitments.is_empty() {
                return vec![];
            }

            return self
                .sampling_columns
                .iter()
                .filter(|index| {
                    self.accepted_gloas_data_column_sidecars
                        .get(&(block_root, **index))
                        .is_none_or(|slot| *slot != block.slot())
                })
                .copied()
                .collect();
        }

        let Some(body) = block.body().with_blob_kzg_commitments() else {
            return vec![];
        };

        if body.blob_kzg_commitments().is_empty() {
            return vec![];
        }

        self.sampling_columns
            .iter()
            .filter(|index| {
                !self
                    .accepted_data_column_sidecars
                    .get(&(block.slot(), block.proposer_index(), **index))
                    .is_some_and(|kzg_commitments| {
                        kzg_commitments.get(&block_root) == Some(body.blob_kzg_commitments())
                    })
            })
            .copied()
            .collect()
    }

    // note: one of the call sites for this is apply_execution_envelope(spec:
    // https://github.com/ethereum/consensus-specs/blob/915907a6ed6d753bbbee4919a41a1e5b8a6a2d96/specs/gloas/fork-choice.md?plain=1#L678)
    // Avoid requiring the block from store here to prevent circular dependency:
    // envelope may arrive before block import in Gloas paths.
    pub fn is_data_available_for_envelope(
        &self,
        envelope: &SignedExecutionPayloadEnvelope<P>,
    ) -> bool {
        let block_root = envelope.message.beacon_block_root;
        let slot = envelope.message.slot;
        let builder_index = envelope.message.builder_index;
        let phase = self.chain_config.phase_at_slot::<P>(slot);

        if phase < Phase::Gloas {
            return true;
        }

        // Look up commitments from accepted bids. For self-built blocks
        // (BUILDER_INDEX_SELF_BUILD), the bid may not be in the map yet because
        // the envelope arrives before apply_block inserts it. In that case,
        // treat as zero commitments (data available).
        let blob_kzg_commitments = self
            .accepted_payload_bids
            .get(&slot)
            .and_then(|bids_at_slot| {
                bids_at_slot
                    .get(&builder_index)
                    .or_else(|| bids_at_slot.values().max_by_key(|bid| bid.message.value))
            })
            .map(|bid| bid.blob_kzg_commitments());

        let Some(blob_kzg_commitments) = blob_kzg_commitments else {
            if builder_index == BUILDER_INDEX_SELF_BUILD {
                return true;
            }
            return false;
        };

        if blob_kzg_commitments.as_ref().is_empty() {
            return true;
        }

        self.sampling_columns.iter().all(|index| {
            self.accepted_gloas_data_column_sidecars
                .get(&(block_root, *index))
                .is_some_and(|imported_slot| *imported_slot == slot)
        })
    }

    pub fn register_rejected_block(&mut self, block_root: H256) {
        self.rejected_block_roots.insert(block_root);
    }

    pub fn has_unpersisted_blob_sidecars(&self) -> bool {
        self.blob_cache.has_unpersisted_blob_sidecars()
    }

    pub fn mark_persisted_blobs(&mut self, persisted_blob_ids: Vec<BlobIdentifier>) {
        self.blob_cache.mark_persisted_blobs(persisted_blob_ids);
    }

    pub fn unpersisted_blob_sidecars(&self) -> impl Iterator<Item = BlobSidecarWithId<P>> + '_ {
        self.blob_cache.unpersisted_blob_sidecars()
    }

    pub fn has_unpersisted_envelopes(&self) -> bool {
        self.execution_payload_envelope_cache
            .has_unpersisted_envelopes()
    }

    pub fn mark_persisted_envelopes(&mut self, persisted_block_roots: Vec<H256>) {
        self.execution_payload_envelope_cache
            .mark_persisted_envelopes(persisted_block_roots);
    }

    pub fn unpersisted_envelopes(
        &self,
    ) -> impl Iterator<Item = Arc<SignedExecutionPayloadEnvelope<P>>> + '_ {
        self.execution_payload_envelope_cache
            .unpersisted_envelopes()
            .map(|(_, envelope)| envelope)
    }

    pub fn min_checked_block_availability_epoch(&self) -> Epoch {
        self.tick
            .epoch::<P>()
            .checked_sub(self.chain_config.min_epochs_for_block_requests)
            .unwrap_or(GENESIS_EPOCH)
    }

    pub fn min_checked_blob_availability_epoch(&self) -> Epoch {
        self.chain_config.deneb_fork_epoch.max(
            self.tick
                .epoch::<P>()
                .checked_sub(self.chain_config.min_epochs_for_blob_sidecars_requests)
                .unwrap_or(GENESIS_EPOCH),
        )
    }

    pub fn min_checked_data_column_availability_epoch(&self) -> Epoch {
        self.chain_config.fulu_fork_epoch.max(
            self.tick
                .epoch::<P>()
                .checked_sub(
                    self.chain_config
                        .min_epochs_for_data_column_sidecars_requests,
                )
                .unwrap_or(GENESIS_EPOCH),
        )
    }

    pub fn min_checked_data_availability_epoch(&self, slot: Slot) -> Epoch {
        if self
            .chain_config
            .phase_at_slot::<P>(slot)
            .is_peerdas_activated()
        {
            self.min_checked_data_column_availability_epoch()
        } else {
            self.min_checked_blob_availability_epoch()
        }
    }

    pub fn should_check_data_availability_at_slot(&self, slot: Slot) -> bool {
        misc::compute_epoch_at_slot::<P>(slot) >= self.min_checked_data_availability_epoch(slot)
    }

    pub fn state_cache(&self) -> Arc<StateCacheProcessor<P>> {
        self.state_cache.clone_arc()
    }

    pub fn mark_persisted_data_columns(
        &mut self,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
    ) {
        self.data_column_cache
            .mark_persisted_data_columns(persisted_data_column_ids);
    }

    pub fn prune_data_columns(&mut self, slot: Slot) {
        self.data_column_cache.prune(slot);
    }

    pub fn prune_persisted_data_columns(&mut self, slot: Slot) {
        self.data_column_cache.prune_persisted(slot);
    }

    pub fn unpersisted_data_column_sidecars(
        &self,
    ) -> impl Iterator<Item = DataColumnSidecarWithId<P>> + '_ {
        self.data_column_cache.unpersisted_data_column_sidecars()
    }

    pub fn store_sampling_columns(&mut self, sampling_columns: StdHashSet<ColumnIndex>) {
        self.sampling_columns = sampling_columns;
    }

    pub fn sampling_columns_count(&self) -> usize {
        self.sampling_columns.len()
    }

    pub const fn sampling_columns(&self) -> &StdHashSet<ColumnIndex> {
        &self.sampling_columns
    }

    pub fn is_sidecars_construction_started(&self, block_root: &H256) -> bool {
        self.sidecars_construction_started.contains_key(block_root)
    }

    pub fn mark_sidecar_construction_started(&self, block_root: H256, slot: Slot) {
        self.sidecars_construction_started.insert(block_root, slot);
    }

    pub fn mark_sidecar_construction_failed(&self, block_root: &H256) {
        self.sidecars_construction_started.remove(block_root);
    }

    pub fn has_requested_blobs_from_el(&self, block_root: &H256) -> bool {
        self.requested_blobs_from_el.contains_key(block_root)
    }

    pub fn mark_requested_blobs_from_el(&mut self, block_root: H256, slot: Slot) {
        self.requested_blobs_from_el.insert(block_root, slot);
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "blob_store",
            self.blob_cache.size(),
        );
        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "data_column_store",
            self.data_column_cache.size(),
        );
        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "finalized",
            self.finalized().len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unfinalized",
            self.unfinalized().len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unfinalized_segment_blocks",
            self.unfinalized
                .values()
                .map(|segment| segment.len().get())
                .sum(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "finalized_indices",
            self.finalized_indices.len(),
        );

        // ePBS: Report both location maps
        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unfinalized_locations_empty",
            self.unfinalized_locations_empty.len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unfinalized_locations_full",
            self.unfinalized_locations_full.len(),
        );

        metrics.set_collection_length(
            "fork_choice_store",
            &type_name,
            "justified_active_balances",
            self.justified_active_balances.len(),
        );

        metrics.set_collection_length(
            "fork_choice_store",
            &type_name,
            "latest_messages",
            self.latest_messages.len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "checkpoint_states",
            self.checkpoint_states.len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "unpersisted_data_columns",
            self.unpersisted_data_column_sidecars().count(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "current_slot_attestations",
            self.current_slot_attestations.len(),
        );
    }
}
