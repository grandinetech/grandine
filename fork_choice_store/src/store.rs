use core::ops::{AddAssign as _, Bound, SubAssign as _};
use std::{
    backtrace::Backtrace,
    collections::binary_heap::{BinaryHeap, PeekMut},
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, bail, ensure, Result};
use arithmetic::NonZeroExt as _;
use clock::Tick;
use eip_7594::{verify_kzg_proofs, verify_sidecar_inclusion_proof};
use execution_engine::ExecutionEngine;
use features::Feature;
use hash_hasher::HashedMap;
use helper_functions::{
    accessors,
    error::SignatureKind,
    misc, predicates,
    signing::SignForSingleFork as _,
    slot_report::NullSlotReport,
    verifier::{NullVerifier, SingleVerifier, Verifier},
};
use im::{hashmap, hashmap::HashMap, ordmap, vector, HashSet, OrdMap, Vector};
use itertools::{izip, Either, EitherOrBoth, Itertools as _};
use log::{error, warn};
use prometheus_metrics::Metrics;
use ssz::{ContiguousList, SszHash as _};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use transition_functions::{
    combined,
    unphased::{self, ProcessSlots, StateRootPolicy},
};
use typenum::Unsigned as _;
use types::{
    bellatrix::containers::PowBlock,
    combined::{BeaconState, SignedBeaconBlock},
    config::Config as ChainConfig,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::{BlobIndex, KzgCommitment},
    },
    eip7594::{ColumnIndex, DataColumnIdentifier, DataColumnSidecar, NumberOfColumns},
    nonstandard::{BlobSidecarWithId, DataColumnSidecarWithId, PayloadStatus, Phase, WithStatus},
    phase0::{
        consts::{ATTESTATION_PROPAGATION_SLOT_RANGE, GENESIS_EPOCH, GENESIS_SLOT},
        containers::{
            AggregateAndProof, Attestation, AttestationData, AttesterSlashing, Checkpoint,
            SignedAggregateAndProof,
        },
        primitives::{Epoch, ExecutionBlockHash, Gwei, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, PostBellatrixBeaconBlockBody, SignedBeaconBlock as _},
};
use unwrap_none::UnwrapNone as _;

use crate::{
    blob_cache::BlobCache,
    data_column_cache::DataColumnCache,
    error::Error,
    misc::{
        AggregateAndProofAction, AggregateAndProofOrigin, ApplyBlockChanges, ApplyTickChanges,
        AttestationAction, AttestationOrigin, AttesterSlashingOrigin, BlobSidecarAction,
        BlobSidecarOrigin, BlockAction, BranchPoint, ChainLink, DataColumnSidecarAction,
        Difference, DifferenceAtLocation, DissolvedDifference, LatestMessage, Location,
        PartialAttestationAction, PartialBlockAction, PayloadAction, Score, SegmentId,
        UnfinalizedBlock, ValidAttestation,
    },
    segment::{Position, Segment},
    state_cache::StateCache,
    store_config::StoreConfig,
    supersets::AggregateAndProofSets as AggregateAndProofSupersets,
    DataColumnSidecarOrigin,
};

/// [`Store`] from the Fork Choice specification.
///
/// [`Store`]: https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#store
#[derive(Clone)]
pub struct Store<P: Preset> {
    chain_config: Arc<ChainConfig>,
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
    preprocessed_states: StateCache<P>,
    execution_payload_locations: HashMap<ExecutionBlockHash, Location>,
    aggregate_and_proof_supersets: Arc<AggregateAndProofSupersets<P>>,
    accepted_blob_sidecars:
        HashMap<(Slot, ValidatorIndex, BlobIndex), HashMap<H256, KzgCommitment>>,
    accepted_data_column_sidecars: HashMap<
        (Slot, ValidatorIndex, ColumnIndex),
        HashMap<H256, ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    >,
    blob_cache: BlobCache<P>,
    data_column_cache: DataColumnCache<P>,
    rejected_block_roots: HashSet<H256>,
    finished_initial_forward_sync: bool,
    custody_columns: HashSet<ColumnIndex>,
    metrics: Option<Arc<Metrics>>,
}

impl<P: Preset> Store<P> {
    /// [`get_forkchoice_store`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_forkchoice_store)
    #[must_use]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        store_config: StoreConfig,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        finished_initial_forward_sync: bool,
        metrics: Option<Arc<Metrics>>,
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

        let anchor = ChainLink {
            block_root,
            block: anchor_block,
            state: Some(anchor_state.clone_arc()),
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            payload_status: Self::initial_payload_status(&anchor_state),
        };

        let validator_count = anchor_state.validators().len_usize();
        let latest_messages = itertools::repeat_n(None, validator_count).collect();

        Self {
            chain_config,
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
            checkpoint_states: HashMap::unit(checkpoint, anchor_state),
            current_slot_attestations: vector![],
            preprocessed_states: StateCache::default(),
            execution_payload_locations: hashmap! {},
            aggregate_and_proof_supersets: Arc::new(AggregateAndProofSupersets::new()),
            accepted_blob_sidecars: HashMap::default(),
            accepted_data_column_sidecars: HashMap::default(),
            blob_cache: BlobCache::default(),
            data_column_cache: DataColumnCache::default(),
            rejected_block_roots: HashSet::default(),
            finished_initial_forward_sync,
            custody_columns: HashSet::default(),
            metrics,
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
        // > Use GENESIS_EPOCH for previous when genesis to avoid underflow
        self.current_epoch().saturating_sub(1).max(GENESIS_EPOCH)
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

    #[must_use]
    pub fn chain_link(&self, block_root: H256) -> Option<&ChainLink<P>> {
        if let Some(location) = self.unfinalized_locations.get(&block_root) {
            let Location {
                segment_id,
                position,
            } = location;

            return Some(&self.unfinalized[segment_id][*position].chain_link);
        }

        let index = self.finalized_indices.get(&block_root)?;

        Some(&self.finalized[*index])
    }

    #[must_use]
    pub fn block(&self, block_root: H256) -> Option<WithStatus<&Arc<SignedBeaconBlock<P>>>> {
        let chain_link = self.chain_link(block_root)?;

        Some(WithStatus {
            value: &chain_link.block,
            optimistic: chain_link.is_optimistic(),
            finalized: self.is_slot_finalized(chain_link.slot()),
        })
    }

    #[must_use]
    pub fn contains_block(&self, block_root: H256) -> bool {
        self.contains_unfinalized_block(block_root)
            || self.finalized_indices.contains_key(&block_root)
    }

    fn contains_unfinalized_block(&self, block_root: H256) -> bool {
        self.unfinalized_locations.contains_key(&block_root)
    }

    #[must_use]
    pub fn state_by_state_root(&self, state_root: H256) -> Option<WithStatus<Arc<BeaconState<P>>>> {
        self.canonical_chain()
            .find(|chain_link| chain_link.block.message().state_root() == state_root)
            .map(|chain_link| WithStatus {
                value: chain_link.state(self),
                optimistic: chain_link.is_optimistic(),
                finalized: self.is_slot_finalized(chain_link.slot()),
            })
    }

    pub fn state_by_block_root(&self, block_root: H256) -> Option<Arc<BeaconState<P>>> {
        self.chain_link(block_root)
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
        self.chain_link(self.justified_checkpoint.root)
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
    pub fn unfinalized_chain_link_mut(&mut self, block_root: H256) -> Option<&mut ChainLink<P>> {
        let Location {
            segment_id,
            position,
        } = self.unfinalized_locations.get(&block_root)?;

        Some(&mut self.unfinalized[segment_id][*position].chain_link)
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
        if let Some(location) = self.unfinalized_locations.get(&block_root).copied() {
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
    ) -> impl Iterator<Item = &ChainLink<P>> {
        self.segments_ending_with(segment, last_included)
            .flat_map(|(segment, position)| segment.chain_ending_at(position))
    }

    fn segments_ending_with<'store>(
        &'store self,
        segment: &'store Segment<P>,
        last_included: Position,
    ) -> impl Iterator<Item = (&Segment<P>, Position)> {
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
        let parent_root = segment
            .first_block()
            .chain_link
            .block
            .message()
            .parent_root();
        self.unfinalized_locations.get(&parent_root).copied()
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
            unfinalized_block
                .chain_link
                .state(self)
                .current_justified_checkpoint()
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
    fn score(&self, unfinalized_block: &UnfinalizedBlock<P>) -> Score {
        let attestation_score = unfinalized_block.attesting_balance;

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
        let tiebreaker = unfinalized_block.chain_link.block_root;

        (attestation_score + proposer_score, tiebreaker)
    }

    fn timely_proposer_score(&self) -> Gwei {
        *self.timely_proposer_score.get_or_init(|| {
            let total_active_balance = self.justified_active_balances.iter().sum::<Gwei>();
            let committee_weight = total_active_balance / P::SlotsPerEpoch::non_zero();
            committee_weight * self.chain_config.proposer_score_boost / 100
        })
    }

    /// [`get_ancestor`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_ancestor)
    ///
    /// This should never return `None` in normal operation, but the reasons for that are slightly
    /// different at each call site, so we call `Option::expect` every time we use this instead of
    /// changing the type.
    fn ancestor(&self, descendant_root: H256, ancestor_slot: Slot) -> Option<H256> {
        if let Some(location) = self.unfinalized_locations.get(&descendant_root).copied() {
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

    #[allow(clippy::too_many_lines)]
    pub fn validate_block(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        state_root_policy: StateRootPolicy,
        execution_engine: impl ExecutionEngine<P> + Send,
        verifier: impl Verifier + Send,
    ) -> Result<BlockAction<P>> {
        let block_root = block.message().hash_tree_root();

        // Skip blocks that are already known.
        //
        // This is a slight deviation from `consensus-specs`, but it appears to be compatible with
        // both the fork choice rule and the Networking specification.
        if self.contains_block(block_root) {
            return Ok(BlockAction::Ignore);
        }

        // > Blocks cannot be in the future.
        // > If they are, their consideration must be delayed until the are in the past.
        if self.slot() < block.message().slot() {
            return Ok(BlockAction::DelayUntilSlot(block));
        }

        // > Check that block is later than the finalized epoch slot
        //
        // This is redundant but may be faster than loading the parent block.
        if block.message().slot() <= self.finalized_slot() {
            return Ok(BlockAction::Ignore);
        }

        // > Parent block must be known
        let Some(parent) = self.chain_link(block.message().parent_root()) else {
            return Ok(BlockAction::DelayUntilParent(block));
        };

        // > Check block is a descendant of the finalized block at the checkpoint finalized slot
        //
        // Checking the slot is sufficient because orphans are pruned as soon as possible.
        if parent.slot() < self.finalized_slot() {
            return Ok(BlockAction::Ignore);
        }

        // > Make a copy of the state to avoid mutability issues
        let mut state = self
            .preprocessed_states
            .before_or_at_slot(parent.block_root, block.message().slot())
            .cloned()
            .unwrap_or_else(|| {
                if Feature::WarnOnStateCacheSlotProcessing.is_enabled() && self.is_forward_synced()
                {
                    // `Backtrace::force_capture` can be costly and a warning may be excessive,
                    // but this is controlled by a `Feature` that should be disabled by default.
                    warn!(
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
                .post_bellatrix()
                .filter(|body| predicates::is_merge_transition_block(&state, *body))
            {
                match self.validate_merge_block(&block, body, &execution_engine)? {
                    PartialBlockAction::Accept => {}
                    PartialBlockAction::Ignore => return Ok(BlockAction::Ignore),
                }
            }
        }
        
        // > [Modified in EIP7594] Check if blob data is available
        //
        // If not, this block MAY be queued and subsequently considered when blob data becomes available
        if self
            .chain_config
            .is_eip7594_fork(accessors::get_current_epoch(&state))
        {
            let missing_indices = self.indices_of_missing_data_columns(&parent.block);

            if missing_indices.len() * 2 >= NumberOfColumns::USIZE && self.is_forward_synced() {
                return Ok(BlockAction::DelayUntilBlobs(block));
            }
        } else {
            if !self.indices_of_missing_blobs(&block).is_empty() {
                return Ok(BlockAction::DelayUntilBlobs(block));
            }
        }
        
        // > Check the block is valid and compute the post-state
        combined::custom_state_transition(
            &self.chain_config,
            state.make_mut(),
            &block,
            ProcessSlots::IfNeeded,
            state_root_policy,
            execution_engine,
            verifier,
            NullSlotReport,
        )?;

        let attester_slashing_results = block
            .message()
            .body()
            .attester_slashings()
            .iter()
            .map(|attester_slashing| {
                self.validate_attester_slashing(attester_slashing, AttesterSlashingOrigin::Block)
            })
            .collect();

        let justified_checkpoint = state.current_justified_checkpoint();

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
            block,
            state: Some(state),
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

    /// [`validate_merge_block`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/fork-choice.md#validate_merge_block)
    ///
    /// > Check the parent PoW block of execution payload is a valid terminal PoW block.
    /// >
    /// > Note: Unavailable PoW block(s) may later become available,
    /// > and a client software MAY delay a call to ``validate_merge_block``
    /// > until the PoW block(s) become available.
    fn validate_merge_block<E: ExecutionEngine<P>>(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        body: &(impl PostBellatrixBeaconBlockBody<P> + ?Sized),
        execution_engine: E,
    ) -> Result<PartialBlockAction> {
        if !self.chain_config.terminal_block_hash.is_zero() {
            let epoch = misc::compute_epoch_at_slot::<P>(block.message().slot());

            // > If `TERMINAL_BLOCK_HASH` is used as an override,
            // > the activation epoch must be reached.
            ensure!(
                epoch >= self.chain_config.terminal_block_hash_activation_epoch,
                Error::MergeBlockBeforeActivationEpoch {
                    block: block.clone_arc(),
                },
            );

            ensure!(
                body.execution_payload().parent_hash() == self.chain_config.terminal_block_hash,
                Error::TerminalBlockHashMismatch {
                    block: block.clone_arc(),
                },
            );

            return Ok(PartialBlockAction::Accept);
        }

        if E::IS_NULL {
            return Ok(PartialBlockAction::Accept);
        }

        let pow_block_missing_block_action =
            if execution_engine.allow_optimistic_merge_block_validation() {
                // In case PoW block is not found (e.g. execution engine is not synced),
                // let fork choice optimistically accept beacon block
                PartialBlockAction::Accept
            } else {
                PartialBlockAction::Ignore
            };

        // > Check if `pow_block` is available
        let Some(pow_block) = execution_engine.pow_block(body.execution_payload().parent_hash())
        else {
            return Ok(pow_block_missing_block_action);
        };

        // > Check if `pow_parent` is available
        let Some(pow_parent) = execution_engine.pow_block(pow_block.pow_block.parent_hash) else {
            return Ok(pow_block_missing_block_action);
        };

        // > Check if `pow_block` is a valid terminal PoW block
        self.validate_terminal_pow_block(block, pow_block.pow_block, pow_parent.pow_block)?;

        Ok(PartialBlockAction::Accept)
    }

    /// [`is_valid_terminal_pow_block`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/fork-choice.md#is_valid_terminal_pow_block)
    fn validate_terminal_pow_block(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        pow_block: PowBlock,
        parent: PowBlock,
    ) -> Result<()> {
        ensure!(
            pow_block.total_difficulty >= self.chain_config.terminal_total_difficulty,
            Error::TerminalTotalDifficultyNotReached {
                block: block.clone_arc(),
                pow_block: Box::new(pow_block),
            },
        );

        ensure!(
            parent.total_difficulty < self.chain_config.terminal_total_difficulty,
            Error::TerminalTotalDifficultyReachedByParent {
                block: block.clone_arc(),
                pow_block: Box::new(pow_block),
                parent: Box::new(parent),
            },
        );

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_aggregate_and_proof<I>(
        &self,
        aggregate_and_proof: Box<SignedAggregateAndProof<P>>,
        origin: &AggregateAndProofOrigin<I>,
    ) -> Result<AggregateAndProofAction<P>> {
        let SignedAggregateAndProof {
            ref message,
            signature,
        } = *aggregate_and_proof;

        let AggregateAndProof {
            aggregator_index,
            ref aggregate,
            selection_proof,
        } = *message;

        match self.validate_attestation_internal(aggregate, false)? {
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
        }

        let AttestationData {
            slot,
            index,
            target,
            ..
        } = aggregate.data;

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
            aggregate.aggregation_bits.count_ones() > 0,
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

        if origin.verify_signatures() {
            let chain_config = &self.chain_config;

            // > The `aggregate_and_proof.selection_proof` is a valid signature of the
            // > `aggregate.data.slot` by the validator with index
            // > `aggregate_and_proof.aggregator_index`.
            if let Err(error) =
                slot.verify(chain_config, &target_state, selection_proof, public_key)
            {
                bail!(error.context(Error::InvalidSelectionProof {
                    aggregate_and_proof,
                }));
            }

            // > The aggregator signature, `signed_aggregate_and_proof.signature`, is valid.
            if let Err(error) = message.verify(chain_config, &target_state, signature, public_key) {
                bail!(error.context(Error::InvalidAggregateAndProofSignature {
                    aggregate_and_proof,
                }));
            }
        }

        let attesting_indices =
            self.attesting_indices(&target_state, aggregate, origin.verify_signatures())?;

        // https://github.com/ethereum/consensus-specs/pull/2847
        let is_superset = self.aggregate_and_proof_supersets.check(aggregate);

        Ok(AggregateAndProofAction::Accept {
            aggregate_and_proof,
            attesting_indices,
            is_superset,
        })
    }

    pub fn validate_attestation<I>(
        &self,
        attestation: Arc<Attestation<P>>,
        origin: &AttestationOrigin<I>,
    ) -> Result<AttestationAction<P>> {
        match self.validate_attestation_internal(&attestation, origin.is_from_block())? {
            PartialAttestationAction::Accept => {}
            PartialAttestationAction::Ignore => {
                return Ok(AttestationAction::Ignore);
            }
            PartialAttestationAction::DelayUntilBlock(block_root) => {
                return Ok(AttestationAction::DelayUntilBlock(attestation, block_root));
            }
            PartialAttestationAction::DelayUntilSlot => {
                return Ok(AttestationAction::DelayUntilSlot(attestation));
            }
        }

        let AttestationData {
            slot,
            index,
            target,
            ..
        } = attestation.data;

        // TODO(feature/deneb): Figure out why this validation is split over 2 methods.
        // TODO(feature/deneb): This appears to be unfinished.
        //                      Deneb replaces the old validation with 2 new ones.
        //                      One of them is in `Store::validate_attestation_internal`.
        if self.phase() < Phase::Deneb && origin.validate_as_gossip() {
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
                return Ok(AttestationAction::Ignore);
            }
        }

        if origin.must_be_singular() {
            // > The attestation is unaggregated
            ensure!(
                attestation.aggregation_bits.count_ones() == 1,
                Error::SingularAttestationHasMultipleAggregationBitsSet { attestation },
            );
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
            let Some(state) = self.state_before_or_at_slot(
                target.root,
                misc::compute_start_slot_at_epoch::<P>(target.epoch),
            ) else {
                return Ok(AttestationAction::DelayUntilBlock(attestation, target.root));
            };

            state
        };

        let Ok(relative_epoch) = accessors::relative_epoch(&target_state, target.epoch) else {
            return Ok(AttestationAction::Ignore);
        };

        if let Some(actual) = origin.subnet_id() {
            let committees_per_slot =
                accessors::get_committee_count_per_slot(&target_state, relative_epoch);

            let expected =
                misc::compute_subnet_for_attestation::<P>(committees_per_slot, slot, index)?;

            // > The attestation is for the correct subnet
            ensure!(
                actual == expected,
                Error::SingularAttestationOnIncorrectSubnet {
                    attestation,
                    expected,
                    actual,
                },
            );
        }

        let attesting_indices =
            self.attesting_indices(&target_state, &attestation, origin.validate_indexed())?;

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
        attestation: &Attestation<P>,
        is_from_block: bool,
    ) -> Result<PartialAttestationAction> {
        let AttestationData {
            slot,
            beacon_block_root,
            target,
            ..
        } = attestation.data;

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
                attestation: Arc::new(attestation.clone()),
            },
        );

        // > Attestation target must be for a known block.
        // > If target block is unknown, delay consideration until block is found
        if !self.contains_block(target.root) {
            if Feature::IgnoreAttestationsForUnknownBlocks.is_enabled() {
                return Ok(PartialAttestationAction::Ignore);
            }

            return Ok(PartialAttestationAction::DelayUntilBlock(target.root));
        };

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
                attestation: Arc::new(attestation.clone()),
                block: ghost_vote_block.clone_arc(),
            },
        );

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
                attestation: Arc::new(attestation.clone()),
            },
        );

        Ok(PartialAttestationAction::Accept)
    }

    fn attesting_indices(
        &self,
        target_state: &BeaconState<P>,
        attestation: &Attestation<P>,
        validate_indexed: bool,
    ) -> Result<ContiguousList<ValidatorIndex, P::MaxValidatorsPerCommittee>> {
        let indexed_attestation = accessors::get_indexed_attestation(target_state, attestation)?;

        if validate_indexed {
            predicates::validate_constructed_indexed_attestation(
                &self.chain_config,
                target_state,
                &indexed_attestation,
                SingleVerifier,
            )?;
        }

        Ok(indexed_attestation.attesting_indices)
    }

    pub fn validate_attester_slashing(
        &self,
        attester_slashing: &AttesterSlashing<P>,
        origin: AttesterSlashingOrigin,
    ) -> Result<Vec<ValidatorIndex>> {
        if origin.verify_signatures() {
            unphased::validate_attester_slashing(
                &self.chain_config,
                self.justified_state(),
                attester_slashing,
            )
        } else {
            unphased::validate_attester_slashing_with_verifier(
                &self.chain_config,
                self.justified_state(),
                attester_slashing,
                NullVerifier,
            )
        }
    }

    // TODO(feature/deneb): Format quotes and log message like everything else.
    #[allow(clippy::too_many_lines)]
    pub fn validate_blob_sidecar(
        &self,
        blob_sidecar: Arc<BlobSidecar<P>>,
        block_seen: bool,
        origin: &BlobSidecarOrigin,
        mut verifier: impl Verifier + Send,
    ) -> Result<BlobSidecarAction<P>> {
        let block_header = blob_sidecar.signed_block_header.message;

        // [REJECT] The sidecar's index is consistent with MAX_BLOBS_PER_BLOCK -- i.e. blob_sidecar.index < MAX_BLOBS_PER_BLOCK.
        ensure!(
            blob_sidecar.index < P::MaxBlobsPerBlock::U64,
            Error::BlobSidecarInvalidIndex { blob_sidecar },
        );

        // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_blob_sidecar(blob_sidecar.index) == subnet_id.
        if let Some(actual) = origin.subnet_id() {
            let expected = misc::compute_subnet_for_blob_sidecar(blob_sidecar.index);

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
        if block_header.slot <= self.finalized_slot() {
            return Ok(BlobSidecarAction::Ignore);
        }

        // [IGNORE] The sidecar is the first sidecar for the tuple (block_header.slot, block_header.proposer_index, blob_sidecar.index) with valid header signature, sidecar inclusion proof, and kzg proof.
        // Adjustment: Ignore blob sidecars for unseen blocks only
        if self.accepted_blob_sidecars.contains_key(&(
            block_header.slot,
            block_header.proposer_index,
            blob_sidecar.index,
        )) && !block_seen
        {
            return Ok(BlobSidecarAction::Ignore);
        }

        let mut state = self
            .preprocessed_states
            .before_or_at_slot(block_header.parent_root, block_header.slot)
            .cloned()
            .unwrap_or_else(|| {
                self.chain_link(block_header.parent_root)
                    .or_else(|| self.chain_link_before_or_at(block_header.slot))
                    .map(|chain_link| chain_link.state(self))
                    .unwrap_or_else(|| self.head().state(self))
            });

        // [REJECT] The proposer signature of blob_sidecar.signed_block_header, is valid with respect to the block_header.proposer_index pubkey.
        verifier.verify_singular(
            blob_sidecar.signing_root(&self.chain_config, &state),
            blob_sidecar.signed_block_header.signature,
            accessors::public_key(&state, block_header.proposer_index)?,
            SignatureKind::BlobSidecar,
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
        let Some(parent) = self.chain_link(block_header.parent_root) else {
            return Ok(BlobSidecarAction::DelayUntilParent(blob_sidecar));
        };

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 2/2:
        ensure!(
            !parent.is_invalid(),
            Error::BlobSidecarInvalidParentOfBlock { blob_sidecar },
        );

        // [REJECT] The sidecar is from a higher slot than the sidecar's block's parent (defined by block_header.parent_root).
        let parent_slot = parent.slot();

        ensure!(
            block_header.slot > parent_slot,
            Error::BlobSidecarNotNewerThanBlockParent {
                blob_sidecar,
                parent_slot,
            }
        );

        // [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block
        // -- i.e. get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root.
        let ancestor_at_finalized_slot = self
            .ancestor(block_header.parent_root, self.finalized_slot())
            .expect("every block in the store should have an ancestor at the last finalized slot");

        ensure!(
            ancestor_at_finalized_slot == self.finalized_checkpoint.root,
            Error::BlobSidecarBlockNotADescendantOfFinalized { blob_sidecar },
        );

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
            )
            .unwrap_or(false),
            Error::BlobSidecarInvalid { blob_sidecar }
        );

        // [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot in the context of the current shuffling
        // (defined by block_header.parent_root/block_header.slot).
        // If the proposer_index cannot immediately be verified against the expected shuffling,
        // the sidecar MAY be queued for later processing while proposers for the block's branch are calculated --
        // in such a case do not REJECT, instead IGNORE this message.
        if state.slot() < block_header.slot {
            if Feature::WarnOnStateCacheSlotProcessing.is_enabled() && self.is_forward_synced() {
                // `Backtrace::force_capture` can be costly and a warning may be excessive,
                // but this is controlled by a `Feature` that should be disabled by default.
                warn!(
                    "processing slots for beacon state not found in state cache before state transition \
                    (block root: {:?}, from slot {} to {})\n{}",
                    block_header.parent_root,
                    state.slot(),
                    block_header.slot,
                    Backtrace::force_capture(),
                );
            }

            combined::process_slots(&self.chain_config, state.make_mut(), block_header.slot)?;
        }

        let computed = accessors::get_beacon_proposer_index(&state)?;

        ensure!(
            block_header.proposer_index == computed,
            Error::BlobSidecarProposerIndexMismatch {
                blob_sidecar,
                computed,
            }
        );

        Ok(BlobSidecarAction::Accept(blob_sidecar))
    }

    pub fn validate_data_column_sidecar(
        &self,
        data_column_sidecar: Arc<DataColumnSidecar<P>>,
        origin: &DataColumnSidecarOrigin,
        current_slot: Slot,
        mut verifier: impl Verifier + Send,
        metrics: &Option<Arc<Metrics>>,
    ) -> Result<DataColumnSidecarAction<P>> {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.data_column_sidecars_submitted_for_processing.inc();
        }

        let _data_column_sidecar_verification_timer = metrics
            .as_ref()
            .map(|metrics| metrics.data_column_sidecar_verification_times.start_timer());

        let block_header = data_column_sidecar.signed_block_header.message;

        let mut state = self
            .preprocessed_states
            .before_or_at_slot(block_header.parent_root, block_header.slot)
            .cloned()
            .unwrap_or_else(|| {
                self.chain_link(block_header.parent_root)
                    .or_else(|| self.chain_link_before_or_at(block_header.slot))
                    .map(|chain_link| chain_link.state(self))
                    .unwrap_or_else(|| self.head().state(self))
            });

        // [REJECT] The sidecar's index is consistent with NUMBER_OF_COLUMNS -- i.e. sidecar.index < NUMBER_OF_COLUMNS.
        ensure!(
            data_column_sidecar.index < NumberOfColumns::U64,
            Error::DataColumnSidecarInvalidIndex {
                data_column_sidecar
            },
        );

        // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_data_column_sidecar(sidecar.index) == subnet_id.
        if let Some(subnet_id) = origin.subnet_id() {
            let expected = misc::compute_subnet_for_data_column_sidecar(data_column_sidecar.index);

            ensure!(
                subnet_id == expected,
                Error::DataColumnSidecarOnIncorrectSubnet {
                    data_column_sidecar,
                    expected: expected.try_into().unwrap(),
                    actual: subnet_id,
                },
            );
        }

        // [IGNORE] The sidecar is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that block_header.slot <= current_slot (a client MAY queue future sidecars for processing at the appropriate slot).
        if data_column_sidecar.slot() > current_slot {
            return Ok(DataColumnSidecarAction::Ignore);
        }

        // [IGNORE] The sidecar is from a slot greater than the latest finalized slot -- i.e. validate that block_header.slot > compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
        if data_column_sidecar.signed_block_header.message.slot
            <= misc::compute_start_slot_at_epoch::<P>(state.finalized_checkpoint().epoch)
        {
            return Ok(DataColumnSidecarAction::Ignore);
        }

        // [REJECT] The proposer signature of sidecar.signed_block_header, is valid with respect to the block_header.proposer_index pubkey.
        verifier.verify_singular(
            data_column_sidecar.signing_root(&self.chain_config, &state),
            data_column_sidecar.signed_block_header.signature,
            accessors::public_key(&state, block_header.proposer_index)?,
            SignatureKind::BlobSidecar,
        )?;

        // [REJECT] The sidecar's kzg_commitments field inclusion proof is valid as verified by verify_data_column_sidecar_inclusion_proof(sidecar).
        let _data_column_sidecar_inclusion_proof_verification = metrics
            .as_ref()
            .map(|metrics| &metrics.data_column_sidecar_inclusion_proof_verification);

        ensure!(
            verify_sidecar_inclusion_proof(&data_column_sidecar, _data_column_sidecar_inclusion_proof_verification),
            Error::DataColumnSidecarInvalidInclusionProof {
                data_column_sidecar
            }
        );

        // [REJECT] The sidecar's column data is valid as verified by verify_data_column_sidecar_kzg_proofs(sidecar).
        let _data_column_sidecar_kzg_verification_single = metrics
            .as_ref()
            .map(|metrics| &metrics.data_column_sidecar_kzg_verification_single);

        verify_kzg_proofs(
            &data_column_sidecar, 
            _data_column_sidecar_kzg_verification_single)
            .map_err(|error| {
                Error::DataColumnSidecarInvalid {
                    data_column_sidecar: data_column_sidecar.clone_arc(),
                    error,
                }
            }
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

        // [IGNORE] The sidecar's block's parent (defined by block_header.parent_root) has been seen (via both gossip and non-gossip sources) (a client MAY queue sidecars for processing once the parent block is retrieved).
        let Some(parent) = self.chain_link(block_header.parent_root) else {
            return Ok(DataColumnSidecarAction::DelayUntilParent(
                data_column_sidecar,
            ));
        };

        // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
        // Part 2/2:
        ensure!(
            !parent.is_invalid(),
            Error::DataColumnSidecarInvalidParentOfBlock {
                data_column_sidecar
            }
        );

        // [REJECT] The sidecar is from a higher slot than the sidecar's block's parent (defined by block_header.parent_root).
        let parent_slot = parent.slot();

        ensure!(
            block_header.slot > parent_slot,
            Error::DataColumnSidecarNotNewerThanBlockParent {
                data_column_sidecar,
                parent_slot,
            }
        );

        // [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block -- i.e. get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root.
        let ancestor_at_finalized_slot = self
            .ancestor(block_header.parent_root, self.finalized_slot())
            .expect("every block in the store should have an ancestor at the last finalized slot");

        ensure!(
            ancestor_at_finalized_slot == self.finalized_checkpoint.root,
            Error::DataColumnSidecarBlockNotADescendantOfFinalized {
                data_column_sidecar
            },
        );

        // [IGNORE] The sidecar is the first sidecar for the tuple (block_header.slot, block_header.proposer_index, sidecar.index) with valid header signature, sidecar inclusion proof, and kzg proof.
        if self.accepted_data_column_sidecars.contains_key(&(
            block_header.slot,
            block_header.proposer_index,
            data_column_sidecar.index,
        )) {
            return Ok(DataColumnSidecarAction::Ignore);
        }

        // [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot in the context of the current shuffling (defined by block_header.parent_root/block_header.slot). If the proposer_index cannot immediately be verified against the expected shuffling, the sidecar MAY be queued for later processing while proposers for the block's branch are calculated -- in such a case do not REJECT, instead IGNORE this message.
        if state.slot() < block_header.slot {
            if Feature::WarnOnStateCacheSlotProcessing.is_enabled() && self.is_forward_synced() {
                // `Backtrace::force_capture` can be costly and a warning may be excessive,
                // but this is controlled by a `Feature` that should be disabled by default.
                warn!(
                    "processing slots for beacon state not found in state cache before state transition \
                    (block root: {:?}, from slot {} to {})\n{}",
                    block_header.parent_root,
                    state.slot(),
                    block_header.slot,
                    Backtrace::force_capture(),
                );
            }

            combined::process_slots(&self.chain_config, state.make_mut(), block_header.slot)?;
        }

        let computed = accessors::get_beacon_proposer_index(&state)?;

        ensure!(
            block_header.proposer_index == computed,
            Error::DataColumnSidecarProposerIndexMismatch {
                data_column_sidecar,
                computed,
            }
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.verified_gossip_data_column_sidecar.inc();
        }

        Ok(DataColumnSidecarAction::Accept(data_column_sidecar))
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
        if new_tick.epoch::<P>() > old_tick.epoch::<P>() {
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
                self.prune_after_finalization();
            }
        }

        let current_slot_attestations = core::mem::take(&mut self.current_slot_attestations);
        let differences = self.attestation_balance_differences(current_slot_attestations)?;

        self.apply_balance_differences(differences)?;
        self.update_head_segment_id();

        self.blob_cache.on_slot(new_tick.slot);
        self.data_column_cache.on_slot(new_tick.slot);

        let changes = if self.reorganized(old_head_segment_id) {
            ApplyTickChanges::Reorganized {
                finalized_checkpoint_updated,
                old_head,
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
        let is_before_attesting_interval = self.tick.is_before_attesting_interval();
        let is_first_block = self.proposer_boost_root.is_zero();

        // > Add proposer score boost if the block is timely
        //
        // Updating `Store.proposer_boost_root` and the checkpoints before calling
        // `Store::insert_block` can leave the `Store` in an inconsistent state if
        // `Store::insert_block` fails, but only if segment IDs or positions in a segment run out,
        // which is extremely unlikely and at which point the `Store` is unusable anyway.
        if self.slot() == chain_link.slot() && is_before_attesting_interval && is_first_block {
            self.proposer_boost_root = block_root;
        }

        let old_justified_checkpoint = self.justified_checkpoint;
        let old_finalized_checkpoint = self.finalized_checkpoint;

        // > Update checkpoints in store if necessary
        self.update_checkpoints(
            chain_link.state(self).current_justified_checkpoint(),
            chain_link.state(self).finalized_checkpoint(),
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

        // Temporary logging for debugging
        if let Some(post_deneb_block_body) = chain_link.block.message().body().post_deneb() {
            let blob_count = post_deneb_block_body.blob_kzg_commitments().len();

            log::info!(
                "imported {blob_count}/{blob_count} blobs for beacon block: {block_root:?}, slot: {}",
                chain_link.slot()
            );
        }

        self.insert_block(chain_link)?;

        if justified_checkpoint_updated {
            self.update_balances_after_justification()?;
        }

        if finalized_checkpoint_updated {
            self.extend_latest_messages_after_finalization();
            self.prune_after_finalization();
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

        if !self.finished_initial_forward_sync && self.head().slot() >= self.slot() {
            self.finished_initial_forward_sync = true;
        }

        let changes = if self.reorganized(old_head_segment_id) {
            ApplyBlockChanges::Reorganized {
                finalized_checkpoint_updated,
                old_head,
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
    fn update_checkpoints(
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
    fn update_unrealized_checkpoints(
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
        let differences = self.attestation_balance_differences(valid_attestations)?;

        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        self.apply_balance_differences(differences)?;
        self.update_head_segment_id();

        self.reorganized(old_head_segment_id)
            .then_some(old_head)
            .pipe(Ok)
    }

    /// [`on_attester_slashing`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#on_attester_slashing)
    pub fn apply_attester_slashing(
        &mut self,
        slashable_indices: Vec<ValidatorIndex>,
    ) -> Result<Option<ChainLink<P>>> {
        let mut differences = Self::difference_map();

        for validator_index in slashable_indices {
            // Votes of slashed validators should not be used to compute the head.
            self.equivocating_indices.insert(validator_index);

            let index = usize::try_from(validator_index)?;

            let Some(latest_message) = &self.latest_messages[index] else {
                continue;
            };

            let balance = self.justified_active_balance(index);

            differences
                .entry(latest_message.beacon_block_root)
                .or_default()
                .sub_assign(balance);
        }

        let old_head_segment_id = self.head_segment_id;
        let old_head = self.head().clone();

        self.apply_balance_differences(differences)?;
        self.update_head_segment_id();

        self.reorganized(old_head_segment_id)
            .then_some(old_head)
            .pipe(Ok)
    }

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

    pub fn apply_data_column_sidecar(&mut self, data_sidecar: Arc<DataColumnSidecar<P>>) {
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

        self.data_column_cache.insert(data_sidecar);
    }

    fn insert_block(&mut self, chain_link: ChainLink<P>) -> Result<()> {
        let block_root = chain_link.block_root;
        let block = &chain_link.block;
        let parent_root = block.message().parent_root();
        let execution_block_hash = block.execution_block_hash();

        let new_block_location;

        if let Some(parent) = self.unfinalized_locations.get(&parent_root).copied() {
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

                self.unfinalized
                    .insert(new_block_location.segment_id, Segment::new(chain_link))
                    .unwrap_none();
            }
        } else {
            assert!(self.finalized_indices.contains_key(&parent_root));

            new_block_location = Location {
                segment_id: self.lowest_unused_segment_id()?,
                position: Position::default(),
            };

            self.unfinalized
                .insert(new_block_location.segment_id, Segment::new(chain_link))
                .unwrap_none();
        }

        self.unfinalized_locations
            .insert(block_root, new_block_location)
            .unwrap_none();

        if let Some(block_hash) = execution_block_hash {
            self.execution_payload_locations
                .insert(block_hash, new_block_location);
        }

        Ok(())
    }

    fn finalize_blocks(&mut self) -> Option<Location> {
        let locations_from_newest_to_root = core::iter::successors(
            self.unfinalized_locations
                .get(&self.finalized_checkpoint.root)
                .copied(),
            |location| self.parent_location(&self.unfinalized[&location.segment_id]),
        )
        .collect_vec();

        // Updating the finalized checkpoint does not always result in new finalized blocks.
        let locations = locations_from_newest_to_root.split_first()?;
        let (partially_finalized_location, completely_finalized_locations) = locations;

        for completely_finalized_location in completely_finalized_locations.iter().rev() {
            let segment = self
                .unfinalized
                .remove(&completely_finalized_location.segment_id)
                .expect(
                    "self.unfinalized_locations and Segment.parent \
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

        Some(*partially_finalized_location)
    }

    fn move_to_finalized(&mut self, unfinalized_blocks: Vector<UnfinalizedBlock<P>>) {
        let Self {
            finalized,
            finalized_indices,
            unfinalized_locations,
            execution_payload_locations,
            ..
        } = self;

        let old_len = finalized.len();

        finalized.extend(unfinalized_blocks.into_iter().enumerate().map(
            |(offset, unfinalized_block)| {
                let block_root = unfinalized_block.chain_link.block_root;

                finalized_indices
                    .insert(block_root, old_len + offset)
                    .unwrap_none();

                unfinalized_locations.remove(&block_root).expect(
                    "roots of unfinalized blocks should be present in self.unfinalized_locations",
                );

                if let Some(block_hash) = unfinalized_block.chain_link.execution_block_hash() {
                    execution_payload_locations.remove(&block_hash);
                }

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
            self.unfinalized_locations
                .remove(&block.chain_link.block_root)
                .expect(
                    "roots of unfinalized blocks should be present in self.unfinalized_locations",
                );
        }
    }

    fn prune_checkpoint_states(&mut self) {
        let finalized_epoch = self.finalized_epoch();

        self.checkpoint_states
            .retain(|target, _| finalized_epoch <= target.epoch);
    }

    pub fn unload_old_states(&mut self, unfinalized_states_in_memory: Slot) {
        let head_slot = self.head().slot();

        // `OrdMap` has no `iter_mut` or `values_mut` methods or `IntoIterator` impl for `&mut`.
        // See <https://github.com/bodil/im-rs/issues/138>.
        let segment_ids = self.unfinalized.keys().copied().collect_vec();

        for segment_id in segment_ids {
            for unfinalized_block in &mut self.unfinalized[&segment_id] {
                let chain_link = &mut unfinalized_block.chain_link;

                if head_slot.saturating_sub(chain_link.slot()) < unfinalized_states_in_memory {
                    break;
                }

                // Checking whether `chain_link` is justified is neither necessary nor sufficient.
                // It is not necessary because the justified state can be computed from the anchor
                // (as long as the justified block is not orphaned, which is possible according to
                // the Fork Choice specification). It is not sufficient because it does not prevent
                // `ChainLink`s with unloaded states from becoming justified or finalized later.
                if misc::is_epoch_start::<P>(chain_link.slot()) {
                    continue;
                }

                chain_link.state.take();
            }
        }
    }

    fn update_balances_after_justification(&mut self) -> Result<()> {
        // `Store.timely_proposer_score` is derived from `Store.justified_active_balances`.
        self.timely_proposer_score.take();

        let new_balances = Self::active_balances(self.justified_state());
        let old_balances = core::mem::replace(&mut self.justified_active_balances, new_balances);
        let new_balances = self.justified_active_balances.as_ref();

        let mut differences = Self::difference_map();

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

            let difference = differences
                .entry(latest_message.beacon_block_root)
                .or_default();

            *difference = difference
                .checked_sub_unsigned(old_balance)
                .expect("the combined balances of the planned validators fit in i64");

            *difference = difference
                .checked_add_unsigned(new_balance)
                .expect("the combined balances of the planned validators fit in i64");
        }

        self.apply_balance_differences(differences)
    }

    // `Vector` has no `resize` method as of `im` version 15.1.0.
    fn extend_latest_messages_after_finalization(&mut self) {
        let old_length = self.latest_messages.len();
        let new_length = self.last_finalized().state(self).validators().len_usize();
        let added_vacancies = itertools::repeat_n(None, new_length - old_length);

        self.latest_messages.extend(added_vacancies);
    }

    fn prune_after_finalization(&mut self) {
        if let Some(partially_finalized_location) = self.finalize_blocks() {
            self.prune_orphans(partially_finalized_location);
        }

        let finalized_slot = self.finalized_slot();

        self.accepted_blob_sidecars
            .retain(|(slot, _, _), _| finalized_slot <= *slot);
        self.accepted_data_column_sidecars
            .retain(|(slot, _, _), _| finalized_slot <= *slot);
        // TODO(feature/eip-7594):
        //
        // Data columns must be stored for much longer period than finalization.
        // However, that should be done in persistence layer.
        self.data_column_cache.prune_finalized(finalized_slot);
        self.prune_checkpoint_states();
        self.preprocessed_states.prune(finalized_slot);
        self.aggregate_and_proof_supersets
            .prune(self.finalized_epoch());
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
    ) -> Result<HashedMap<H256, Difference>> {
        let mut differences = Self::difference_map();

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

            let latest_message = Arc::new(LatestMessage {
                epoch,
                beacon_block_root,
            });

            // The indices must be filtered here rather than in a task to avoid race conditions.
            // The filtering is not covered by `consensus-spec-tests` as of version 1.3.0.
            let attesting_indices = attesting_indices
                .iter()
                .copied()
                .filter(|index| !self.equivocating_indices.contains(index));

            for validator_index in attesting_indices {
                let index = usize::try_from(validator_index)?;
                let balance = self.justified_active_balance(index);

                if let Some(old_message) = &self.latest_messages[index] {
                    let LatestMessage {
                        epoch: old_epoch,
                        beacon_block_root: old_beacon_block_root,
                    } = **old_message;

                    if epoch <= old_epoch {
                        continue;
                    }

                    if old_beacon_block_root == beacon_block_root {
                        continue;
                    }

                    differences
                        .entry(old_beacon_block_root)
                        .or_default()
                        .sub_assign(balance);
                }

                differences
                    .entry(beacon_block_root)
                    .or_default()
                    .add_assign(balance);

                // Note that we mutate `Store.latest_messages` as we go along.
                // This prevents duplicate attestations from being counted more than once.
                self.latest_messages[index] = Some(latest_message.clone_arc());
            }
        }

        Ok(differences)
    }

    fn apply_balance_differences(
        &mut self,
        differences: impl IntoIterator<Item = (H256, Difference)>,
    ) -> Result<()> {
        // This could be parallelized by making `Store::propagate_and_dissolve_differences` return
        // an `Ordmap<SegmentId, DissolvedDifference>`, but it would almost certainly not be worth
        // the overhead.
        for (segment_id, group) in &self
            .propagate_and_dissolve_differences(differences)?
            .into_iter()
            .group_by(|dissolved_difference| dissolved_difference.segment_id)
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
                            error!(
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

    // This could be rewritten to return an `Iterator` instead of a `Vec`,
    // but the cost of using a `Vec` is probably negligible.
    fn propagate_and_dissolve_differences(
        &self,
        differences: impl IntoIterator<Item = (H256, Difference)>,
    ) -> Result<Vec<DissolvedDifference>> {
        let mut difference_queue = differences
            .into_iter()
            .filter(|(_, difference)| *difference != 0)
            .filter_map(|(block_root, difference)| {
                // `block_root` may refer to a finalized block.
                // Changes to balances of finalized blocks are irrelevant.
                let location = *self.unfinalized_locations.get(&block_root)?;

                Some(DifferenceAtLocation {
                    difference,
                    location,
                })
            })
            .collect::<BinaryHeap<_>>();

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

    fn update_head_segment_id(&mut self) {
        let mut branch_points = BinaryHeap::<BranchPoint>::new();
        let mut best = None;

        for (segment_id, segment) in self.unfinalized.iter().rev() {
            let viable = self.is_segment_viable(segment);

            let mut best_descendant_of_segment = viable.then_some(*segment_id);

            while let Some(branch_point) = branch_points.peek_mut() {
                if branch_point.parent.segment_id != *segment_id {
                    break;
                }

                let branch_point = PeekMut::pop(branch_point);

                if best_descendant_of_segment.is_none() {
                    best_descendant_of_segment = Some(branch_point.best_descendant);
                    continue;
                }

                let next_position_in_segment =
                    branch_point.parent.position.next().expect(
                        "next position in segment must be valid because it is already filled",
                    );

                let sibling = &segment[next_position_in_segment];

                if self.score(sibling) < branch_point.score || sibling.is_invalid() {
                    best_descendant_of_segment = Some(branch_point.best_descendant);
                }
            }

            if let Some(best_descendant) = best_descendant_of_segment {
                let score = self.score(segment.first_block());

                if let Some(parent) = self.parent_location(segment) {
                    branch_points.push(BranchPoint {
                        parent,
                        best_descendant,
                        score,
                    });
                    continue;
                }

                let best_root_segment_score = best.map(|(score, _)| score);

                if best_root_segment_score < Some(score) {
                    best = Some((score, best_descendant));
                }
            }
        }

        assert!(branch_points.is_empty());

        // Fork choice poisoning may cause all forks to become non-viable.
        // When that happens, it may be more useful to stay on the current fork.
        // That would arguably be a deviation from `consensus-specs`.
        // <https://github.com/ethereum/hive/pull/637#issuecomment-1219219657> claims otherwise.
        self.head_segment_id = best.map(|(_, segment_id)| segment_id);
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

    pub fn state_before_or_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        self.preprocessed_state_before_or_at_slot(block_root, slot)
            .cloned()
            .or_else(|| self.state_by_block_root(block_root))
            .filter(|state| state.slot() <= slot)
    }

    #[must_use]
    pub fn preprocessed_state_before_or_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Option<&Arc<BeaconState<P>>> {
        self.preprocessed_states.before_or_at_slot(block_root, slot)
    }

    pub fn insert_preprocessed_state(&mut self, block_root: H256, state: Arc<BeaconState<P>>) {
        self.preprocessed_states.insert(block_root, state);
    }

    #[must_use]
    pub fn is_forward_synced(&self) -> bool {
        self.head().slot() + self.store_config.max_empty_slots >= self.slot()
            && self.finished_initial_forward_sync
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

    pub fn invalidate_block_and_descendant_payload_statuses(
        &mut self,
        block_hash: ExecutionBlockHash,
    ) -> PayloadAction {
        if self.set_block_payload_status(block_hash, PayloadStatus::Invalid) {
            self.set_block_descendant_payload_statuses(block_hash, PayloadStatus::Invalid);
            self.update_head_segment_id();

            return PayloadAction::Accept;
        }

        PayloadAction::DelayUntilBlock(block_hash)
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

    pub fn indices_of_missing_blobs(&self, block: &Arc<SignedBeaconBlock<P>>) -> Vec<BlobIndex> {
        let block = block.message();

        let Some(body) = block.body().post_deneb() else {
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
        block: &Arc<SignedBeaconBlock<P>>,
    ) -> Vec<ColumnIndex> {
        let block = block.message();

        let Some(body) = block.body().post_deneb() else {
            return vec![];
        };

        if self.custody_columns.is_empty() || body.blob_kzg_commitments().is_empty() {
            return vec![];
        }

        let block_root = block.hash_tree_root();

        // get custody column count, or custody columns with column index
        // then, replace the const number of columns with custody columns
        // since we don't need to do peer sampling to maintained all of the columns
        self.custody_columns
            .clone()
            .into_iter()
            .filter(|index| {
                !self
                    .accepted_data_column_sidecars
                    .get(&(block.slot(), block.proposer_index(), *index))
                    .is_some_and(|kzg_commitments| {
                        kzg_commitments.get(&block_root) == Some(body.blob_kzg_commitments())
                    })
            })
            .collect()
    }

    pub fn store_custody_columns(
        &mut self,
        custody_columns: HashSet<ColumnIndex>
    ) {
        self.custody_columns = custody_columns;
    }

    pub fn has_custody_columns_stored(&self) -> bool {
        !self.custody_columns.is_empty()
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

    pub fn has_unpersisted_data_column_sidecars(&self) -> bool {
        self.data_column_cache.has_unpersisted_data_column_sidecars()
    }

    pub fn mark_persisted_data_columns(&mut self, persisted_data_column_ids: Vec<DataColumnIdentifier>) {
        self.data_column_cache.mark_persisted_data_columns(persisted_data_column_ids);
    }

    pub fn unpersisted_data_column_sidecars(&self) -> impl Iterator<Item = DataColumnSidecarWithId<P>> + '_ {
        self.data_column_cache.unpersisted_data_column_sidecars()
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(&type_name, "blob_store", self.blob_cache.size());
        metrics.set_collection_length(&type_name, "data_column_store", self.data_column_cache.size());
        metrics.set_collection_length(&type_name, "finalized", self.finalized().len());
        metrics.set_collection_length(&type_name, "unfinalized", self.unfinalized().len());

        metrics.set_collection_length(
            &type_name,
            "unfinalized_segment_blocks",
            self.unfinalized
                .values()
                .map(|segment| segment.len().get())
                .sum(),
        );

        metrics.set_collection_length(
            &type_name,
            "finalized_indices",
            self.finalized_indices.len(),
        );

        metrics.set_collection_length(
            &type_name,
            "unfinalized_locations",
            self.unfinalized_locations.len(),
        );

        metrics.set_collection_length(
            &type_name,
            "justified_active_balances",
            self.justified_active_balances.len(),
        );

        metrics.set_collection_length(&type_name, "latest_messages", self.latest_messages.len());

        metrics.set_collection_length(
            &type_name,
            "checkpoint_states",
            self.checkpoint_states.len(),
        );

        metrics.set_collection_length(
            &type_name,
            "current_slot_attestations",
            self.current_slot_attestations.len(),
        );

        metrics.set_collection_length(
            &type_name,
            "preprocessed_states",
            self.preprocessed_states.len(),
        );
    }
}
