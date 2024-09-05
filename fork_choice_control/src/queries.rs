use core::{fmt::Debug, ops::Range};
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use arc_swap::Guard;
use eth2_libp2p::GossipId;
use execution_engine::ExecutionEngine;
use fork_choice_store::{
    AggregateAndProofOrigin, AttestationItem, ChainLink, Segment, StateCacheProcessor, Store,
};
use helper_functions::misc;
use itertools::Itertools as _;
use serde::Serialize;
use std_ext::ArcExt;
use thiserror::Error;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    deneb::containers::{BlobIdentifier, BlobSidecar},
    nonstandard::{PayloadStatus, Phase, WithStatus},
    phase0::{
        containers::{Checkpoint, SignedAggregateAndProof},
        primitives::{Epoch, ExecutionBlockHash, Gwei, Slot, UnixSeconds, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    controller::Controller,
    messages::AttestationVerifierMessage,
    misc::{VerifyAggregateAndProofResult, VerifyAttestationResult},
    storage::Storage,
    unbounded_sink::UnboundedSink,
    wait::Wait,
};

#[cfg(test)]
use ::{clock::Tick, types::phase0::consts::GENESIS_SLOT};

// TODO(Grandine Team): There is currently no way to persist payload statuses.
//                      We previously treated blocks loaded from the database as optimistic.
//                      Doing so is safe but produces misleading API responses for finalized blocks.
//                      We now store only valid blocks in the database.

// Some of the methods defined here may take a while to execute.
// Do not call them directly in `async` tasks. Use something like `tokio::task::spawn_blocking`.
impl<P, E, A, W> Controller<P, E, A, W>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    A: UnboundedSink<AttestationVerifierMessage<P, W>>,
    W: Wait,
{
    #[must_use]
    pub fn slot(&self) -> Slot {
        self.store_snapshot().slot()
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.store_snapshot().phase()
    }

    #[must_use]
    pub fn justified_checkpoint(&self) -> Checkpoint {
        self.store_snapshot().justified_checkpoint()
    }

    #[must_use]
    pub fn finalized_epoch(&self) -> Epoch {
        self.store_snapshot().finalized_epoch()
    }

    #[must_use]
    pub fn finalized_root(&self) -> H256 {
        self.store_snapshot().finalized_root()
    }

    #[must_use]
    pub fn genesis_time(&self) -> UnixSeconds {
        let store = self.store_snapshot();
        store.last_finalized().state(&store).genesis_time()
    }

    #[must_use]
    pub fn anchor_block(&self) -> Arc<SignedBeaconBlock<P>> {
        self.store_snapshot().anchor().block.clone_arc()
    }

    /// Returns the post-state of the justified block.
    ///
    /// The returned state may be older than the target state of the justified checkpoint.
    /// It's not clear which of them `justified` refers to in the [Eth Beacon Node API].
    ///
    /// [Eth Beacon Node API]: https://ethereum.github.io/beacon-APIs/
    pub fn justified_state(&self) -> Result<WithStatus<Arc<BeaconState<P>>>> {
        let store = self.store_snapshot();

        // `rustfmt` formats the method chain below in a surprising and counterproductive way.
        // <https://github.com/rust-lang/rustfmt/issues/2961> describes a similar problem.
        // <https://github.com/rust-lang/rustfmt/issues/3514> proposes adding an option.
        // <https://github.com/rust-lang/rustfmt/pull/4886> implements the option.
        #[rustfmt::skip]
        let chain_link = store
            .justified_chain_link()
            .ok_or_else(|| Error::JustifiedBlockPruned {
                justified_checkpoint: store.justified_checkpoint(),
                finalized_checkpoint: store.finalized_checkpoint(),
            })?;

        Ok(WithStatus {
            value: chain_link.state(&store),
            optimistic: chain_link.is_optimistic(),
            finalized: store.is_slot_finalized(chain_link.slot()),
        })
    }

    #[must_use]
    pub fn last_finalized_block_root(&self) -> WithStatus<H256> {
        let store = self.store_snapshot();
        let chain_link = store.last_finalized();

        WithStatus {
            value: chain_link.block_root,
            optimistic: chain_link.is_optimistic(),
            finalized: true,
        }
    }

    #[must_use]
    pub fn last_finalized_block(&self) -> WithStatus<Arc<SignedBeaconBlock<P>>> {
        let store = self.store_snapshot();
        let chain_link = store.last_finalized();

        WithStatus {
            value: chain_link.block.clone_arc(),
            optimistic: chain_link.is_optimistic(),
            finalized: true,
        }
    }

    /// Returns the post-state of the finalized block.
    ///
    /// The returned state may be older than the target state of the finalized checkpoint.
    /// It's not clear which of them `finalized` refers to in the [Eth Beacon Node API].
    ///
    /// [Eth Beacon Node API]: https://ethereum.github.io/beacon-APIs/
    #[must_use]
    pub fn last_finalized_state(&self) -> WithStatus<Arc<BeaconState<P>>> {
        let store = self.store_snapshot();
        let chain_link = store.last_finalized();

        WithStatus {
            value: chain_link.state(&store),
            optimistic: chain_link.is_optimistic(),
            finalized: true,
        }
    }

    // TODO(Grandine Team): This will incorrectly return `None` for archived slots.
    #[must_use]
    pub fn finalized_block_root_before_or_at(&self, slot: Slot) -> Option<H256> {
        self.store_snapshot()
            .finalized_before_or_at(slot)
            .map(|chain_link| chain_link.block_root)
    }

    pub fn checkpoint_state(&self, checkpoint: Checkpoint) -> Result<Option<Arc<BeaconState<P>>>> {
        self.snapshot().checkpoint_state(checkpoint)
    }

    // The [Eth Beacon Node API specification] does not say if `GET /eth/v2/debug/beacon/heads`
    // should return non-viable forks. We return all of them.
    //
    // [Eth Beacon Node API specification]: https://ethereum.github.io/beacon-APIs/
    #[must_use]
    pub fn fork_tips(&self) -> Vec<ForkTip> {
        let store = self.store_snapshot();

        if store.unfinalized().is_empty() {
            return vec![(store.head(), store.head().is_optimistic()).into()];
        }

        store
            .unfinalized()
            .values()
            .filter_map(Segment::last_non_invalid_block)
            .map(|unfinalized_block| {
                (
                    &unfinalized_block.chain_link,
                    unfinalized_block.is_optimistic(),
                )
            })
            .map_into()
            .collect_vec()
    }

    #[must_use]
    pub fn fork_choice_context(&self) -> ForkChoiceContext {
        let store = self.store_snapshot();

        let fork_choice_nodes = store
            .unfinalized()
            .values()
            .flatten()
            .map(|unfinalized_block| {
                let chain_link = &unfinalized_block.chain_link;

                ForkChoiceNode {
                    slot: chain_link.slot(),
                    block_root: chain_link.block_root,
                    parent_root: chain_link.block.message().parent_root(),
                    justified_epoch: chain_link.current_justified_checkpoint.epoch,
                    finalized_epoch: chain_link.finalized_checkpoint.epoch,
                    validity: chain_link.payload_status,
                    weight: unfinalized_block.attesting_balance,
                    execution_block_hash: chain_link.execution_block_hash().unwrap_or_default(),
                }
            })
            .collect();

        ForkChoiceContext {
            justified_checkpoint: store.justified_checkpoint(),
            finalized_checkpoint: store.finalized_checkpoint(),
            fork_choice_nodes,
        }
    }

    #[must_use]
    pub fn head(&self) -> WithStatus<ChainLink<P>> {
        let store = self.store_snapshot();
        let head = store.head();

        WithStatus {
            value: head.clone(),
            optimistic: head.is_optimistic(),
            finalized: store.is_slot_finalized(head.slot()),
        }
    }

    #[must_use]
    pub fn head_slot(&self) -> Slot {
        self.store_snapshot().head().slot()
    }

    #[must_use]
    pub fn head_block_root(&self) -> WithStatus<H256> {
        let store = self.store_snapshot();
        let head = store.head();

        WithStatus {
            value: head.block_root,
            optimistic: head.is_optimistic(),
            finalized: store.is_slot_finalized(head.slot()),
        }
    }

    #[must_use]
    pub fn head_block(&self) -> WithStatus<Arc<SignedBeaconBlock<P>>> {
        let store = self.store_snapshot();
        let head = store.head();

        WithStatus {
            value: head.block.clone_arc(),
            optimistic: head.is_optimistic(),
            finalized: store.is_slot_finalized(head.slot()),
        }
    }

    #[must_use]
    pub fn head_state(&self) -> WithStatus<Arc<BeaconState<P>>> {
        let store = self.store_snapshot();
        let head = store.head();

        WithStatus {
            value: head.state(&store),
            optimistic: head.is_optimistic(),
            finalized: store.is_slot_finalized(head.slot()),
        }
    }

    #[must_use]
    pub fn is_forward_synced(&self) -> bool {
        self.store_snapshot().is_forward_synced()
    }

    #[must_use]
    pub fn state_by_chain_link(&self, chain_link: &ChainLink<P>) -> Arc<BeaconState<P>> {
        chain_link.state(&self.store_snapshot())
    }

    pub fn state_at_slot(&self, slot: Slot) -> Result<Option<WithStatus<Arc<BeaconState<P>>>>> {
        self.snapshot().state_at_slot(slot)
    }

    pub fn state_before_or_at_slot(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Option<Arc<BeaconState<P>>> {
        self.store_snapshot()
            .state_before_or_at_slot(block_root, slot)
    }

    // TODO(Grandine Team): This will perform linear search on states still stored in memory.
    //                      It will also only search the canonical chain.
    //                      `Store` used to have an index mapping state roots to block roots.
    //                      Consider bringing that back.
    pub fn state_by_state_root(
        &self,
        state_root: H256,
    ) -> Result<Option<WithStatus<Arc<BeaconState<P>>>>> {
        let store = self.store_snapshot();

        if let Some(with_status) = store.state_by_state_root(state_root) {
            return Ok(Some(with_status));
        }

        if let Some(state) = self.storage().stored_state_by_state_root(state_root)? {
            let finalized = store.is_slot_finalized(state.slot());
            return Ok(Some(WithStatus::valid(state, finalized)));
        }

        Ok(None)
    }

    pub fn exibits_equivocation(&self, block: &Arc<SignedBeaconBlock<P>>) -> bool {
        let block_slot = block.message().slot();
        let store = self.store_snapshot();

        if store.is_slot_finalized(block_slot) {
            return false;
        }

        let block_proposer_index = block.message().proposer_index();
        let block_root = block.message().hash_tree_root();

        store.exibits_equivocation_on_blobs(block_slot, block_proposer_index, block_root)
            || store.exibits_equivocation_on_blocks(block_slot, block_proposer_index, block_root)
    }

    pub fn check_block_root(&self, block_root: H256) -> Result<Option<WithStatus<H256>>> {
        let store = self.store_snapshot();

        if let Some(chain_link) = store.chain_link(block_root) {
            return Ok(Some(WithStatus {
                value: block_root,
                optimistic: chain_link.is_optimistic(),
                finalized: store.is_slot_finalized(chain_link.slot()),
            }));
        }

        if self.storage().contains_finalized_block(block_root)? {
            return Ok(Some(WithStatus::valid_and_finalized(block_root)));
        }

        if self.storage().contains_unfinalized_block(block_root)? {
            return Ok(Some(WithStatus::valid_and_unfinalized(block_root)));
        }

        Ok(None)
    }

    pub fn block_by_root(
        &self,
        block_root: H256,
    ) -> Result<Option<WithStatus<Arc<SignedBeaconBlock<P>>>>> {
        if let Some(with_status) = self.store_snapshot().block(block_root) {
            return Ok(Some(with_status.cloned()));
        }

        if let Some(block) = self.storage().finalized_block_by_root(block_root)? {
            return Ok(Some(WithStatus::valid_and_finalized(block)));
        }

        if let Some(block) = self.storage().unfinalized_block_by_root(block_root)? {
            return Ok(Some(WithStatus::valid_and_unfinalized(block)));
        }

        Ok(None)
    }

    pub fn block_by_slot(&self, slot: Slot) -> Result<Option<WithStatus<BlockWithRoot<P>>>> {
        let store = self.store_snapshot();

        if let Some(chain_link) = store.chain_link_before_or_at(slot) {
            if chain_link.slot() == slot {
                let block = chain_link.block.clone_arc();
                let root = chain_link.block_root;

                return Ok(Some(WithStatus {
                    value: BlockWithRoot { block, root },
                    optimistic: chain_link.is_optimistic(),
                    finalized: store.is_slot_finalized(chain_link.slot()),
                }));
            }
        }

        if let Some((block, root)) = self.storage().finalized_block_by_slot(slot)? {
            let block_with_root = BlockWithRoot { block, root };
            return Ok(Some(WithStatus::valid_and_finalized(block_with_root)));
        }

        Ok(None)
    }

    pub fn block_root_by_slot(&self, slot: Slot) -> Result<Option<H256>> {
        self.storage()
            .block_root_by_slot_with_store(self.store_snapshot().as_ref(), slot)
    }

    pub fn blocks_by_range(&self, range: Range<Slot>) -> Result<Vec<BlockWithRoot<P>>> {
        self.snapshot().blocks_by_range(range)
    }

    pub fn blob_sidecars_by_ids(
        &self,
        blob_ids: impl IntoIterator<Item = BlobIdentifier> + Send,
    ) -> Result<Vec<Arc<BlobSidecar<P>>>> {
        let snapshot = self.snapshot();
        let storage = self.storage();

        let blob_sidecars = blob_ids
            .into_iter()
            .map(
                |blob_id| match snapshot.cached_blob_sidecar_by_id(blob_id) {
                    Some(blob_sidecar) => Ok(Some(blob_sidecar)),
                    None => storage.blob_sidecar_by_id(blob_id),
                },
            )
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect_vec();

        Ok(blob_sidecars)
    }

    pub fn blob_sidecars_by_range(&self, range: Range<Slot>) -> Result<Vec<Arc<BlobSidecar<P>>>> {
        let canonical_chain_blocks = self.blocks_by_range(range)?;

        let blob_ids =
            canonical_chain_blocks
                .into_iter()
                .flat_map(|BlockWithRoot { block, root }| {
                    let block_kzg_commitment_indices = block
                        .message()
                        .body()
                        .post_deneb()
                        .map(|body| {
                            (0..)
                                .zip(body.blob_kzg_commitments())
                                .map(|(index, _)| index)
                                .collect_vec()
                        })
                        .unwrap_or_default();

                    block_kzg_commitment_indices
                        .into_iter()
                        .map(move |index| BlobIdentifier {
                            block_root: root,
                            index,
                        })
                });

        self.blob_sidecars_by_ids(blob_ids)
    }

    pub fn blocks_by_root(
        &self,
        block_roots: impl IntoIterator<Item = H256> + Send,
    ) -> Result<Vec<WithStatus<Arc<SignedBeaconBlock<P>>>>> {
        block_roots
            .into_iter()
            .map(|root| self.block_by_root(root))
            .filter_map(Result::transpose)
            .collect()
    }

    pub fn preprocessed_state_at_current_slot(&self) -> Result<Arc<BeaconState<P>>> {
        let store = self.store_snapshot();
        let head = store.head();

        self.state_cache()
            .state_at_slot(&store, head.block_root, store.slot())
    }

    pub fn preprocessed_state_at_next_slot(&self) -> Result<Arc<BeaconState<P>>> {
        let store = self.store_snapshot();
        let head = store.head();

        self.state_cache()
            .state_at_slot(&store, head.block_root, store.slot() + 1)
    }

    // The `block_root` and `state` parameters are needed
    // to avoid a race condition in `Validator::slot_head`.
    pub fn preprocessed_state_post_block(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        let store = self.store_snapshot();

        if let Some(state) = self
            .state_cache()
            .try_state_at_slot(&store, block_root, slot)?
        {
            return Ok(state);
        }

        if let Some(state) = self.storage().state_post_block(block_root)? {
            return self
                .state_cache()
                .process_slots(&store, state, block_root, slot);
        }

        bail!(Error::StateNotFound { block_root })
    }

    pub fn preprocessed_state_at_epoch(
        &self,
        requested_epoch: Epoch,
    ) -> Result<WithStatus<Arc<BeaconState<P>>>> {
        let store = self.store_snapshot();
        let store_epoch = store.current_epoch();

        ensure!(
            requested_epoch <= store_epoch + P::MIN_SEED_LOOKAHEAD,
            Error::EpochTooFarInTheFuture {
                requested_epoch,
                store_epoch,
            },
        );

        let head = store.head();
        let requested_slot = misc::compute_start_slot_at_epoch::<P>(requested_epoch);

        let state = self
            .state_cache()
            .state_at_slot(&store, head.block_root, requested_slot)
            .unwrap_or_else(|_| head.state(&store));

        Ok(WithStatus {
            value: state,
            optimistic: head.is_optimistic(),
            finalized: store.is_slot_finalized(head.slot()),
        })
    }

    pub fn dependent_root(&self, state: &BeaconState<P>, epoch: Epoch) -> Result<H256> {
        self.storage()
            .dependent_root(self.store_snapshot().as_ref(), state, epoch)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot<P> {
        Snapshot {
            store_snapshot: self.store_snapshot(),
            state_cache: self.state_cache().clone_arc(),
            storage: self.storage(),
        }
    }
}

#[cfg(test)]
impl<P, E, A, W> Controller<P, E, A, W>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    A: UnboundedSink<AttestationVerifierMessage<P, W>>,
    W: Wait,
{
    #[must_use]
    pub fn tick(&self) -> Tick {
        self.store_snapshot().tick()
    }

    #[must_use]
    pub fn justified_epoch(&self) -> Epoch {
        self.store_snapshot().justified_epoch()
    }

    #[must_use]
    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.store_snapshot().finalized_checkpoint()
    }

    #[must_use]
    pub fn proposer_boost_root(&self) -> H256 {
        self.store_snapshot().proposer_boost_root()
    }

    #[must_use]
    pub fn genesis(&self) -> Option<ChainLink<P>> {
        self.store_snapshot()
            .finalized_before_or_at(GENESIS_SLOT)
            .cloned()
    }

    #[must_use]
    pub fn anchor_state(&self) -> Arc<BeaconState<P>> {
        let store = self.store_snapshot();
        store.anchor().state(&store)
    }

    #[must_use]
    pub fn attesting_balance(&self) -> Option<Gwei> {
        self.store_snapshot()
            .unfinalized_head()
            .map(|unfinalized_block| unfinalized_block.attesting_balance)
    }

    #[must_use]
    pub fn fork_count_viable(&self) -> usize {
        let store = self.store_snapshot();

        store
            .unfinalized()
            .values()
            .filter(|segment| store.is_segment_viable(segment))
            .count()
            .max(1)
    }

    #[must_use]
    pub fn fork_count_total(&self) -> usize {
        self.store_snapshot().unfinalized().len().max(1)
    }

    pub fn finalized_block_count(&self) -> Result<usize> {
        let in_database = self.storage().finalized_block_count()?;
        let overlap = usize::from(in_database > 0);
        let in_memory = self.store_snapshot().finalized().len();
        Ok(in_database - overlap + in_memory)
    }

    #[must_use]
    pub fn unfinalized_block_count_in_fork(&self) -> usize {
        self.store_snapshot()
            .canonical_chain_segments()
            .map(|(segment, position)| {
                let len = segment.len_up_to(position).get();
                let non_invalid_len = segment.non_invalid_len();
                len.min(non_invalid_len)
            })
            .sum()
    }

    #[must_use]
    pub fn unfinalized_block_count_total(&self) -> usize {
        self.store_snapshot()
            .unfinalized()
            .values()
            .map(Segment::non_invalid_len)
            .sum()
    }

    #[must_use]
    pub fn payload_status(&self, block_root: H256) -> Option<PayloadStatus> {
        self.store_snapshot()
            .chain_link(block_root)
            .map(|chain_link| chain_link.payload_status)
    }
}

#[derive(Serialize)]
pub struct ForkTip {
    root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    execution_optimistic: bool,
}

#[derive(Serialize)]
pub struct ForkChoiceContext {
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    fork_choice_nodes: Vec<ForkChoiceNode>,
}

#[derive(Serialize)]
struct ForkChoiceNode {
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    block_root: H256,
    parent_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    justified_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    finalized_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    weight: Gwei,
    validity: PayloadStatus,
    // `execution_block_hash` is not nullable in the [Eth Beacon Node API].
    // [`protovis`] expects `execution_block_hash` to be 0x00…00 for pre-Merge blocks.
    //
    // [Eth Beacon Node API]: https://ethereum.github.io/beacon-APIs/#/Debug/getDebugForkChoice
    // [`protovis`]:          https://github.com/tbenr/protovis
    execution_block_hash: ExecutionBlockHash,
}

impl<P: Preset> From<(&ChainLink<P>, bool)> for ForkTip {
    fn from(chain_link_with_status: (&ChainLink<P>, bool)) -> Self {
        let (chain_link, execution_optimistic) = chain_link_with_status;

        Self {
            root: chain_link.block_root,
            slot: chain_link.slot(),
            execution_optimistic,
        }
    }
}

pub struct BlockWithRoot<P: Preset> {
    pub block: Arc<SignedBeaconBlock<P>>,
    pub root: H256,
}

/// A snapshot of the fork choice store that can also look up values in the database.
///
/// Note that the contents of the database are not snapshotted.
/// They may change between calls to methods of a single [`Snapshot`].
/// If database-level snapshotting turns out to be necessary we may have to go back to RocksDB. See:
/// - [`rocksdb::SnapshotWithThreadMode`][docs].
/// - [RocksDB wiki page about snapshots][wiki].
///
/// [docs]: https://docs.rs/rocksdb/0.18.0/rocksdb/struct.SnapshotWithThreadMode.html
/// [wiki]: https://github.com/facebook/rocksdb/wiki/Snapshot/e09da0053d05583919354cfaf834b8e8edd97be8
#[allow(clippy::struct_field_names)]
pub struct Snapshot<'storage, P: Preset> {
    // Use a `Guard` instead of an owned snapshot unlike in tasks based on the intuition that
    // `Snapshot`s will be less common than tasks.
    store_snapshot: Guard<Arc<Store<P>>>,
    state_cache: Arc<StateCacheProcessor<P>>,
    storage: &'storage Storage<P>,
}

impl<P: Preset> Snapshot<'_, P> {
    // TODO(Grandine Team): `Snapshot::nonempty_slots` only uses data stored in memory.
    //                      It's enough for builder circuit breaking, but that may change if we
    //                      redesign the fork choice store to keep less data in memory.
    // `nonempty_slots` has to be defined on `Snapshot` because the returned iterator borrows from
    // `Store`. Trying to define it on `Controller` causes `E0515`.
    pub fn nonempty_slots(&self, block_root: H256) -> impl Iterator<Item = Slot> + '_ {
        self.store_snapshot
            .chain_ending_with(block_root)
            .map(ChainLink::slot)
    }

    pub fn checkpoint_state(&self, checkpoint: Checkpoint) -> Result<Option<Arc<BeaconState<P>>>> {
        if let Some(state) = self.store_snapshot.checkpoint_state(checkpoint) {
            return Ok(Some(state.clone_arc()));
        }

        let Checkpoint { epoch, root } = checkpoint;
        let slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        self.state_cache
            .try_state_at_slot(&self.store_snapshot, root, slot)
    }

    #[must_use]
    pub fn finalized_epoch(&self) -> Epoch {
        self.store_snapshot.finalized_epoch()
    }

    #[must_use]
    pub fn finalized_root(&self) -> H256 {
        self.store_snapshot.finalized_root()
    }

    #[must_use]
    pub fn head_slot(&self) -> Slot {
        self.store_snapshot.head().slot()
    }

    #[must_use]
    pub fn head_state(&self) -> Arc<BeaconState<P>> {
        self.store_snapshot.head().state(&self.store_snapshot)
    }

    /// Returns [`true`] if the fork choice store is optimistic as defined in the
    /// [Optimistic Sync specification].
    ///
    /// > Let a node be an *optimistic node* if its fork choice is in one of the following states:
    /// > 1. `is_optimistic(opt_store, head) is True`
    /// > 2. Blocks from every viable (with respect to FFG) branch have transitioned from
    /// >    `NOT_VALIDATED` to `INVALIDATED` leaving the block tree without viable branches
    ///
    /// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/sync/optimistic.md#helpers
    #[must_use]
    pub fn is_optimistic(&self) -> bool {
        let store = &self.store_snapshot;
        store.head().is_optimistic() || self.store_snapshot.is_poisoned()
    }

    #[must_use]
    pub fn is_forward_synced(&self) -> bool {
        self.store_snapshot.is_forward_synced()
    }

    #[must_use]
    pub fn safe_execution_payload_hash(&self) -> ExecutionBlockHash {
        self.store_snapshot.safe_execution_payload_hash()
    }

    #[must_use]
    pub fn finalized_execution_payload_hash(&self) -> ExecutionBlockHash {
        self.store_snapshot.finalized_execution_payload_hash()
    }

    #[must_use]
    pub fn prevalidate_verifier_aggregate_and_proof(
        &self,
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        origin: AggregateAndProofOrigin<GossipId>,
    ) -> VerifyAggregateAndProofResult<P> {
        let result =
            self.store_snapshot
                .validate_aggregate_and_proof(aggregate_and_proof, &origin, true);

        VerifyAggregateAndProofResult { result, origin }
    }

    pub fn prevalidate_verifier_attestation(
        &self,
        attestation: AttestationItem<P, GossipId>,
    ) -> VerifyAttestationResult<P> {
        self.store_snapshot.validate_attestation(attestation, true)
    }

    // TODO(Grandine Team): If `slot` is empty, this advances the next most recent state to `slot`,
    //                      even if `slot` is later than the current fork choice slot. This was
    //                      originally done to match the behavior of Lighthouse API endpoints that the
    //                      Beacon Chain Explorer used at the time. Consider adding a check to prevent
    //                      this method for computing states for future slots. The Eth Beacon Node API
    //                      specification does not say if this is allowed.
    pub fn state_at_slot(&self, slot: Slot) -> Result<Option<WithStatus<Arc<BeaconState<P>>>>> {
        let store = &self.store_snapshot;

        if let Some(chain_link) = store.chain_link_before_or_at(slot) {
            let state = self
                .state_cache
                .state_at_slot(store, chain_link.block_root, slot)?;

            return Ok(Some(WithStatus {
                value: state,
                optimistic: chain_link.is_optimistic(),
                finalized: store.is_slot_finalized(slot),
            }));
        }

        if let Some(state) = self.storage.stored_state(slot)? {
            let finalized = store.is_slot_finalized(state.slot());
            return Ok(Some(WithStatus::valid(state, finalized)));
        };

        Ok(None)
    }

    // This returns blocks ordered oldest to newest, as mandated for `BeaconBlocksByRange`.
    pub fn blocks_by_range(&self, range: Range<Slot>) -> Result<Vec<BlockWithRoot<P>>> {
        let Range { start, end } = range;

        let mut blocks = self
            .store_snapshot
            .canonical_chain()
            .skip_while(|chain_link| end <= chain_link.slot())
            .take_while(|chain_link| start <= chain_link.slot())
            .map(|chain_link| BlockWithRoot {
                block: chain_link.block.clone_arc(),
                root: chain_link.block_root,
            })
            .collect_vec();

        // Load missing blocks from storage.
        let storage_end_slot = match blocks.last() {
            Some(block_with_root) => block_with_root.block.message().slot(),
            None => end,
        };

        itertools::process_results(
            (start..storage_end_slot)
                .rev()
                .map(|slot| self.storage.finalized_block_by_slot(slot))
                .filter_map(Result::transpose),
            |options| {
                blocks.extend(options.map(|(block, root)| BlockWithRoot { block, root }));
            },
        )?;

        blocks.reverse();

        Ok(blocks)
    }

    #[must_use]
    pub(crate) fn cached_blob_sidecar_by_id(
        &self,
        blob_id: BlobIdentifier,
    ) -> Option<Arc<BlobSidecar<P>>> {
        self.store_snapshot.cached_blob_sidecar_by_id(blob_id)
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error(
        "epoch is too far in the future \
         (requested_epoch: {requested_epoch}, store_epoch: {store_epoch})"
    )]
    EpochTooFarInTheFuture {
        requested_epoch: Epoch,
        store_epoch: Epoch,
    },
    #[error(
        "justified block is pruned \
         (justified_checkpoint: {justified_checkpoint:?}, \
          finalized_checkpoint: {finalized_checkpoint:?})"
    )]
    JustifiedBlockPruned {
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
    },
    #[error("state not found in fork choice store: {block_root:?}")]
    StateNotFound { block_root: H256 },
}
