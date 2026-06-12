use std::sync::Arc;

use anyhow::{Result, anyhow};
use derive_more::Constructor;
use execution_engine::ExecutionEngine;
use fork_choice_store::{
    BlockAction, BlockItem, DataAvailabilityPolicy, PartialBlockAction, StateCacheProcessor, Store,
    validate_merge_block,
};
use helper_functions::{
    predicates,
    slot_report::{NullSlotReport, RealSlotReport, SlotReport, SyncAggregateRewards},
    verifier::{Verifier, VerifierOption},
};
use logging::debug_with_peers;
use once_cell::unsync::OnceCell;
use pubkey_cache::PubkeyCache;
use ssz::SszHash;
use state_cache::StateWithRewards;
use std_ext::ArcExt as _;
use tracing::instrument;
use transition_functions::{
    combined,
    unphased::{ProcessSlots, StateRootPolicy},
};
use types::{
    combined::{BeaconBlock, BeaconState, BlindedBeaconBlock, SignedBeaconBlock},
    config::Config as ChainConfig,
    nonstandard::{BlockRewards, Phase, SlashingKind},
    phase0::primitives::{Gwei, H256, Slot},
    preset::Preset,
    traits::{BeaconBlock as _, SignedBeaconBlock as _},
};

use crate::Storage;

#[derive(Constructor)]
pub struct BlockProcessor<P: Preset> {
    chain_config: Arc<ChainConfig>,
    pubkey_cache: Arc<PubkeyCache>,
    state_cache: Arc<StateCacheProcessor<P>>,
}

// NOTE: These functions are all potentially blocking due to state cache access.
// They should be called within a blocking task only.
impl<P: Preset> BlockProcessor<P> {
    pub fn process_untrusted_block_with_report(
        &self,
        mut state: Arc<BeaconState<P>>,
        block: &BeaconBlock<P>,
        skip_randao_verification: bool,
    ) -> Result<StateWithRewards<P>> {
        self.state_cache
            .get_or_insert_with(block.hash_tree_root(), block.slot(), false, || {
                let mut slot_report = RealSlotReport::default();

                combined::process_untrusted_block(
                    &self.chain_config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    block,
                    &mut slot_report,
                    skip_randao_verification,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report)?;

                Ok((state, Some(block_rewards)))
            })
    }

    pub fn process_trusted_block_with_report(
        &self,
        mut state: Arc<BeaconState<P>>,
        block: &BeaconBlock<P>,
    ) -> Result<StateWithRewards<P>> {
        self.state_cache
            .get_or_insert_with(block.hash_tree_root(), block.slot(), false, || {
                let mut slot_report = RealSlotReport::default();

                combined::process_trusted_block(
                    &self.chain_config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    block,
                    &mut slot_report,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report)?;

                Ok((state, Some(block_rewards)))
            })
    }

    pub fn process_untrusted_blinded_block_with_report(
        &self,
        mut state: Arc<BeaconState<P>>,
        block: &BlindedBeaconBlock<P>,
        skip_randao_verification: bool,
    ) -> Result<StateWithRewards<P>> {
        self.state_cache
            .get_or_insert_with(block.hash_tree_root(), block.slot(), false, || {
                let mut slot_report = RealSlotReport::default();

                combined::process_untrusted_blinded_block(
                    &self.chain_config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    block,
                    &mut slot_report,
                    skip_randao_verification,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report)?;

                Ok((state, Some(block_rewards)))
            })
    }

    pub fn process_trusted_blinded_block_with_report(
        &self,
        mut state: Arc<BeaconState<P>>,
        block: &BlindedBeaconBlock<P>,
    ) -> Result<StateWithRewards<P>> {
        self.state_cache
            .get_or_insert_with(block.hash_tree_root(), block.slot(), false, || {
                let mut slot_report = RealSlotReport::default();

                combined::process_trusted_blinded_block(
                    &self.chain_config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    block,
                    &mut slot_report,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report)?;

                Ok((state, Some(block_rewards)))
            })
    }

    #[expect(clippy::too_many_arguments)]
    #[instrument(level = "debug", skip_all)]
    fn perform_state_transition(
        &self,
        mut state: Arc<BeaconState<P>>,
        block: &SignedBeaconBlock<P>,
        block_root: H256,
        process_slots: ProcessSlots,
        state_root_policy: StateRootPolicy,
        execution_engine: impl ExecutionEngine<P> + Send,
        verifier: impl Verifier + Send,
        slot_report: impl SlotReport + Send,
    ) -> Result<Arc<BeaconState<P>>> {
        self.state_cache
            .get_or_insert_with(block_root, block.message().slot(), true, || {
                combined::custom_state_transition(
                    &self.chain_config,
                    &self.pubkey_cache,
                    state.make_mut(),
                    block,
                    process_slots,
                    state_root_policy,
                    execution_engine,
                    verifier,
                    slot_report,
                )?;

                Ok((state, None))
            })
            .map(|(state, _)| state)
    }

    fn fetch_state_for_block(
        &self,
        store: &Store<P, Storage<P>>,
        parent_root: H256,
        block_slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        self.state_cache
            .try_state_at_slot_for_block_sync(&self.pubkey_cache, store, parent_root, block_slot)
            .and_then(|opt| opt.ok_or_else(|| anyhow!("state not found")))
            .inspect_err(|error| {
                debug_with_peers!(
                    "error while fetching state for block_slot: \
                    {block_slot}, parent_root: {parent_root:?}: {error:?}"
                )
            })
    }

    pub fn validate_block_for_gossip(
        &self,
        store: &Store<P, Storage<P>>,
        block: &Arc<SignedBeaconBlock<P>>,
    ) -> Result<Option<BlockAction<P>>> {
        let block_slot = block.message().slot();
        let parent_root = block.message().parent_root();
        let cached = OnceCell::new();

        let state_fn = || {
            cached
                .get_or_try_init(|| self.fetch_state_for_block(store, parent_root, block_slot))
                .ok()
                .cloned()
        };

        store.validate_block_for_gossip(
            BlockItem::unverified(block.clone_arc()),
            state_fn,
            |parent| {
                // > Make a copy of the state to avoid mutability issues
                let state = state_fn().unwrap_or_else(|| parent.state(store));

                combined::process_block_for_gossip(
                    &self.chain_config,
                    &self.pubkey_cache,
                    &state,
                    block,
                )?;

                Ok(None)
            },
        )
    }

    #[instrument(ret(level = "debug"), level = "debug", skip_all)]
    pub fn validate_block<E: ExecutionEngine<P> + Send>(
        &self,
        store: &Store<P, Storage<P>>,
        block: BlockItem<P>,
        state_root_policy: StateRootPolicy,
        data_availability_policy: DataAvailabilityPolicy,
        execution_engine: E,
        mut verifier: impl Verifier + Send,
    ) -> Result<BlockAction<P>> {
        let parent_root = block.item.message().parent_root();
        let block_slot = block.item.message().slot();
        let cached = OnceCell::new();

        let state_fn = || {
            cached
                .get_or_try_init(|| self.fetch_state_for_block(store, parent_root, block_slot))
                .ok()
                .cloned()
        };

        store.validate_block_with_custom_state_transition(
            block,
            data_availability_policy,
            state_fn,
            |block, parent| {
                // > Make a copy of the state to avoid mutability issues
                let state = state_fn().unwrap_or_else(|| parent.state(store));

                // This validation was removed from Capella in `consensus-specs` v1.4.0-alpha.0.
                // See <https://github.com/ethereum/consensus-specs/pull/3232>.
                // It is unclear when modifications to fork choice logic should come into effect.
                // We check the phase of the block rather than the current slot.
                if block.item.phase() < Phase::Capella {
                    // > [New in Bellatrix]
                    //
                    // The Fork Choice specification does this after the state transition.
                    // We don't because that would require keeping around a clone of the pre-state.
                    if let Some(body) = block
                        .item
                        .message()
                        .body()
                        .with_execution_payload()
                        .filter(|body| predicates::is_merge_transition_block(&state, *body))
                    {
                        match validate_merge_block(
                            &self.chain_config,
                            &block.item,
                            body,
                            &execution_engine,
                        )? {
                            PartialBlockAction::Accept => {}
                            PartialBlockAction::Ignore => {
                                return Ok((state, Some(BlockAction::Ignore(false))));
                            }
                        }
                    }
                }

                if block.base_signature_status.is_verified() {
                    verifier.set_option(VerifierOption::SkipBlockRootSignature);
                }

                let state = self.perform_state_transition(
                    state,
                    &block.item,
                    block.item.message().hash_tree_root(),
                    ProcessSlots::IfNeeded,
                    state_root_policy,
                    execution_engine,
                    verifier,
                    NullSlotReport,
                )?;

                Ok((state, None))
            },
        )
    }
}

fn calculate_block_rewards(slot_report: &RealSlotReport) -> Result<BlockRewards> {
    let attestations: Gwei = slot_report.attestation_rewards.iter().sum();

    let sync_aggregate = slot_report
        .sync_aggregate_rewards
        .map(SyncAggregateRewards::total)
        .transpose()?
        .unwrap_or_default();

    let proposer_slashings = slot_report.slashing_rewards[SlashingKind::Proposer]
        .iter()
        .sum();

    let attester_slashings = slot_report.slashing_rewards[SlashingKind::Attester]
        .iter()
        .sum();

    Ok(BlockRewards {
        total: attestations
            .saturating_add(sync_aggregate)
            .saturating_add(proposer_slashings)
            .saturating_add(attester_slashings),
        attestations,
        sync_aggregate,
        proposer_slashings,
        attester_slashings,
    })
}
