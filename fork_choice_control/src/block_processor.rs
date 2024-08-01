use std::sync::Arc;

use anyhow::Result;
use derive_more::Constructor;
use execution_engine::ExecutionEngine;
use fork_choice_store::{
    validate_merge_block, BlockAction, PartialBlockAction, StateCacheProcessor, Store,
};
use helper_functions::{
    predicates,
    slot_report::{NullSlotReport, RealSlotReport, SlotReport, SyncAggregateRewards},
    verifier::Verifier,
};
use ssz::SszHash;
use state_cache::StateWithRewards;
use std_ext::ArcExt as _;
use transition_functions::{
    combined,
    unphased::{ProcessSlots, StateRootPolicy},
};
use types::{
    combined::{BeaconBlock, BeaconState, BlindedBeaconBlock, SignedBeaconBlock},
    config::Config as ChainConfig,
    nonstandard::{BlockRewards, Phase, SlashingKind},
    phase0::primitives::H256,
    preset::Preset,
    traits::{BeaconBlock as _, BeaconState as _, SignedBeaconBlock as _},
};

#[derive(Constructor)]
pub struct BlockProcessor<P: Preset> {
    chain_config: Arc<ChainConfig>,
    state_cache: Arc<StateCacheProcessor<P>>,
}

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
                    state.make_mut(),
                    block,
                    &mut slot_report,
                    skip_randao_verification,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report);

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
                    state.make_mut(),
                    block,
                    &mut slot_report,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report);

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
                    state.make_mut(),
                    block,
                    &mut slot_report,
                    skip_randao_verification,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report);

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
                    state.make_mut(),
                    block,
                    &mut slot_report,
                )?;

                let block_rewards = calculate_block_rewards(&slot_report);

                Ok((state, Some(block_rewards)))
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn perform_state_transition(
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

    pub fn validate_block_for_gossip(
        &self,
        store: &Store<P>,
        block: &Arc<SignedBeaconBlock<P>>,
    ) -> Result<Option<BlockAction<P>>> {
        store.validate_block_for_gossip(block, |parent| {
            let block_slot = block.message().slot();

            // > Make a copy of the state to avoid mutability issues
            let mut state = self
                .state_cache
                .before_or_at_slot(store, parent.block_root, block_slot)
                .unwrap_or_else(|| parent.state(store));

            // > Process slots (including those with no blocks) since block
            if state.slot() < block_slot {
                combined::process_slots(&self.chain_config, state.make_mut(), block_slot)?;
            }

            combined::process_block_for_gossip(&self.chain_config, &state, block)?;

            Ok(None)
        })
    }

    pub fn validate_block<E: ExecutionEngine<P> + Send>(
        &self,
        store: &Store<P>,
        block: &Arc<SignedBeaconBlock<P>>,
        state_root_policy: StateRootPolicy,
        execution_engine: E,
        verifier: impl Verifier + Send,
    ) -> Result<BlockAction<P>> {
        store.validate_block_with_custom_state_transition(block, |block_root, parent| {
            // > Make a copy of the state to avoid mutability issues
            let state = self
                .state_cache
                .before_or_at_slot(store, parent.block_root, block.message().slot())
                .unwrap_or_else(|| parent.state(store));

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
                    match validate_merge_block(&self.chain_config, block, body, &execution_engine)?
                    {
                        PartialBlockAction::Accept => {}
                        PartialBlockAction::Ignore => {
                            return Ok((state, Some(BlockAction::Ignore(false))))
                        }
                    }
                }
            }

            let state = self.perform_state_transition(
                state,
                block,
                block_root,
                ProcessSlots::IfNeeded,
                state_root_policy,
                execution_engine,
                verifier,
                NullSlotReport,
            )?;

            Ok((state, None))
        })
    }
}

fn calculate_block_rewards(slot_report: &RealSlotReport) -> BlockRewards {
    let attestations = slot_report.attestation_rewards.iter().sum();

    let sync_aggregate = slot_report
        .sync_aggregate_rewards
        .map(SyncAggregateRewards::total)
        .unwrap_or_default();

    let proposer_slashings = slot_report.slashing_rewards[SlashingKind::Proposer]
        .iter()
        .sum();

    let attester_slashings = slot_report.slashing_rewards[SlashingKind::Attester]
        .iter()
        .sum();

    BlockRewards {
        total: attestations + sync_aggregate + proposer_slashings + attester_slashings,
        attestations,
        sync_aggregate,
        proposer_slashings,
        attester_slashings,
    }
}
