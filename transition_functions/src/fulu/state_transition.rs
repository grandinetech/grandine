use core::ops::Not as _;

use anyhow::Result;
use execution_engine::ExecutionEngine;
use helper_functions::{
    accessors, electra,
    error::SignatureKind,
    misc, par_utils, predicates,
    signing::{RandaoEpoch, SignForAllForksWithGenesis as _, SignForSingleFork as _},
    slot_report::SlotReport,
    verifier::{NullVerifier, Triple, Verifier, VerifierOption},
};
use pubkey_cache::PubkeyCache;
#[cfg(not(target_os = "zkvm"))]
use rayon::iter::ParallelIterator as _;
use ssz::Hc;
#[cfg(target_os = "zkvm")]
use ssz::SszHash;
use std_ext::ArcExt as _;
use types::{
    config::Config,
    fulu::{beacon_state::BeaconState, containers::SignedBeaconBlock},
    preset::Preset,
};

use super::{block_processing, slot_processing};
use crate::{
    altair,
    unphased::{ProcessSlots, StateRootPolicy},
};

#[expect(clippy::too_many_arguments)]
#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn state_transition<P: Preset, V: Verifier + Send>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut Hc<BeaconState<P>>,
    signed_block: &SignedBeaconBlock<P>,
    process_slots: ProcessSlots,
    state_root_policy: StateRootPolicy,
    execution_engine: impl ExecutionEngine<P> + Send,
    verifier: V,
    slot_report: impl SlotReport + Send,
) -> Result<()> {
    let block = &signed_block.message;

    // > Process slots (including those with no blocks) since block
    if process_slots.should_process(state, block) {
        slot_processing::process_slots(config, pubkey_cache, state, block.slot)?;
    }

    let verify_signatures = V::IS_NULL.not().then(|| {
        let state = state.clone();

        // > Verify signature
        move || verify_signatures(config, pubkey_cache, &state, signed_block, verifier)
    });

    let process_block = || {
        // > Process block
        block_processing::custom_process_block(
            config,
            pubkey_cache,
            state,
            &signed_block.message,
            execution_engine,
            NullVerifier,
            slot_report,
        )?;

        #[cfg(target_os = "zkvm")]
        bls::set_rand_seed(state.hash_tree_root().0);

        // > Verify state root
        state_root_policy.verify(state, block)?;

        Ok(())
    };

    if let Some(verify_signatures) = verify_signatures {
        let (block_result, signature_result) = par_utils::join(process_block, verify_signatures);
        signature_result.and(block_result)
    } else {
        process_block()
    }
}

#[expect(clippy::too_many_lines)]
#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn verify_signatures<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    verifier.reserve(count_required_signatures(block));

    if !verifier.has_option(VerifierOption::SkipBlockBaseSignatures) {
        // Block signature
        //
        let pubkey = pubkey_cache
            .get_or_insert(*accessors::public_key(state, block.message.proposer_index)?)?;

        verifier.verify_singular(
            block.message.signing_root(config, state),
            block.signature,
            pubkey.clone_arc(),
            SignatureKind::Block,
        )?;

        // RANDAO reveal

        verifier.verify_singular(
            RandaoEpoch::from(misc::compute_epoch_at_slot::<P>(block.message.slot))
                .signing_root(config, state),
            block.message.body.randao_reveal,
            pubkey,
            SignatureKind::Randao,
        )?;

        // Proposer slashings

        for proposer_slashing in &block.message.body.proposer_slashings {
            for signed_header in [
                proposer_slashing.signed_header_1,
                proposer_slashing.signed_header_2,
            ] {
                verifier.verify_singular(
                    signed_header.message.signing_root(config, state),
                    signed_header.signature,
                    pubkey_cache.get_or_insert(*accessors::public_key(
                        state,
                        signed_header.message.proposer_index,
                    )?)?,
                    SignatureKind::Block,
                )?;
            }
        }

        // Attester slashings

        for attester_slashing in &block.message.body.attester_slashings {
            for attestation in [
                &attester_slashing.attestation_1,
                &attester_slashing.attestation_2,
            ] {
                itertools::process_results(
                    attestation
                        .attesting_indices
                        .iter()
                        .copied()
                        .map(|validator_index| {
                            pubkey_cache
                                .get_or_insert(*accessors::public_key(state, validator_index)?)
                        }),
                    |public_keys| {
                        verifier.verify_aggregate(
                            attestation.data.signing_root(config, state),
                            attestation.signature,
                            public_keys,
                            SignatureKind::Attestation,
                        )
                    },
                )??
            }
        }

        // Attestations

        let attestations = &block.message.body.attestations;

        accessors::initialize_shuffled_indices(state, attestations.iter())?;

        let triples = helper_functions::par_iter!(attestations)
            .map(|attestation| {
                let indexed_attestation = electra::get_indexed_attestation(state, attestation)?;

                let mut triple = Triple::default();

                predicates::validate_constructed_indexed_attestation(
                    config,
                    pubkey_cache,
                    state,
                    &indexed_attestation,
                    &mut triple,
                )?;

                Ok(triple)
            })
            .collect::<Result<Vec<_>>>()?;

        verifier.extend(triples, SignatureKind::Attestation)?;

        // Voluntary exits

        for voluntary_exit in &block.message.body.voluntary_exits {
            verifier.verify_singular(
                voluntary_exit.message.signing_root(config, state),
                voluntary_exit.signature,
                pubkey_cache.get_or_insert(*accessors::public_key(
                    state,
                    voluntary_exit.message.validator_index,
                )?)?,
                SignatureKind::VoluntaryExit,
            )?;
        }
    }

    if !verifier.has_option(VerifierOption::SkipBlockSyncAggregateSignature) {
        // Sync aggregate

        altair::verify_sync_aggregate_signature(
            config,
            pubkey_cache,
            state,
            block.message.body.sync_aggregate,
            &mut verifier,
        )?;
    }

    // BLS to execution changes

    for bls_to_execution_change in &block.message.body.bls_to_execution_changes {
        verifier.verify_singular(
            bls_to_execution_change.message.signing_root(config, state),
            bls_to_execution_change.signature,
            pubkey_cache.get_or_insert(bls_to_execution_change.message.from_bls_pubkey)?,
            SignatureKind::BlsToExecutionChange,
        )?;
    }

    verifier.finish()
}

fn count_required_signatures(block: &SignedBeaconBlock<impl Preset>) -> usize {
    1 + block_processing::count_required_signatures(&block.message)
}
