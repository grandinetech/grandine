use core::ops::Not as _;

use anyhow::{anyhow, Error as AnyhowError, Result};
use execution_engine::ExecutionEngine;
use helper_functions::{
    accessors,
    error::SignatureKind,
    misc, phase0, predicates,
    signing::{RandaoEpoch, SignForSingleFork as _},
    slot_report::SlotReport,
    verifier::{NullVerifier, Triple, Verifier, VerifierOption},
};
use rayon::iter::{IntoParallelRefIterator as _, ParallelIterator as _};
use ssz::Hc;
use types::{
    bellatrix::{beacon_state::BeaconState, containers::SignedBeaconBlock},
    config::Config,
    preset::Preset,
};

use super::{block_processing, slot_processing};
use crate::{
    altair,
    unphased::{ProcessSlots, StateRootPolicy},
};

#[expect(clippy::too_many_arguments)]
pub fn state_transition<P: Preset, V: Verifier + Send>(
    config: &Config,
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
        slot_processing::process_slots(config, state, block.slot)?;
    }

    let verify_signatures = V::IS_NULL.not().then(|| {
        let state = state.clone();

        // > Verify signature
        move || verify_signatures(config, &state, signed_block, verifier)
    });

    let process_block = || {
        // > Process block
        block_processing::custom_process_block(
            config,
            state,
            &signed_block.message,
            execution_engine,
            NullVerifier,
            slot_report,
        )?;

        // > Verify state root
        state_root_policy.verify(state, block)?;

        Ok(())
    };

    if let Some(verify_signatures) = verify_signatures {
        std::thread::scope(|scope| {
            let verify_signatures = scope.spawn(verify_signatures);
            let process_block = scope.spawn(process_block);

            let signature_result = verify_signatures
                .join()
                .map_err(|_| anyhow!("failed to verify signatures"))
                .and_then(|result| result);

            let block_result = process_block
                .join()
                .map_err(|_| anyhow!("failed to process block"))
                .and_then(|result| result);

            signature_result.and(block_result)
        })
    } else {
        process_block()
    }
}

pub fn verify_signatures<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
    mut verifier: impl Verifier,
) -> Result<()> {
    verifier.reserve(count_required_signatures(block));

    if !verifier.has_option(VerifierOption::SkipBlockBaseSignatures) {
        // Block signature

        verifier.verify_singular(
            block.message.signing_root(config, state),
            block.signature,
            accessors::public_key(state, block.message.proposer_index)?,
            SignatureKind::Block,
        )?;

        // RANDAO reveal

        verifier.verify_singular(
            RandaoEpoch::from(misc::compute_epoch_at_slot::<P>(block.message.slot))
                .signing_root(config, state),
            block.message.body.randao_reveal,
            accessors::public_key(state, block.message.proposer_index)?,
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
                    accessors::public_key(state, signed_header.message.proposer_index)?,
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
                            accessors::public_key(state, validator_index)?
                                .decompress()
                                .map_err(AnyhowError::new)
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

        accessors::initialize_shuffled_indices(state, attestations)?;

        let triples = attestations
            .par_iter()
            .map(|attestation| {
                let indexed_attestation = phase0::get_indexed_attestation(state, attestation)?;

                let mut triple = Triple::default();

                predicates::validate_constructed_indexed_attestation(
                    config,
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
                accessors::public_key(state, voluntary_exit.message.validator_index)?,
                SignatureKind::VoluntaryExit,
            )?;
        }
    }

    if !verifier.has_option(VerifierOption::SkipBlockSyncAggregateSignature) {
        // Sync aggregate

        altair::verify_sync_aggregate_signature(
            config,
            state,
            block.message.body.sync_aggregate,
            &mut verifier,
        )?;
    }

    verifier.finish()
}

fn count_required_signatures(block: &SignedBeaconBlock<impl Preset>) -> usize {
    1 + altair::count_required_signatures(&block.message)
}
