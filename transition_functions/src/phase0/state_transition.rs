use core::ops::Not as _;

use anyhow::{Error as AnyhowError, Result};
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
    config::Config,
    phase0::{beacon_state::BeaconState, containers::SignedBeaconBlock},
    preset::Preset,
};

use super::{block_processing, slot_processing};
use crate::unphased::{ProcessSlots, StateRootPolicy};

pub fn state_transition<P: Preset, V: Verifier + Send>(
    config: &Config,
    state: &mut Hc<BeaconState<P>>,
    signed_block: &SignedBeaconBlock<P>,
    process_slots: ProcessSlots,
    state_root_policy: StateRootPolicy,
    verifier: V,
    slot_report: impl SlotReport + Send,
) -> Result<()> {
    let block = &signed_block.message;

    // > Process slots (including those with no blocks) since block
    if process_slots.should_process(state, block) {
        slot_processing::process_slots(config, state, block.slot)?;
    }

    // Running `verifier.finish()` and `state.hash_tree_root()` in parallel speeds up Goerli block
    // processing by 4-5 blocks/s (which is around 5%) at the time of writing. Running the entirety
    // of `verify_signatures` in parallel with all of block processing yields another small speedup
    // (3-6% with Medalla Phase 0 blocks, 1-2% with mainnet and Goerli Phase 0 blocks).
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
            NullVerifier,
            slot_report,
        )?;

        // > Verify state root
        state_root_policy.verify(state, block)?;

        Ok(())
    };

    if let Some(verify_signatures) = verify_signatures {
        let (signature_result, block_result) = rayon::join(verify_signatures, process_block);
        signature_result.and(block_result)
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
    if verifier.has_option(VerifierOption::SkipBlockBaseSignatures) {
        return Ok(());
    }

    verifier.reserve(count_required_signatures(block));

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

    verifier.finish()
}

fn count_required_signatures(block: &SignedBeaconBlock<impl Preset>) -> usize {
    1 + block_processing::count_required_signatures(&block.message)
}
