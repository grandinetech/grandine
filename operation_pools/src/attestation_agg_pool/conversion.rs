use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result, bail};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::{accessors, misc};
use logging::debug_with_peers;
use typenum::Unsigned as _;
use types::{
    combined::{Attestation, BeaconState},
    electra::{
        containers::{Attestation as ElectraAttestation, SingleAttestation},
        error::AttestationConversionError,
    },
    phase0::containers::{Attestation as Phase0Attestation, Checkpoint},
    preset::Preset,
};

use crate::attestation_agg_pool::types::PoolAttestation;

pub fn convert_attestation_for_pool<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    attestation: Arc<Attestation<P>>,
) -> Result<PoolAttestation<P>> {
    if attestation
        .data()
        .slot
        .saturating_add(P::SlotsPerEpoch::U64)
        < controller.slot()
    {
        bail!(AttestationConversionError::Irrelevant);
    }

    let attestation = match Arc::unwrap_or_clone(attestation) {
        Attestation::Phase0(attestation) => {
            let Phase0Attestation {
                aggregation_bits,
                data,
                signature,
            } = attestation;

            PoolAttestation {
                aggregation_bits,
                data,
                committee_index: data.index,
                signature,
            }
        }
        Attestation::Electra(attestation) => {
            let ElectraAttestation {
                aggregation_bits,
                data,
                committee_bits,
                signature,
            } = attestation;

            let aggregation_bits: Vec<u8> = aggregation_bits.into();

            let committee_index = misc::get_committee_indices::<P>(committee_bits)
                .next()
                .ok_or(AttestationConversionError::InvalidCommitteeIndex)?;

            // Keep `data` pristine (the signed Electra `data.index` is 0). The committee index is
            // in its own field, never written into `data.index`.
            PoolAttestation {
                aggregation_bits: aggregation_bits
                    .try_into()
                    .map_err(AttestationConversionError::InvalidAggregationBits)?,
                data,
                committee_index,
                signature,
            }
        }
        Attestation::Single(attestation) => {
            let committee_index = attestation.committee_index;
            let data = attestation.data;
            let slot = attestation.data.slot;
            let state = current_state(controller, attestation.data.target);
            let committee = accessors::beacon_committee(&state, slot, committee_index)?;

            let phase0_attestation = attestation.try_into_phase0_attestation::<P>(committee)?;
            let Phase0Attestation {
                aggregation_bits,
                signature,
                ..
            } = phase0_attestation;

            PoolAttestation {
                aggregation_bits,
                data,
                committee_index,
                signature,
            }
        }
    };

    Ok(attestation)
}

pub fn convert_to_electra_attestation<P: Preset>(
    attestation: Phase0Attestation<P>,
) -> Result<ElectraAttestation<P>> {
    attestation.try_into()
}

// TODO(feature/electra): properly refactor attestations
pub fn try_convert_to_single_attestation<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    attestation: ElectraAttestation<P>,
) -> Result<SingleAttestation> {
    let ElectraAttestation {
        aggregation_bits,
        data,
        signature,
        committee_bits,
    } = attestation;

    let committee_index = misc::get_committee_indices::<P>(committee_bits)
        .next()
        .unwrap_or_default();

    let state = current_state(controller, data.target);
    let committee = accessors::beacon_committee(&state, data.slot, committee_index)?;

    let attester_index = aggregation_bits
        .iter()
        .zip(committee)
        .find_map(|(participated, validator_index)| (*participated).then_some(validator_index))
        .ok_or_else(|| AnyhowError::msg("attester_index not available"))?;

    Ok(SingleAttestation {
        committee_index,
        attester_index,
        data,
        signature,
    })
}

fn current_state<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    target: Checkpoint,
) -> Arc<BeaconState<P>> {
    if !controller.is_forward_synced() {
        return controller.head_state().value;
    }

    if let Some(state) = controller.state_before_or_at_slot(
        target.root,
        misc::compute_start_slot_at_epoch::<P>(target.epoch),
    ) && accessors::get_current_epoch(&state) == target.epoch
    {
        return state;
    }

    match controller.preprocessed_state_at_current_slot_blocking() {
        Ok(state) => state,
        Err(error) => {
            debug_with_peers!(
                "failed to get state at current slot for attestation conversion: {error}. \
                 Using head state instead",
            );

            controller.head_state().value
        }
    }
}

#[cfg(test)]
mod tests {
    // These tests exercise the single-attestation inflow conversion directly (no controller / no
    // `eth2-cache` data). They are deliberately written against `try_into_phase0_attestation`,
    // which exists on both the pre-fix and post-fix code with the same signature, so they double as
    // portable regression tests: on the pre-fix code (which overwrote `data.index` with the
    // committee index) `single_conversion_keeps_gloas_votes_distinct` fails.
    use bls::SignatureBytes;
    use types::{
        cache::IndexSlice,
        electra::containers::SingleAttestation,
        phase0::{
            containers::{AttestationData, Checkpoint},
            primitives::H256,
        },
        preset::Minimal,
    };

    // A Gloas single attestation: `data.index` is the payload-presence vote (0 or 1), and the
    // committee index is carried in its own field.
    fn gloas_single(committee_index: u64, payload_vote: u64) -> SingleAttestation {
        SingleAttestation {
            committee_index,
            attester_index: 11,
            data: AttestationData {
                slot: 7,
                index: payload_vote,
                beacon_block_root: H256::repeat_byte(0xff),
                source: Checkpoint {
                    epoch: 1,
                    root: H256::repeat_byte(1),
                },
                target: Checkpoint {
                    epoch: 2,
                    root: H256::repeat_byte(2),
                },
            },
            signature: SignatureBytes::default(),
        }
    }

    // Test 4 — the single-attestation inflow keeps `data` pristine: the committee index is tracked
    // separately, never written into `data.index`.
    #[test]
    fn single_conversion_keeps_data_index_pristine() -> anyhow::Result<()> {
        let committee: Vec<u64> = vec![10, 11, 12, 13];
        let single = gloas_single(2, 0);

        let phase0 = single.try_into_phase0_attestation::<Minimal>(IndexSlice::U64(&committee))?;

        assert_eq!(
            phase0.data.index, single.data.index,
            "data.index must stay pristine, not be overwritten with committee_index"
        );

        Ok(())
    }

    // Test 3 (portable regression) — two single attestations that differ ONLY in the payload vote
    // must convert to distinct `data`, so the pool cannot merge them. The pre-fix code overwrote
    // `data.index` with the committee index, collapsing both onto the same `data` (the ★A bug):
    // this assertion fails there and passes here.
    #[test]
    fn single_conversion_keeps_gloas_votes_distinct() -> anyhow::Result<()> {
        let committee: Vec<u64> = vec![10, 11, 12, 13];

        let vote_empty = gloas_single(2, 0);
        let vote_full = gloas_single(2, 1);

        let a = vote_empty.try_into_phase0_attestation::<Minimal>(IndexSlice::U64(&committee))?;
        let b = vote_full.try_into_phase0_attestation::<Minimal>(IndexSlice::U64(&committee))?;

        assert_ne!(
            a.data, b.data,
            "payload votes must remain distinct after conversion"
        );

        Ok(())
    }
}
