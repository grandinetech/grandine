use anyhow::{Error as AnyhowError, Result};
use eth1_api::{ApiController, RealController};
use fork_choice_control::Wait;
use helper_functions::{accessors, misc};
use ssz::ReadError;
use thiserror::Error;
use types::{
    combined::Attestation,
    electra::containers::{Attestation as ElectraAttestation, SingleAttestation},
    phase0::containers::{Attestation as Phase0Attestation, AttestationData},
    preset::Preset,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid committee index for conversion")]
    InvalidCommitteeIndex,
    #[error("invalid aggregation bits for conversion")]
    InvalidAggregationBits(#[source] ReadError),
}

pub fn convert_attestation_for_pool<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    attestation: Attestation<P>,
) -> Result<Phase0Attestation<P>> {
    let attestation = match attestation {
        Attestation::Phase0(attestation) => attestation,
        Attestation::Electra(attestation) => {
            let ElectraAttestation {
                aggregation_bits,
                data,
                committee_bits,
                signature,
            } = attestation;

            let aggregation_bits: Vec<u8> = aggregation_bits.into();

            let index = misc::get_committee_indices::<P>(committee_bits)
                .next()
                .ok_or(Error::InvalidCommitteeIndex)?;

            Phase0Attestation {
                aggregation_bits: aggregation_bits
                    .try_into()
                    .map_err(Error::InvalidAggregationBits)?,
                data: AttestationData { index, ..data },
                signature,
            }
        }
        Attestation::Single(attestation) => {
            let slot = attestation.data.slot;
            let state = controller
                .state_at_slot(slot)?
                .ok_or_else(|| AnyhowError::msg(format!("state not available at slot: {slot:?}")))?
                .value;
            let committee = accessors::beacon_committee(&state, slot, attestation.committee_index)?;

            attestation.try_into_phase0_attestation(committee)?
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
pub fn try_convert_to_single_attestation<P: Preset>(
    controller: &RealController<P>,
    attestation: &ElectraAttestation<P>,
) -> Result<SingleAttestation> {
    let ElectraAttestation {
        aggregation_bits,
        data,
        signature,
        committee_bits,
    } = attestation;

    let committee_index = misc::get_committee_indices::<P>(*committee_bits)
        .next()
        .unwrap_or_default();

    let state = controller
        .state_at_slot(data.slot)?
        .ok_or_else(|| AnyhowError::msg(format!("state not available at slot: {:?}", data.slot)))?
        .value;

    let committee = accessors::beacon_committee(&state, data.slot, committee_index)?;

    let attester_index = aggregation_bits
        .iter()
        .zip(committee)
        .find_map(|(participated, validator_index)| (*participated).then_some(validator_index))
        .ok_or_else(|| AnyhowError::msg("attester_index not available"))?;

    Ok(SingleAttestation {
        committee_index,
        attester_index,
        data: *data,
        signature: *signature,
    })
}
