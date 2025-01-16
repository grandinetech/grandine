use anyhow::{ensure, Error as AnyhowError, Result};
use eth1_api::{ApiController, RealController};
use fork_choice_control::Wait;
use helper_functions::{accessors, misc};
use ssz::{BitList, BitVector, ReadError};
use thiserror::Error;
use typenum::Unsigned as _;
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

pub fn convert_attestation_for_pool<P: Preset>(
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
    };

    Ok(attestation)
}

pub fn convert_to_electra_attestation<P: Preset>(
    attestation: Phase0Attestation<P>,
) -> Result<ElectraAttestation<P>> {
    let Phase0Attestation {
        aggregation_bits,
        data,
        signature,
    } = attestation;

    let aggregation_bits: Vec<u8> = aggregation_bits.into();
    let mut committee_bits = BitVector::default();
    committee_bits.set(data.index.try_into()?, true);

    Ok(ElectraAttestation {
        aggregation_bits: aggregation_bits
            .try_into()
            .map_err(Error::InvalidAggregationBits)?,
        data: AttestationData { index: 0, ..data },
        committee_bits,
        signature,
    })
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

pub fn try_convert_to_attestation<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    single_attestation: SingleAttestation,
) -> Result<Attestation<P>> {
    let SingleAttestation {
        committee_index,
        attester_index,
        data,
        signature,
    } = single_attestation;

    ensure!(
        committee_index < P::MaxCommitteesPerSlot::U64,
        AnyhowError::msg(format!("invalid committee_index: {committee_index}"))
    );

    let mut committee_bits = BitVector::default();
    let index = committee_index.try_into()?;
    committee_bits.set(index, true);

    let state = controller
        .state_at_slot(data.slot)?
        .ok_or_else(|| AnyhowError::msg(format!("state not available at slot: {:?}", data.slot)))?
        .value;

    let committee = accessors::beacon_committee(&state, data.slot, committee_index)?;

    let mut aggregation_bits = BitList::with_length(committee.len());

    let position = committee
        .into_iter()
        .position(|index| index == attester_index)
        .ok_or_else(|| AnyhowError::msg(format!("{attester_index} not in committee")))?;

    aggregation_bits.set(position, true);

    Ok(Attestation::Electra(ElectraAttestation {
        aggregation_bits,
        data,
        signature,
        committee_bits,
    }))
}
