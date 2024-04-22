use anyhow::Result;
use helper_functions::misc;
use ssz::{BitVector, ReadError};
use thiserror::Error;
use types::{
    combined::Attestation,
    electra::containers::Attestation as ElectraAttestation,
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
