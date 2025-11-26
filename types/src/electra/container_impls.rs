use anyhow::{ensure, Error as AnyhowError, Result};
use ssz::{BitList, BitVector, ContiguousList};
use typenum::Unsigned as _;

use crate::{
    cache::IndexSlice,
    deneb::{
        containers::{ExecutionPayload, ExecutionPayloadHeader},
        primitives::KzgCommitment,
    },
    electra::{
        containers::{
            Attestation, BeaconBlock, BeaconBlockBody, BlindedBeaconBlock, BlindedBeaconBlockBody,
            ExecutionRequests, IndexedAttestation, SingleAttestation,
        },
        error::AttestationConversionError,
    },
    phase0::{
        containers::{Attestation as Phase0Attestation, AttestationData},
        primitives::H256,
    },
    preset::Preset,
};

impl<P: Preset> BeaconBlock<P> {
    pub fn with_execution_payload_header_and_kzg_commitments(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
        kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
        execution_requests: Option<ExecutionRequests<P>>,
    ) -> BlindedBeaconBlock<P> {
        let Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = self;

        let BeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload: _,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests: beacon_block_execution_requests,
        } = body;

        BlindedBeaconBlock {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: BlindedBeaconBlockBody {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                execution_payload_header,
                bls_to_execution_changes,
                blob_kzg_commitments: kzg_commitments.unwrap_or(blob_kzg_commitments),
                execution_requests: execution_requests.unwrap_or(beacon_block_execution_requests),
            },
        }
    }
}

impl<P: Preset> BlindedBeaconBlock<P> {
    pub fn with_execution_payload(self, execution_payload: ExecutionPayload<P>) -> BeaconBlock<P> {
        let Self {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = self;

        let BlindedBeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload_header: _,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        } = body;

        let body = BeaconBlockBody {
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            execution_payload,
            bls_to_execution_changes,
            blob_kzg_commitments,
            execution_requests,
        };

        BeaconBlock {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        }
    }

    #[must_use]
    pub const fn with_state_root(mut self, state_root: H256) -> Self {
        self.state_root = state_root;
        self
    }
}

impl<P: Preset> TryFrom<Phase0Attestation<P>> for Attestation<P> {
    type Error = AnyhowError;

    fn try_from(phase0_attestation: Phase0Attestation<P>) -> Result<Self> {
        let Phase0Attestation {
            aggregation_bits,
            data,
            signature,
        } = phase0_attestation;

        let aggregation_bits: Vec<u8> = aggregation_bits.into();
        let mut committee_bits = BitVector::default();
        committee_bits.set(data.index.try_into()?, true);

        Ok(Self {
            aggregation_bits: aggregation_bits
                .try_into()
                .map_err(AttestationConversionError::InvalidAggregationBits)?,
            data: AttestationData { index: 0, ..data },
            committee_bits,
            signature,
        })
    }
}

impl<P: Preset> TryFrom<SingleAttestation> for IndexedAttestation<P> {
    type Error = AnyhowError;

    fn try_from(single_attestation: SingleAttestation) -> Result<Self> {
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

        Ok(Self {
            attesting_indices: ContiguousList::try_from([attester_index])?,
            data,
            signature,
        })
    }
}

impl SingleAttestation {
    pub fn try_into_phase0_attestation<P: Preset>(
        self,
        beacon_committee: IndexSlice,
    ) -> Result<Phase0Attestation<P>> {
        let Self {
            committee_index,
            attester_index,
            data,
            signature,
        } = self;

        let data = AttestationData {
            index: committee_index,
            ..data
        };

        ensure!(
            committee_index < P::MaxCommitteesPerSlot::U64,
            AnyhowError::msg(format!("invalid committee_index: {committee_index}"))
        );

        let mut aggregation_bits = BitList::with_length(beacon_committee.len());

        let position = beacon_committee
            .into_iter()
            .position(|index| index == attester_index)
            .ok_or_else(|| AttestationConversionError::AttesterNotInCommittee {
                attester_index,
                committee_index,
                attestation_data: data,
                committee: beacon_committee.into_iter().collect(),
            })?;

        aggregation_bits.set(position, true);

        Ok(Phase0Attestation {
            aggregation_bits,
            data,
            signature,
        })
    }
}
