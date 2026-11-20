use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use bls::AggregateSignature;
use ssz::BitList;
use tokio::sync::{Mutex, RwLock};
use types::{
    phase0::{
        containers::{Attestation, AttestationData},
        primitives::CommitteeIndex,
    },
    pq::primitives::AttestationProof,
    preset::Preset,
};

// Use `Mutex` instead of `RwLock` to avoid race conditions in `InsertAttestationTask`.
// Don't let this comment fool you into thinking the locking is well thought out.
// There may be other bugs.
pub type AggregateMap<P> = BTreeMap<AttestationKey, Arc<Mutex<Vec<Aggregate<P>>>>>;

pub type AttestationMap<P> = BTreeMap<AttestationKey, Arc<RwLock<AttestationSet<P>>>>;

pub type PqAggregateMap<P> = BTreeMap<AttestationKey, Vec<Arc<PqPoolAttestation<P>>>>;

// Use `BTreeSet` to make attestation packing deterministic for snapshot testing.
// This does not affect performance in our benchmarks.
pub type AttestationSet<P> = BTreeSet<Arc<PoolAttestation<P>>>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct AttestationKey {
    pub data: AttestationData,
    pub committee_index: CommitteeIndex,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PoolAttestation<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub committee_index: CommitteeIndex,
    pub signature: bls::AggregateSignatureBytes,
}

impl<P: Preset> PoolAttestation<P> {
    #[must_use]
    pub fn into_phase0_attestation(self) -> Attestation<P> {
        let Self {
            aggregation_bits,
            data,
            signature,
            ..
        } = self;

        Attestation {
            aggregation_bits,
            data,
            signature,
        }
    }
}

#[derive(Default, Clone)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}

/// A PQ aggregate of one committee with the proof of its attesters' signatures.
///
/// PQ aggregates cannot be merged with each other, so the pool keeps each one it receives.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqPoolAttestation<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub committee_index: CommitteeIndex,
    pub proof: AttestationProof<P>,
}

/// What attestation packing reads from an aggregate of one committee.
pub trait PackableAttestation<P: Preset> {
    fn data(&self) -> AttestationData;

    fn committee_index(&self) -> CommitteeIndex;

    fn aggregation_bits(&self) -> &BitList<P::MaxValidatorsPerCommittee>;

    fn key(&self) -> AttestationKey {
        AttestationKey {
            data: self.data(),
            committee_index: self.committee_index(),
        }
    }
}

impl<P: Preset> PackableAttestation<P> for PoolAttestation<P> {
    fn data(&self) -> AttestationData {
        self.data
    }

    fn committee_index(&self) -> CommitteeIndex {
        self.committee_index
    }

    fn aggregation_bits(&self) -> &BitList<P::MaxValidatorsPerCommittee> {
        &self.aggregation_bits
    }
}

impl<P: Preset> PackableAttestation<P> for PqPoolAttestation<P> {
    fn data(&self) -> AttestationData {
        self.data
    }

    fn committee_index(&self) -> CommitteeIndex {
        self.committee_index
    }

    fn aggregation_bits(&self) -> &BitList<P::MaxValidatorsPerCommittee> {
        &self.aggregation_bits
    }
}

impl<P: Preset, A: PackableAttestation<P>> PackableAttestation<P> for &A {
    fn data(&self) -> AttestationData {
        (*self).data()
    }

    fn committee_index(&self) -> CommitteeIndex {
        (*self).committee_index()
    }

    fn aggregation_bits(&self) -> &BitList<P::MaxValidatorsPerCommittee> {
        (*self).aggregation_bits()
    }
}
