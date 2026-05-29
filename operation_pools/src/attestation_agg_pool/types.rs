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
    preset::Preset,
};

// Use `Mutex` instead of `RwLock` to avoid race conditions in `InsertAttestationTask`.
// Don't let this comment fool you into thinking the locking is well thought out.
// There may be other bugs.
pub type AggregateMap<P> = BTreeMap<AttestationKey, Arc<Mutex<Vec<Aggregate<P>>>>>;

pub type AttestationMap<P> = BTreeMap<AttestationKey, Arc<RwLock<AttestationSet<P>>>>;

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
    pub const fn key(&self) -> AttestationKey {
        AttestationKey {
            data: self.data,
            committee_index: self.committee_index,
        }
    }

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
