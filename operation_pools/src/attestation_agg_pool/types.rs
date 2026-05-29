use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use anyhow::Result;
use bls::AggregateSignature;
use ssz::{BitList, BitVector};
use tokio::sync::{Mutex, RwLock};
use types::{
    electra::containers::Attestation as ElectraAttestation,
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

/// Key for the pool's per-committee aggregate and singular-attestation maps.
///
/// `committee_index` is the pool's **organizational dimension**, and is deliberately kept
/// separate from `data`. It is NOT part of the signed message: `data.index` carries
/// fork-specific *signed* meaning (phase0 = committee index; Gloas/EIP-7732 = payload-presence
/// vote), and must never be conflated with the committee index the pool groups aggregates by.
///
/// Storing the committee index here lets `data` stay byte-for-byte as it was signed (pristine).
/// That is what stops Gloas attestations that differ only in their payload vote (`data.index`
/// 0 vs 1) from colliding into a single aggregate bucket and having their signatures merged
/// into an invalid aggregate. Do not fold `committee_index` back into `data.index` for storage.
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

    pub fn try_into_electra_attestation(self) -> Result<ElectraAttestation<P>> {
        let Self {
            aggregation_bits,
            data,
            committee_index,
            signature,
        } = self;

        let aggregation_bits: Vec<u8> = aggregation_bits.into();
        let mut committee_bits = BitVector::default();
        committee_bits.set(committee_index.try_into()?, true);

        Ok(ElectraAttestation {
            aggregation_bits: aggregation_bits.try_into()?,
            data,
            signature,
            committee_bits,
        })
    }
}

#[derive(Default, Clone)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod tests {
    use types::{
        phase0::{
            containers::{AttestationData, Checkpoint},
            primitives::H256,
        },
    };

    use super::AttestationKey;

    fn sample_data(index: u64) -> AttestationData {
        AttestationData {
            slot: 42,
            index,
            beacon_block_root: H256::repeat_byte(0xaa),
            source: Checkpoint {
                epoch: 3,
                root: H256::repeat_byte(0x11),
            },
            target: Checkpoint {
                epoch: 4,
                root: H256::repeat_byte(0x22),
            },
        }
    }

    #[test]
    fn attestation_key_separates_gloas_payload_votes() {
        let committee_index = 2;

        let vote_empty = sample_data(0);
        let vote_full = sample_data(1);

        let key_empty = AttestationKey {
            data: vote_empty,
            committee_index,
        };
        let key_full = AttestationKey {
            data: vote_full,
            committee_index,
        };

        assert_eq!(key_empty.committee_index, key_full.committee_index);
        assert_ne!(
            key_empty, key_full,
            "payload votes must not collide into one bucket"
        );
    }
}
