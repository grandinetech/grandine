use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use bls::AggregateSignature;
use ssz::BitList;
use tokio::sync::{Mutex, RwLock};
use types::{
    phase0::containers::{Attestation, AttestationData},
    phase0::primitives::CommitteeIndex,
    preset::Preset,
};

// Use `Mutex` instead of `RwLock` to avoid race conditions in `InsertAttestationTask`.
// Don't let this comment fool you into thinking the locking is well thought out.
// There may be other bugs.
pub type AggregateMap<P> = HashMap<AttestationData, Arc<Mutex<Vec<Aggregate<P>>>>>;

pub type AttestationMap<P> = HashMap<AttestationData, Arc<RwLock<AttestationSet<P>>>>;

// Use `BTreeSet` to make attestation packing deterministic for snapshot testing.
// This does not affect performance in our benchmarks.
pub type AttestationSet<P> = BTreeSet<Arc<Attestation<P>>>;

#[derive(Clone, Copy, Debug, Default)]
pub struct AttestationPrePool {
    pub committee_index: CommitteeIndex,
    pub original_payload_index: u64,
}

// Packs committee_index (lower 32 bits) and payload_index (upper 32 bits) into a single u64.
// This encodes data.index for pool storage so that same-committee attestations with different
// payload votes (Gloas) get separate aggregate buckets. decode_committee_index extracts the
// lower half via bitmask, decode_payload_index extracts the upper half via right-shift.
pub fn encode_pool_index(committee_index: u64, payload_index: u64) -> u64 {
    committee_index | (payload_index << 32)
}

pub fn decode_committee_index(encoded: u64) -> u64 {
    encoded & 0xFFFF_FFFF
}

pub fn decode_payload_index(encoded: u64) -> u64 {
    encoded >> 32
}

#[derive(Default, Clone)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}
