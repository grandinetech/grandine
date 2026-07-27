use std::{
    collections::{BTreeSet, HashMap},
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
/// See TODO(grandinetech/grandine#780).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PoolKey {
    pub data: AttestationData,
    pub committee_index: CommitteeIndex,
}

impl PoolKey {
    /// Rebuild the pre-Electra "scratch representation" `AttestationData`, in which `data.index`
    /// holds the committee index instead of its signed meaning.
    ///
    /// TEMPORARY — TODO(grandinetech/grandine#780). This exists only so the current
    /// `AttestationPacker` (and the block-production / HTTP-API paths that read `data.index` as a
    /// committee index) keep working byte-for-byte while the pool's *storage* moves to pristine
    /// data. It MUST be deleted once the packer consumes pristine data directly (the greedy
    /// baseline PR).
    ///
    /// Do NOT use on the Gloas path: re-injecting the committee index overwrites the payload-presence
    /// vote that `data.index` carries under EIP-7732, producing an attestation that no longer matches
    /// what was signed. Pre-Electra this is a no-op (`committee_index == data.index` already); for
    /// Electra/Fulu it restores the committee index the packer expects.
    #[must_use]
    pub const fn rehydrate_phase0_scratch_repr(&self) -> AttestationData {
        AttestationData {
            index: self.committee_index,
            ..self.data
        }
    }

    /// Inverse of [`Self::rehydrate_phase0_scratch_repr`]: recover the storage key from a scratch
    /// representation supplied by a caller (validator duties, HTTP-API lookups) whose `data.index`
    /// holds the committee index.
    ///
    /// TEMPORARY — TODO(grandinetech/grandine#780), same lifetime as the rehydrate helper. For
    /// post-Electra the signed `data.index` is 0, so it is reset here to keep the stored `data`
    /// pristine; pre-Electra `data.index` is genuinely the committee index and is left untouched.
    #[must_use]
    pub const fn from_scratch_repr(scratch: AttestationData, is_post_electra: bool) -> Self {
        let committee_index = scratch.index;
        let data = if is_post_electra {
            AttestationData {
                index: 0,
                ..scratch
            }
        } else {
            scratch
        };

        Self {
            data,
            committee_index,
        }
    }
}

// Use `Mutex` instead of `RwLock` to avoid race conditions in `InsertAttestationTask`.
// Don't let this comment fool you into thinking the locking is well thought out.
// There may be other bugs.
pub type AggregateMap<P> = HashMap<PoolKey, Arc<Mutex<Vec<Aggregate<P>>>>>;

pub type AttestationMap<P> = HashMap<PoolKey, Arc<RwLock<AttestationSet<P>>>>;

// Use `BTreeSet` to make attestation packing deterministic for snapshot testing.
// This does not affect performance in our benchmarks.
pub type AttestationSet<P> = BTreeSet<Arc<Attestation<P>>>;

#[derive(Default, Clone)]
pub struct Aggregate<P: Preset> {
    pub aggregation_bits: BitList<P::MaxValidatorsPerCommittee>,
    pub signature: AggregateSignature,
}

#[cfg(test)]
mod tests {
    use helper_functions::misc;
    use ssz::{BitVector, SszHash as _};
    use types::{
        phase0::{
            containers::{AttestationData, Checkpoint},
            primitives::H256,
        },
        preset::Minimal,
    };

    use super::PoolKey;

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

    // Test 1 — pre-Electra byte-identical: for a phase0 attestation, emission
    // (`rehydrate ∘ from_scratch_repr`) reproduces the input exactly (structural + SSZ root).
    // This is the executable evidence for the "pre-Electra byte-identical" claim.
    #[test]
    fn phase0_scratch_roundtrip_is_byte_identical() {
        // Phase0: `data.index` genuinely is the committee index, so is_post_electra = false.
        let data = sample_data(3);

        let key = PoolKey::from_scratch_repr(data, false);

        // Committee comes from data.index; stored data stays pristine (== input for phase0).
        assert_eq!(key.committee_index, 3);
        assert_eq!(key.data, data);

        let emitted = key.rehydrate_phase0_scratch_repr();

        assert_eq!(emitted, data);
        assert_eq!(emitted.hash_tree_root(), data.hash_tree_root());
    }

    // The post-Electra scratch round-trip is also the identity: storage drops the committee index
    // out of `data` (keeping it pristine, index == 0), and emission re-injects it.
    #[test]
    fn electra_scratch_roundtrip_reconstructs_input() {
        // Caller-supplied scratch repr: `data.index` carries the committee index (7).
        let scratch = sample_data(7);

        let key = PoolKey::from_scratch_repr(scratch, true);

        assert_eq!(key.committee_index, 7);
        assert_eq!(
            key.data.index, 0,
            "post-Electra stored data.index must be pristine (0)"
        );

        assert_eq!(key.rehydrate_phase0_scratch_repr(), scratch);
    }

    // Test 2 — Electra inflow keeps data pristine and derives the committee from committee_bits.
    #[test]
    fn electra_inflow_keeps_data_pristine_and_extracts_committee() {
        // Model the pool's Electra inflow: committee from committee_bits, data untouched.
        let mut committee_bits = BitVector::default();
        committee_bits.set(2, true);

        let committee_index = misc::get_committee_indices::<Minimal>(committee_bits)
            .next()
            .expect("exactly one committee bit is set");

        // Incoming Electra data: the signed `data.index` is 0 (pristine).
        let data = sample_data(0);
        let key = PoolKey {
            data,
            committee_index,
        };

        assert_eq!(key.committee_index, 2);
        assert_eq!(
            key.data.index, 0,
            "pristine data.index must not be overwritten with the committee index"
        );
    }

    // Test 3 — Gloas payload-vote separation (★A): two attestations identical except for the
    // payload-presence vote in `data.index` (0 vs 1), for the SAME committee, must map to distinct
    // PoolKeys so their signatures are never aggregated into an invalid combined signature.
    #[test]
    fn poolkey_separates_gloas_payload_votes() {
        let committee_index = 2;

        let vote_empty = sample_data(0); // payload EMPTY
        let vote_full = sample_data(1); // payload FULL — same slot/source/target/head + committee

        let key_empty = PoolKey {
            data: vote_empty,
            committee_index,
        };
        let key_full = PoolKey {
            data: vote_full,
            committee_index,
        };

        // Same committee, but the signed data differs → different keys → different buckets.
        assert_eq!(key_empty.committee_index, key_full.committee_index);
        assert_ne!(
            key_empty, key_full,
            "payload votes must not collide into one bucket"
        );

        // Characterise the pre-fix behaviour this fixes: the old pool folded the committee index
        // into `data.index`, collapsing both votes onto a single AttestationData map key.
        let old_key_empty = AttestationData {
            index: committee_index,
            ..vote_empty
        };
        let old_key_full = AttestationData {
            index: committee_index,
            ..vote_full
        };
        assert_eq!(
            old_key_empty, old_key_full,
            "the old committee-in-data.index representation merged the two votes (the ★A bug)"
        );
    }
}
