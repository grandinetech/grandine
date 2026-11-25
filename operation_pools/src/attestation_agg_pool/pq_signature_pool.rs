//! The signatures of PQ single attestations, proven one aggregate per committee and attestation
//! data: all of a slot at the aggregation cutoff of its first aggregators, and a committee again at
//! the later cutoff of each own aggregator after the first.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use helper_functions::{accessors, pq};
use pq_prover::ProverBackend;
use ssz::{BitList, BitVector, SszHash as _};
use typenum::Unsigned as _;
use types::{
    config::Config,
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{CommitteeIndex, H256, Slot, ValidatorIndex},
    },
    pq::{
        containers::{Attestation as PqAttestation, SingleAttestation as PqSingleAttestation},
        primitives::AttestationProof,
    },
    preset::Preset,
    traits::BeaconState,
};
use xmss::XmssSignature;

use crate::attestation_agg_pool::types::PqPoolAttestation;

// Signatures of older slots can no longer make it into an aggregate.
const RETAIN_SLOTS: u64 = 3;

// Bounds the attestation data per committee and slot that the pool keeps signatures for.
const MAX_DATA_PER_COMMITTEE: u64 = 4;

type Key = (Slot, H256, CommitteeIndex);

#[derive(Clone)]
pub struct CommitteeSignatures {
    data: AttestationData,
    committee_index: CommitteeIndex,
    committee_length: usize,
    // Keyed by position in the committee, so that signatures come out in committee order.
    signatures: BTreeMap<usize, (ValidatorIndex, XmssSignature)>,
}

#[derive(Default)]
pub struct PqSignaturePool {
    signatures: BTreeMap<Key, CommitteeSignatures>,
    // Signatures of this slot and earlier ones have been handed over to the first aggregators.
    sealed_slot: Option<Slot>,
}

impl PqSignaturePool {
    pub fn insert<P: Preset>(
        &mut self,
        current_slot: Slot,
        attestation: &PqSingleAttestation,
        position: usize,
        committee_length: usize,
    ) {
        self.prune(current_slot);

        let PqSingleAttestation {
            committee_index,
            attester_index,
            data,
            ref signature,
        } = *attestation;

        let slot = data.slot;

        if slot < current_slot {
            return;
        }

        let key = (slot, data.hash_tree_root(), committee_index);

        if !self.signatures.contains_key(&key) {
            let data_in_slot = self
                .signatures
                .range((slot, H256::zero(), 0)..)
                .take_while(|((entry_slot, _, _), _)| *entry_slot == slot)
                .count();

            let maximum = P::MaxCommitteesPerSlotPq::U64.saturating_mul(MAX_DATA_PER_COMMITTEE);

            if u64::try_from(data_in_slot).unwrap_or(u64::MAX) >= maximum {
                return;
            }
        }

        let committee_signatures =
            self.signatures
                .entry(key)
                .or_insert_with(|| CommitteeSignatures {
                    data,
                    committee_index,
                    committee_length,
                    signatures: BTreeMap::new(),
                });

        if committee_signatures.committee_length == committee_length {
            committee_signatures
                .signatures
                .entry(position)
                .or_insert_with(|| (attester_index, signature.clone()));
        }
    }

    /// The signatures of `slot` collected so far, once per slot. Signatures for it that arrive
    /// later are still collected, for [`Self::committee_signatures`].
    pub fn seal(&mut self, slot: Slot) -> Vec<CommitteeSignatures> {
        self.prune(slot);

        if self.sealed_slot.is_some_and(|sealed| slot <= sealed) {
            return vec![];
        }

        self.sealed_slot = Some(slot);

        self.signatures
            .range((slot, H256::zero(), 0)..(slot.saturating_add(1), H256::zero(), 0))
            .map(|(_, committee_signatures)| committee_signatures.clone())
            .collect()
    }

    /// The signatures collected so far for `data` in the committee.
    pub fn committee_signatures(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Option<CommitteeSignatures> {
        self.signatures
            .get(&(data.slot, data.hash_tree_root(), committee_index))
            .cloned()
    }

    fn prune(&mut self, current_slot: Slot) {
        let earliest_slot = current_slot.saturating_sub(RETAIN_SLOTS - 1);

        self.signatures
            .retain(|(slot, _, _), _| earliest_slot <= *slot);
    }
}

impl CommitteeSignatures {
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// The committee positions of the attesters whose signatures were collected.
    pub fn positions(&self) -> impl Iterator<Item = usize> + '_ {
        self.signatures.keys().copied()
    }

    #[must_use]
    pub const fn target(&self) -> Checkpoint {
        self.data.target
    }

    /// [`get_aggregate_stark`] of the attesters whose signatures were collected.
    ///
    /// [`get_aggregate_stark`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#aggregate-stark
    pub fn prove<P: Preset>(
        self,
        config: &Config,
        state: &impl BeaconState<P>,
        backend: &dyn ProverBackend,
    ) -> Result<PqPoolAttestation<P>> {
        let Self {
            data,
            committee_index,
            committee_length,
            signatures,
        } = self;

        let committee = accessors::beacon_committee(state, data.slot, committee_index)?
            .into_iter()
            .collect::<Vec<_>>();

        ensure!(
            committee.len() == committee_length,
            "committee length changed from {committee_length} to {}",
            committee.len(),
        );

        let mut aggregation_bits = BitList::with_length(committee_length);
        let mut attester_signatures = vec![];

        for (position, (attester_index, signature)) in signatures {
            if committee.get(position) == Some(&attester_index) {
                aggregation_bits.set(position, true);
                attester_signatures.push(signature);
            }
        }

        ensure!(
            !attester_signatures.is_empty(),
            "no signatures of committee members"
        );

        let mut committee_bits = BitVector::default();
        committee_bits.set(usize::try_from(committee_index)?, true);

        let committee_bits_bytes: Vec<u8> = aggregation_bits.clone().into();

        let attestation = PqAttestation::<P> {
            aggregation_bits: BitList::try_from(committee_bits_bytes)?.into(),
            data,
            committee_bits,
        };

        let statements = pq::get_attestation_statements(config, state, &attestation)?;
        let proof = backend.prove(&statements, &[attester_signatures])?;

        Ok(PqPoolAttestation {
            aggregation_bits,
            data,
            committee_index,
            proof: AttestationProof::<P>::try_from(proof)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use types::{phase0::containers::Checkpoint, preset::Minimal};

    use super::*;

    fn attestation(slot: Slot, attester_index: ValidatorIndex, root: H256) -> PqSingleAttestation {
        PqSingleAttestation {
            committee_index: 0,
            attester_index,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: root,
                source: Checkpoint::default(),
                target: Checkpoint::default(),
            },
            signature: XmssSignature::default(),
        }
    }

    #[test]
    fn signatures_are_sealed_once_per_slot() {
        let mut pool = PqSignaturePool::default();
        let single = attestation(3, 123, H256::zero());

        pool.insert::<Minimal>(3, &single, 1, 2);
        pool.insert::<Minimal>(3, &single, 1, 2);

        // A different committee length means the attestation is for another shuffling.
        pool.insert::<Minimal>(3, &attestation(3, 124, H256::zero()), 0, 3);

        let [sealed] = pool
            .seal(3)
            .try_into()
            .ok()
            .expect("one committee was sealed");

        assert_eq!(sealed.signature_count(), 1);
        assert_eq!(
            sealed.signatures.get(&1).map(|(index, _)| *index),
            Some(123)
        );

        // A slot is sealed only once, but its signatures are still collected.
        pool.insert::<Minimal>(3, &attestation(3, 125, H256::zero()), 0, 2);
        assert!(pool.seal(3).is_empty());

        let later = pool
            .committee_signatures(single.data, 0)
            .expect("signatures are still collected");

        assert_eq!(later.positions().collect::<Vec<_>>(), [0, 1]);
    }

    #[test]
    fn signatures_of_past_slots_are_dropped() {
        let mut pool = PqSignaturePool::default();

        pool.insert::<Minimal>(4, &attestation(3, 1, H256::zero()), 0, 1);

        assert!(pool.signatures.is_empty());

        pool.insert::<Minimal>(4, &attestation(4, 1, H256::zero()), 0, 1);
        pool.insert::<Minimal>(
            4 + RETAIN_SLOTS,
            &attestation(5 + RETAIN_SLOTS, 1, H256::zero()),
            0,
            1,
        );

        assert_eq!(pool.signatures.len(), 1);
    }

    #[test]
    fn attestation_data_per_slot_is_bounded() {
        let mut pool = PqSignaturePool::default();
        let maximum = <Minimal as Preset>::MaxCommitteesPerSlotPq::U64 * MAX_DATA_PER_COMMITTEE;

        for root in 0..=maximum {
            let root = H256::from_low_u64_be(root);
            pool.insert::<Minimal>(3, &attestation(3, 1, root), 0, 1);
        }

        assert_eq!(u64::try_from(pool.signatures.len()), Ok(maximum));
    }
}
