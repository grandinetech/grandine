use crossbeam_skiplist::{SkipMap, SkipSet};
use helper_functions::misc;
use ssz::{BitList, H256, SszHash as _};
use types::{
    combined::Attestation,
    phase0::{containers::AttestationData, primitives::Epoch},
    preset::Preset,
};

type AggregateEpochSupersets<N> = SkipMap<H256, SkipSet<BitList<N>>>;

#[derive(Default)]
pub struct AggregateAndProofSets<N> {
    supersets: SkipMap<Epoch, AggregateEpochSupersets<N>>,
}

impl<N: Send + Sync + 'static> AggregateAndProofSets<N> {
    pub fn is_known_subset(&self, data: &AttestationData, aggregation_bits: &BitList<N>) -> bool {
        let Some(supersets) = self.supersets.get(&data.target.epoch) else {
            return false;
        };

        supersets
            .value()
            .get(&data.hash_tree_root())
            .is_some_and(|existing_sets| {
                // Bits not yet validated may have the wrong length, which `any_not_in` asserts.
                existing_sets.value().iter().any(|entry| {
                    entry.value().len() == aggregation_bits.len()
                        && !aggregation_bits.any_not_in(entry.value())
                })
            })
    }

    pub fn observe(&self, data: &AttestationData, aggregation_bits: &BitList<N>) {
        if self.is_known_subset(data, aggregation_bits) {
            return;
        }

        let supersets = self
            .supersets
            .get_or_insert_with(data.target.epoch, SkipMap::new);

        let existing_sets = supersets
            .value()
            .get_or_insert(data.hash_tree_root(), SkipSet::new());

        let existing_sets = existing_sets.value();

        for entry in existing_sets {
            if !entry.value().any_not_in(aggregation_bits) {
                entry.remove();
            }
        }

        existing_sets.insert(aggregation_bits.clone());
    }

    pub fn prune(&self, finalized_epoch: Epoch) {
        for entry in self.supersets.range(..=finalized_epoch) {
            entry.remove();
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.supersets
            .iter()
            .map(|epoch_entry| {
                epoch_entry
                    .value()
                    .iter()
                    .map(|entry| entry.value().len())
                    .sum::<usize>()
            })
            .sum()
    }
}

#[derive(Default)]
pub struct MultiPhaseAggregateAndProofSets<P: Preset> {
    phase0_supersets: AggregateAndProofSets<P::MaxValidatorsPerCommittee>,
    electra_supersets: AggregateAndProofSets<P::MaxAttestersPerSlot>,
}

impl<P: Preset> MultiPhaseAggregateAndProofSets<P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prune(&self, finalized_epoch: Epoch) {
        self.phase0_supersets.prune(finalized_epoch);
        self.electra_supersets.prune(finalized_epoch);
    }

    pub fn is_known_subset(&self, attestation: &Attestation<P>) -> bool {
        let committee_index = misc::committee_index(attestation);

        match attestation {
            Attestation::Phase0(attestation) => self
                .phase0_supersets
                .is_known_subset(&attestation.data, &attestation.aggregation_bits),
            Attestation::Electra(attestation) => {
                let data = AttestationData {
                    index: committee_index,
                    ..attestation.data
                };

                self.electra_supersets
                    .is_known_subset(&data, &attestation.aggregation_bits)
            }
            Attestation::Gloas(attestation) => {
                let data = AttestationData {
                    index: committee_index,
                    ..attestation.data
                };

                self.electra_supersets
                    .is_known_subset(&data, &attestation.aggregation_bits)
            }
            Attestation::Single(_) => {
                unreachable!(
                    "single attestations should not be validated with methods meant for aggregate and proofs only"
                )
            }
        }
    }

    pub fn observe(&self, attestation: &Attestation<P>) {
        let committee_index = misc::committee_index(attestation);

        match attestation {
            Attestation::Phase0(attestation) => self
                .phase0_supersets
                .observe(&attestation.data, &attestation.aggregation_bits),
            Attestation::Electra(attestation) => {
                let data = AttestationData {
                    index: committee_index,
                    ..attestation.data
                };

                self.electra_supersets
                    .observe(&data, &attestation.aggregation_bits);
            }
            Attestation::Gloas(attestation) => {
                let data = AttestationData {
                    index: committee_index,
                    ..attestation.data
                };

                self.electra_supersets
                    .observe(&data, &attestation.aggregation_bits);
            }
            Attestation::Single(_) => {
                unreachable!(
                    "single attestations should not be validated with methods meant for aggregate and proofs only"
                )
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.phase0_supersets
            .len()
            .saturating_add(self.electra_supersets.len())
    }
}

#[cfg(test)]
mod tests {
    use ssz::BitVector;
    use types::{
        electra::containers::Attestation as ElectraAttestation, phase0::primitives::CommitteeIndex,
        preset::Minimal,
    };

    use super::*;

    fn aggregate(
        committee_index: CommitteeIndex,
        attester_bits: impl IntoIterator<Item = u8>,
    ) -> Attestation<Minimal> {
        let attester_bits = attester_bits.into_iter().collect::<Vec<_>>();
        let mut aggregation_bits = BitList::with_length(attester_bits.len());
        let mut committee_bits = BitVector::default();

        for (index, bit) in attester_bits.into_iter().enumerate() {
            aggregation_bits.set(index, bit == 1);
        }

        committee_bits.set(
            committee_index
                .try_into()
                .expect("committee index should fit in usize"),
            true,
        );

        Attestation::Electra(ElectraAttestation {
            aggregation_bits,
            committee_bits,
            ..ElectraAttestation::default()
        })
    }

    #[test]
    fn test_superset_observe() {
        let agg_0_1 = aggregate(0, [0, 0, 1]);
        let agg_0_2 = aggregate(0, [1, 0, 1]);
        let agg_0_3 = aggregate(0, [0, 1, 1]);
        let agg_0_4 = aggregate(0, [1, 0, 0]);
        let agg_0_5 = aggregate(0, [0, 0, 1]);
        let agg_1_1 = aggregate(1, [0, 0, 1]);

        let supersets = MultiPhaseAggregateAndProofSets::<Minimal>::new();
        assert_eq!(supersets.len(), 0);

        assert!(!supersets.is_known_subset(&agg_0_1));
        supersets.observe(&agg_0_1);
        // Adds a new superset
        assert_eq!(supersets.len(), 1);

        assert!(!supersets.is_known_subset(&agg_0_2));
        supersets.observe(&agg_0_2);
        // Overrides existing superset
        assert_eq!(supersets.len(), 1);

        assert!(!supersets.is_known_subset(&agg_0_3));
        supersets.observe(&agg_0_3);
        // Adds a new superset
        assert_eq!(supersets.len(), 2);

        assert!(supersets.is_known_subset(&agg_0_4));
        supersets.observe(&agg_0_4);
        // Does nothing
        assert_eq!(supersets.len(), 2);

        assert!(supersets.is_known_subset(&agg_0_5));
        supersets.observe(&agg_0_5);
        // Does nothing
        assert_eq!(supersets.len(), 2);

        assert!(!supersets.is_known_subset(&agg_1_1));
        supersets.observe(&agg_1_1);
        // Adds a new superset
        assert_eq!(supersets.len(), 3);
    }

    // Gossip validation runs before signatures are verified, so it must not record what it sees.
    #[test]
    fn test_is_known_subset_does_not_observe() {
        let superset = aggregate(0, [1, 1, 1]);
        let subset = aggregate(0, [0, 0, 1]);

        let supersets = MultiPhaseAggregateAndProofSets::<Minimal>::new();

        assert!(!supersets.is_known_subset(&superset));
        assert!(!supersets.is_known_subset(&superset));
        assert!(!supersets.is_known_subset(&subset));
        assert_eq!(supersets.len(), 0);
    }

    // Gossip bits of the wrong length reach the subset check before their length is validated.
    #[test]
    fn test_is_known_subset_with_mismatched_length() {
        let observed = aggregate(0, [1, 1, 1]);
        let shorter = aggregate(0, [1, 1]);
        let longer = aggregate(0, [1, 1, 1, 0]);

        let supersets = MultiPhaseAggregateAndProofSets::<Minimal>::new();

        supersets.observe(&observed);

        assert!(!supersets.is_known_subset(&shorter));
        assert!(!supersets.is_known_subset(&longer));
    }
}
