use crossbeam_skiplist::SkipMap;
use ssz::{BitList, SszHash as _, H256};
use types::{
    combined::Attestation,
    phase0::{containers::AttestationData, primitives::Epoch},
    preset::Preset,
};

type AggregateEpochSupersets<N> = SkipMap<H256, BitList<N>>;

#[derive(Default)]
pub struct AggregateAndProofSets<N> {
    supersets: SkipMap<Epoch, AggregateEpochSupersets<N>>,
}

impl<N: Send + Sync + 'static> AggregateAndProofSets<N> {
    pub fn check(&self, data: &AttestationData, aggregation_bits: &BitList<N>) -> bool {
        let attestation_data_root = data.hash_tree_root();
        let supersets = self
            .supersets
            .get_or_insert_with(data.target.epoch, SkipMap::new);

        let supersets = supersets.value();

        let is_superset = if let Some(existing) = supersets.get(&attestation_data_root) {
            let existing = existing.value();
            aggregation_bits.any_not_in(existing) && !existing.any_not_in(aggregation_bits)
        } else {
            true
        };

        if is_superset {
            supersets.insert(attestation_data_root, aggregation_bits.clone());
        }

        is_superset
    }

    pub fn prune(&self, finalized_epoch: Epoch) {
        for entry in self.supersets.range(..=finalized_epoch) {
            entry.remove();
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.supersets.len()
    }
}

#[derive(Default)]
pub struct MultiPhaseAggregateAndProofSets<P: Preset> {
    phase0_supersets: AggregateAndProofSets<P::MaxValidatorsPerCommittee>,
    electra_supersets: AggregateAndProofSets<P::MaxAggregatorsPerSlot>,
}

impl<P: Preset> MultiPhaseAggregateAndProofSets<P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prune(&self, finalized_epoch: Epoch) {
        self.phase0_supersets.prune(finalized_epoch);
        self.electra_supersets.prune(finalized_epoch);
    }

    pub fn check(&self, attestation: &Attestation<P>) -> bool {
        match attestation {
            Attestation::Phase0(attestation) => self
                .phase0_supersets
                .check(&attestation.data, &attestation.aggregation_bits),
            Attestation::Electra(attestation) => self
                .electra_supersets
                .check(&attestation.data, &attestation.aggregation_bits),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.phase0_supersets.len() + self.electra_supersets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::preset::Minimal;

    #[test]
    fn check_first_insert_is_superset() {
        let supersets = MultiPhaseAggregateAndProofSets::<Minimal>::new();
        assert_eq!(supersets.len(), 0);

        // 1 0 1 1
        // let superset = BitList::::new(true, 1);
        // assert!(superset.check())
    }
}
