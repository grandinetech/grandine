use crossbeam_skiplist::SkipMap;
use ssz::{BitList, SszHash as _, H256};
use types::{
    phase0::{containers::Attestation, primitives::Epoch},
    preset::Preset,
};

type AggregateEpochSupersets<P> = SkipMap<H256, BitList<<P as Preset>::MaxValidatorsPerCommittee>>;

#[derive(Default)]
pub struct AggregateAndProofSets<P: Preset> {
    supersets: SkipMap<Epoch, AggregateEpochSupersets<P>>,
}

impl<P: Preset> AggregateAndProofSets<P> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, aggregate: &Attestation<P>) -> bool {
        let Attestation {
            aggregation_bits,
            data,
            ..
        } = aggregate;

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

#[cfg(test)]
mod tests {
    use super::*;
    use types::preset::Minimal;

    #[test]
    fn check_first_insert_is_superset() {
        let supersets = AggregateAndProofSets::<Minimal>::new();
        assert_eq!(supersets.len(), 0);

        // 1 0 1 1
        // let superset = BitList::::new(true, 1);
        // assert!(superset.check())
    }
}
