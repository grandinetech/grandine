use bls::PublicKeyBytes;
use ssz::{ContiguousList, Ssz, SszListMut};
use try_from_iterator::TryFromIterator as _;
use types::{
    gloas::containers::Builder,
    phase0::primitives::{Epoch, ExecutionAddress},
};

use crate::{
    error::Error,
    list::{
        Unlimited,
        gwei_deltas::GweiDeltas,
        positional::{EditAccumulator, PositionalEdit, PositionalPatch},
    },
    patch::{Patch, PatchConfig},
};

#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct BuilderListPatch {
    base_len: u32,
    balances: GweiDeltas,
    other_edits: ContiguousList<PositionalEdit<OtherBuilderFields>, Unlimited>,
    appended: ContiguousList<Builder, Unlimited>,
}

#[derive(PartialEq, Eq, Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
struct OtherBuilderFields {
    pubkey: PublicKeyBytes,
    version: u8,
    execution_address: ExecutionAddress,
    deposit_epoch: Epoch,
    withdrawable_epoch: Epoch,
}

impl From<&Builder> for OtherBuilderFields {
    fn from(builder: &Builder) -> Self {
        let Builder {
            pubkey,
            version,
            execution_address,
            balance: _,
            deposit_epoch,
            withdrawable_epoch,
        } = *builder;

        Self {
            pubkey,
            version,
            execution_address,
            deposit_epoch,
            withdrawable_epoch,
        }
    }
}

impl<C: SszListMut<Builder> + ?Sized> Patch<C> for BuilderListPatch {
    fn diff(_config: PatchConfig, base: &C, changed: &C) -> Result<Self, Error> {
        let common_len = base.len_usize();

        // An exited builder's slot is overwritten in place rather than removed, so the registry
        // never shrinks and a shorter `changed` cannot be represented.
        if changed.len_usize() < common_len {
            return Err(Error::UnsupportedDiff);
        }

        let mut others = EditAccumulator::new();

        for (index, (base_item, changed_item)) in base.iter().zip(changed.iter()).enumerate() {
            others.push(
                index,
                &OtherBuilderFields::from(base_item),
                &OtherBuilderFields::from(changed_item),
            );
        }

        Ok(Self {
            base_len: u32::try_from(common_len).map_err(|_| Error::PatchListLimitExceeded)?,
            balances: GweiDeltas::diff(common_len, || {
                base.iter()
                    .zip(changed.iter())
                    .map(|(before, after)| (before.balance, after.balance))
            })?,
            other_edits: others.finish(),
            appended: ContiguousList::try_from_iter(changed.iter().skip(common_len).cloned())
                .expect("builder list patch appended items should fit in the SSZ list"),
        })
    }

    fn apply(self, base: &mut C) -> Result<(), Error> {
        let Self {
            base_len,
            balances,
            other_edits,
            appended,
        } = self;

        if base.len_usize() != usize::try_from(base_len).map_err(|_| Error::InvalidPatchEncoding)? {
            return Err(Error::PatchBaseLengthMismatch);
        }

        balances.apply(base, |builder| &mut builder.balance)?;

        PositionalPatch::apply_edits(other_edits, |index, fields| {
            let builder = base
                .get_mut(index)
                .map_err(|_| Error::PatchIndexOutOfBounds)?;

            let OtherBuilderFields {
                pubkey,
                version,
                execution_address,
                deposit_epoch,
                withdrawable_epoch,
            } = fields;

            builder.pubkey = pubkey;
            builder.version = version;
            builder.execution_address = execution_address;
            builder.deposit_epoch = deposit_epoch;
            builder.withdrawable_epoch = withdrawable_epoch;

            Ok(())
        })?;

        base.extend(&mut appended.into_iter())
            .map_err(|_| Error::PatchListLimitExceeded)
    }
}

#[cfg(test)]
mod tests {
    use ssz::{
        PersistentProgressiveList, SszHash as _, SszListMut as _, SszRead as _, SszWrite as _,
    };
    use try_from_iterator::TryFromIterator as _;
    use types::config::Config;

    use super::*;

    type Builders = PersistentProgressiveList<Builder>;

    const BUILDER_SIZE: usize = 93;

    fn other_edit_count(patch: &BuilderListPatch) -> usize {
        patch.other_edits.clone().into_iter().count()
    }

    fn builder(index: u64) -> Builder {
        Builder {
            pubkey: PublicKeyBytes::from_low_u64_be(index),
            version: 1,
            execution_address: ExecutionAddress::from_low_u64_be(index),
            balance: 32_000_000_000_u64.saturating_add(index),
            deposit_epoch: index,
            withdrawable_epoch: Epoch::MAX,
        }
    }

    fn builders(count: u64) -> Builders {
        Builders::try_from_iter((0..count).map(builder)).expect("list is not full")
    }

    fn round_trip(base: &Builders, changed: &Builders) -> BuilderListPatch {
        let patch =
            <BuilderListPatch as Patch<Builders>>::diff(PatchConfig::default(), base, changed)
                .expect("patch should represent the change");

        let encoded = patch.to_ssz().expect("patch should serialize");

        let patch = BuilderListPatch::from_ssz(&Config::minimal(), encoded)
            .expect("patch should deserialize");

        let mut applied = base.clone();

        Patch::apply(patch.clone(), &mut applied).expect("patch should apply");

        assert_eq!(applied, *changed);
        assert_eq!(applied.hash_tree_root(), changed.hash_tree_root());

        patch
    }

    #[test]
    fn a_balance_change_costs_nothing_outside_the_balance_deltas() {
        let base = builders(30);
        let mut changed = base.clone();

        for index in [1, 7, 29] {
            changed
                .get_mut(index)
                .expect("index is within bounds")
                .balance = 16_000_000_000;
        }

        let patch = round_trip(&base, &changed);

        assert_eq!(other_edit_count(&patch), 0);

        // Three balance deltas cost less than a single whole builder would.
        assert!(patch.to_ssz().expect("patch should serialize").len() < BUILDER_SIZE);
    }

    #[test]
    fn edits_to_the_other_fields_round_trip() {
        let base = builders(30);
        let mut changed = base.clone();

        changed
            .get_mut(3)
            .expect("index is within bounds")
            .withdrawable_epoch = 128;

        let builder = changed.get_mut(11).expect("index is within bounds");

        builder.balance = 1;
        builder.execution_address = ExecutionAddress::repeat_byte(0xff);

        let patch = round_trip(&base, &changed);

        assert_eq!(other_edit_count(&patch), 2);
    }

    #[test]
    fn a_recycled_builder_slot_round_trips() {
        let mut base = builders(6);

        // An exited builder, which is what `get_index_for_new_builder` hands out again.
        let exited = base.get_mut(2).expect("index is within bounds");

        exited.balance = 0;
        exited.withdrawable_epoch = 4;

        let mut changed = base.clone();

        *changed.get_mut(2).expect("index is within bounds") = builder(600);

        let patch = round_trip(&base, &changed);

        assert_eq!(other_edit_count(&patch), 1);
    }

    #[test]
    fn appended_builders_round_trip() {
        let base = builders(4);
        let mut changed = base.clone();

        for index in 4..9 {
            changed.push(builder(index)).expect("list is not full");
        }

        changed.get_mut(0).expect("index is within bounds").balance = 7;

        round_trip(&base, &changed);
    }

    #[test]
    fn an_unchanged_list_round_trips() {
        let base = builders(6);

        round_trip(&base, &base.clone());
    }

    #[test]
    fn growing_from_an_empty_list_round_trips() {
        round_trip(&builders(0), &builders(3));
    }

    #[test]
    fn a_shorter_list_is_rejected() {
        let base = builders(4);
        let changed = builders(3);

        let error =
            <BuilderListPatch as Patch<Builders>>::diff(PatchConfig::default(), &base, &changed)
                .expect_err("the builder registry cannot shrink");

        assert!(matches!(error, Error::UnsupportedDiff));
    }

    #[test]
    fn a_base_of_the_wrong_length_is_rejected() {
        let base = builders(4);
        let mut changed = base.clone();

        changed.get_mut(3).expect("index is within bounds").balance = 1;

        let patch =
            <BuilderListPatch as Patch<Builders>>::diff(PatchConfig::default(), &base, &changed)
                .expect("patch should represent the change");

        let mut shorter = builders(2);

        let error = Patch::apply(patch, &mut shorter)
            .expect_err("the patch was diffed against a four-builder list");

        assert!(matches!(error, Error::PatchBaseLengthMismatch));
    }
}
