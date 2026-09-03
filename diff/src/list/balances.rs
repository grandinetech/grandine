use ssz::{ContiguousList, Ssz, SszListMut};
use try_from_iterator::TryFromIterator;
use types::phase0::primitives::Gwei;

use crate::{
    error::Error,
    list::{Unlimited, gwei_deltas::GweiDeltas},
    patch::{Patch, PatchConfig},
};

#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct BalancesPatch {
    base_len: u32,
    balances: GweiDeltas,
    appended: ContiguousList<Gwei, Unlimited>,
}

impl<C: SszListMut<Gwei> + ?Sized> Patch<C> for BalancesPatch {
    fn diff(_config: PatchConfig, base: &C, changed: &C) -> Result<Self, Error> {
        if base.len_usize() > changed.len_usize() {
            return Err(Error::UnsupportedDiff);
        }

        Ok(Self {
            base_len: u32::try_from(base.len_usize()).map_err(|_| Error::PatchListLimitExceeded)?,
            balances: GweiDeltas::diff(base.len_usize(), || {
                base.iter()
                    .zip(changed.iter())
                    .map(|(&before, &after)| (before, after))
            })?,
            appended: ContiguousList::try_from_iter(changed.iter().skip(base.len_usize()).copied())
                .expect("appended balances should fit in the SSZ list"),
        })
    }

    fn apply(self, base: &mut C) -> Result<(), Error> {
        let Self {
            base_len,
            balances,
            appended,
        } = self;

        if base.len_usize() != usize::try_from(base_len).map_err(|_| Error::InvalidPatchEncoding)? {
            return Err(Error::PatchBaseLengthMismatch);
        }

        balances.apply(base, |balance| balance)?;

        base.extend(&mut appended.into_iter())
            .map_err(|_| Error::PatchListLimitExceeded)
    }
}

#[cfg(test)]
mod tests {
    use ssz::PersistentList;
    use typenum::U64;

    use super::*;

    #[test]
    fn round_trips_over_persistent_list() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter((0..20).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        for changed in [
            // unchanged
            List::try_from_iter((0..20).map(|index| 32_000_000_000 + index)),
            // the same increase everywhere, which is what the mode is for
            List::try_from_iter((0..20).map(|index| 32_000_100_000 + index)),
            // decreases, zeroing and an appended balance
            List::try_from_iter(
                (0..20)
                    .map(|index| {
                        if index % 3 == 0 {
                            0
                        } else {
                            31_000_000_000 + index
                        }
                    })
                    .chain([32_000_000_000]),
            ),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
                .expect("balances patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn a_base_of_the_wrong_length_is_rejected() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter((0..20).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        let changed = List::try_from_iter((0..20).map(|index| 32_000_100_000 + index))
            .expect("length is below the maximum");

        let patch = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("balances patch should represent the change");

        let mut shorter = List::try_from_iter((0..10).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        let error = patch
            .apply(&mut shorter)
            .expect_err("the patch was diffed against a twenty-balance list");

        assert!(matches!(error, Error::PatchBaseLengthMismatch));
    }

    #[test]
    fn round_trips_mixed_increases_and_decreases() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter((0..20).map(|index| 32_000_000_000 + index * 1_000))
            .expect("length is below the maximum");

        let changed = List::try_from_iter((0..20).map(|index| {
            if index % 2 == 0 {
                32_000_000_000 + index * 1_000 + 500
            } else {
                32_000_000_000 + index * 1_000 - 700
            }
        }))
        .expect("length is below the maximum");

        let patch = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("balances patch should represent the change");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        assert_eq!(applied, changed);
    }

    #[test]
    fn a_base_longer_than_the_changed_list_is_unsupported() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter((0..20).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        let changed = List::try_from_iter((0..10).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        let error = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
            .expect_err("balances are never removed, so a shrinking list is not encodable");

        assert!(matches!(error, Error::UnsupportedDiff));
    }

    #[test]
    fn a_delta_that_drives_a_balance_negative_is_rejected() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter([100]).expect("length is below the maximum");
        let changed = List::try_from_iter([50]).expect("length is below the maximum");

        let patch = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("balances patch should represent the change");

        // The same length, so the base length check passes and the negative mode is applied.
        let mut smaller = List::try_from_iter([10]).expect("length is below the maximum");

        let error = patch
            .apply(&mut smaller)
            .expect_err("a balance cannot go below zero");

        assert!(matches!(error, Error::InvalidBalanceDelta));
    }

    #[test]
    fn round_trips_a_base_shorter_than_the_changed_list() {
        type List = PersistentList<Gwei, U64>;

        let base = List::try_from_iter((0..10).map(|index| 32_000_000_000 + index))
            .expect("length is below the maximum");

        let changed = List::try_from_iter(
            (0..10)
                .map(|index| 31_999_000_000 + index)
                .chain((0..4).map(|index| 32_000_000_000 + index)),
        )
        .expect("length is below the maximum");

        let patch = BalancesPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("balances patch should represent the change");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        assert_eq!(applied, changed);
    }
}
