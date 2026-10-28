use core::cmp::Reverse;
use std::collections::HashMap;

use ssz::{ByteList, Ssz, SszList, SszListMut};
use typenum::U4294967296;

use crate::{
    error::Error,
    list::{
        bundles::{Vector, vector_bundles, zip_unshared},
        position_set::PositionSet,
    },
};

/// Changes to a list of gwei balances.
#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct GweiDeltas {
    mode: u64,
    positions: PositionSet,
    deltas: ByteList<U4294967296>,
}

impl GweiDeltas {
    pub fn diff_lists<C: SszList<u64> + ?Sized>(base: &C, changed: &C) -> Result<Self, Error> {
        Self::diff(base.len_usize(), || {
            zip_unshared(base.bundles(), changed.bundles())
                .map(|(index, &before, &after)| (index, before, after))
        })
    }

    pub fn diff_vectors(base: &Vector<u64>, changed: &Vector<u64>) -> Result<Self, Error> {
        Self::diff(base.len(), || {
            zip_unshared(vector_bundles(base), vector_bundles(changed))
                .map(|(index, &before, &after)| (index, before, after))
        })
    }

    pub fn diff_pairs<I: Iterator<Item = (u64, u64)>>(
        total_len: usize,
        pairs: impl Fn() -> I,
    ) -> Result<Self, Error> {
        Self::diff(total_len, || {
            pairs()
                .enumerate()
                .map(|(index, (before, after))| (index, before, after))
        })
    }

    fn diff<I: Iterator<Item = (usize, u64, u64)>>(
        total_len: usize,
        pairs: impl Fn() -> I,
    ) -> Result<Self, Error> {
        let mode = Self::compute_mode(pairs())?;

        let mut positions = PositionSet::builder(total_len);
        let mut buffer = unsigned_varint::encode::u64_buffer();
        let mut deltas = Vec::new();

        for (index, before, after) in pairs() {
            if before == after {
                continue;
            }

            let after = i64::try_from(after).map_err(|_| Error::InvalidBalanceDelta)?;
            let before = i64::try_from(before).map_err(|_| Error::InvalidBalanceDelta)?;

            let encoded = if after == 0 {
                0
            } else {
                let delta = after
                    .checked_sub(before)
                    .ok_or(Error::InvalidBalanceDelta)?
                    .checked_sub(mode)
                    .ok_or(Error::InvalidBalanceDelta)?;

                zigzag(delta)
                    .checked_add(1)
                    .ok_or(Error::InvalidBalanceDelta)?
            };

            deltas.extend_from_slice(unsigned_varint::encode::u64(encoded, &mut buffer));

            positions.record(index);
        }

        Ok(Self {
            mode: zigzag(mode),
            positions: positions.finish(),
            deltas: ByteList::try_from(deltas)
                .expect("balance delta bytes should fit in the SSZ byte list"),
        })
    }

    pub fn apply<T, C>(
        self,
        base: &mut C,
        mut balance: impl FnMut(&mut T) -> &mut u64,
    ) -> Result<(), Error>
    where
        T: Clone + Eq,
        C: SszListMut<T> + ?Sized,
    {
        let Self {
            mode,
            positions,
            deltas,
        } = self;

        let mode = unzigzag(mode);
        let mut remaining = deltas.as_bytes();

        positions.apply(base, |item| {
            let balance = balance(item);

            *balance = Self::next_balance(&mut remaining, mode, *balance)?;

            Ok(())
        })?;

        if remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidPatchEncoding)
        }
    }

    pub fn apply_by_index(
        self,
        mut edit: impl FnMut(u64, &mut dyn FnMut(u64) -> Result<u64, Error>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Self {
            mode,
            positions,
            deltas,
        } = self;

        let mode = unzigzag(mode);
        let mut remaining = deltas.as_bytes();

        positions.apply_by_index(|index| {
            edit(index, &mut |balance| {
                Self::next_balance(&mut remaining, mode, balance)
            })
        })?;

        if remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidPatchEncoding)
        }
    }

    fn compute_mode(pairs: impl Iterator<Item = (usize, u64, u64)>) -> Result<i64, Error> {
        let mut counts = HashMap::new();

        for (_, before, after) in pairs {
            if before == after || after == 0 {
                continue;
            }

            let after = i64::try_from(after).map_err(|_| Error::InvalidBalanceDelta)?;
            let before = i64::try_from(before).map_err(|_| Error::InvalidBalanceDelta)?;
            let delta = after
                .checked_sub(before)
                .ok_or(Error::InvalidBalanceDelta)?;

            let count = counts.entry(delta).or_insert(0_usize);
            *count = count.saturating_add(1);
        }

        Ok(counts
            .into_iter()
            .max_by_key(|&(delta, count)| (count, Reverse(delta)))
            .map_or(0, |(delta, _)| delta))
    }

    fn next_balance(remaining: &mut &[u8], mode: i64, balance: u64) -> Result<u64, Error> {
        let delta;
        (delta, *remaining) =
            unsigned_varint::decode::u64(remaining).map_err(|_| Error::InvalidPatchEncoding)?;

        match delta {
            // set to zero
            0 => Ok(0),
            // zigzagged delta
            1.. => {
                let delta = unzigzag(delta.saturating_sub(1))
                    .checked_add(mode)
                    .ok_or(Error::InvalidBalanceDelta)?;
                let patched = i64::try_from(balance).map_err(|_| Error::InvalidBalanceDelta)?;
                let patched = patched
                    .checked_add(delta)
                    .ok_or(Error::InvalidBalanceDelta)?;

                u64::try_from(patched).map_err(|_| Error::InvalidBalanceDelta)
            }
        }
    }
}

const fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

const fn unzigzag(value: u64) -> i64 {
    (value >> 1).cast_signed() ^ (value & 1).cast_signed().wrapping_neg()
}

#[cfg(test)]
mod tests {
    use ssz::PersistentList;
    use try_from_iterator::TryFromIterator as _;
    use typenum::U64;

    use super::*;

    #[test]
    fn a_uniform_decrease_is_picked_as_the_mode() {
        let base =
            PersistentList::<u64, U64>::try_from_iter((0..20).map(|index| 32_000_000_000 + index))
                .expect("length is below the maximum");
        let changed =
            PersistentList::<u64, U64>::try_from_iter((0..20).map(|index| 31_999_900_000 + index))
                .expect("length is below the maximum");

        let deltas =
            GweiDeltas::diff_lists(&base, &changed).expect("deltas should represent the change");

        assert_eq!(deltas.mode, zigzag(-100_000));

        // Every balance moved by the mode, so every delta encodes as the single byte 1.
        assert_eq!(deltas.deltas.as_bytes(), [1; 20]);

        let mut applied = base;

        deltas
            .apply(&mut applied, |balance| balance)
            .expect("deltas should apply");

        assert_eq!(applied, changed);
    }

    #[test]
    fn zeroed_balances_do_not_contribute_to_the_mode() {
        let base = PersistentList::<u64, U64>::try_from_iter([10, 10, 10, 40])
            .expect("length is below the maximum");
        let changed = PersistentList::<u64, U64>::try_from_iter([0, 0, 0, 47])
            .expect("length is below the maximum");

        let deltas =
            GweiDeltas::diff_lists(&base, &changed).expect("deltas should represent the change");

        // The -10 of the three zeroings is the most repeated delta, but zeroings are skipped,
        // which leaves the lone +7.
        assert_eq!(deltas.mode, zigzag(7));

        // The zeroings encode as the set-to-zero opcode, the increase as the mode itself.
        assert_eq!(deltas.deltas.as_bytes(), [0, 0, 0, 1]);

        let mut applied = base;

        deltas
            .apply(&mut applied, |balance| balance)
            .expect("deltas should apply");

        assert_eq!(applied, changed);
    }

    #[test]
    fn truncated_and_overlong_delta_bytes_are_rejected() {
        let mut base = PersistentList::<u64, U64>::try_from_iter([10, 20, 30])
            .expect("length is below the maximum");
        let changed = PersistentList::<u64, U64>::try_from_iter([11, 22, 33])
            .expect("length is below the maximum");

        let deltas =
            GweiDeltas::diff_lists(&base, &changed).expect("deltas should represent the change");

        let mut truncated = deltas.clone();

        truncated.deltas = ByteList::try_from(vec![]).expect("an empty byte list is valid");

        let error = truncated
            .apply(&mut base.clone(), |balance| balance)
            .expect_err("three positions need three deltas");

        assert!(matches!(error, Error::InvalidPatchEncoding));

        let mut overlong_bytes = deltas.deltas.as_bytes().to_vec();
        overlong_bytes.push(1);

        let mut overlong = deltas;

        overlong.deltas = ByteList::try_from(overlong_bytes).expect("length is below the maximum");

        let error = overlong
            .apply(&mut base, |balance| balance)
            .expect_err("a delta no position claims must not be silently dropped");

        assert!(matches!(error, Error::InvalidPatchEncoding));
    }

    #[test]
    fn a_delta_that_drives_a_balance_negative_is_rejected() {
        let base =
            PersistentList::<u64, U64>::try_from_iter([100]).expect("length is below the maximum");
        let changed =
            PersistentList::<u64, U64>::try_from_iter([50]).expect("length is below the maximum");

        let deltas =
            GweiDeltas::diff_lists(&base, &changed).expect("deltas should represent the change");

        assert_eq!(deltas.mode, zigzag(-50));

        let mut other =
            PersistentList::<u64, U64>::try_from_iter([10]).expect("length is below the maximum");

        let error = deltas
            .apply(&mut other, |balance| balance)
            .expect_err("a balance cannot go below zero");

        assert!(matches!(error, Error::InvalidBalanceDelta));
    }

    #[test]
    fn apply_by_index_visits_the_changed_positions_in_order() {
        let base = PersistentList::<u64, U64>::try_from_iter([10, 20, 30, 40, 50])
            .expect("length is below the maximum");
        let changed = PersistentList::<u64, U64>::try_from_iter([10, 22, 30, 0, 51])
            .expect("length is below the maximum");

        let mut visited = Vec::new();

        GweiDeltas::diff_lists(&base, &changed)
            .expect("deltas should represent the change")
            .apply_by_index(|index, patch| {
                let before = *base.get(index).expect("index is within bounds");

                visited.push((index, patch(before)?));

                Ok(())
            })
            .expect("deltas should apply");

        assert_eq!(visited, [(1, 22), (3, 0), (4, 51)]);
    }
}
