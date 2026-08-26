use core::cmp::Reverse;
use std::collections::HashMap;

use ssz::{ByteList, Ssz, SszListMut};
use typenum::U4294967296;
use types::phase0::primitives::Gwei;

use crate::{error::Error, list::position_set::PositionSet};

/// Zigzagged varint deltas for a [`Gwei`] field of every element that changed.
///
/// The field may be the whole element, as in a balance list, or one field of a richer one, as in a
/// validator's effective balance, so the two directions are reached through closures rather than by
/// owning the list.
#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct GweiDeltas {
    mode: Gwei,
    positions: PositionSet,
    deltas: ByteList<U4294967296>,
}

impl GweiDeltas {
    /// Encodes the changes in `pairs`, which must yield `(base, changed)` balances in index order
    /// for the first `total_len` elements of the list being diffed.
    pub fn diff<I: Iterator<Item = (Gwei, Gwei)>>(
        total_len: usize,
        pairs: impl Fn() -> I,
    ) -> Result<Self, Error> {
        let mode = Self::estimate_mode(pairs())?;
        let mode_delta = unzigzag(mode);

        let mut positions = PositionSet::builder(total_len);
        let mut buffer = unsigned_varint::encode::u64_buffer();
        let mut deltas = Vec::new();

        for (index, (before, after)) in pairs().enumerate() {
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
                    .checked_sub(mode_delta)
                    .ok_or(Error::InvalidBalanceDelta)?;

                zigzag(delta)
                    .checked_add(1)
                    .ok_or(Error::InvalidBalanceDelta)?
            };

            deltas.extend_from_slice(unsigned_varint::encode::u64(encoded, &mut buffer));

            positions.record(index);
        }

        Ok(Self {
            mode,
            positions: positions.finish(),
            deltas: ByteList::try_from(deltas)
                .expect("balance delta bytes should fit in the SSZ byte list"),
        })
    }

    pub fn apply<T, C>(
        self,
        base: &mut C,
        mut balance: impl FnMut(&mut T) -> &mut Gwei,
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

            *balance = next_balance(&mut remaining, mode, *balance)?;

            Ok(())
        })?;

        finish(remaining)
    }

    pub fn apply_by_index(
        self,
        mut edit: impl FnMut(u64, &mut dyn FnMut(Gwei) -> Result<Gwei, Error>) -> Result<(), Error>,
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
                next_balance(&mut remaining, mode, balance)
            })
        })?;

        finish(remaining)
    }

    fn estimate_mode(pairs: impl Iterator<Item = (Gwei, Gwei)>) -> Result<Gwei, Error> {
        let mut counts = HashMap::new();

        for (before, after) in pairs {
            if before == after || after == 0 {
                continue;
            }

            let after = i64::try_from(after).map_err(|_| Error::InvalidBalanceDelta)?;
            let before = i64::try_from(before).map_err(|_| Error::InvalidBalanceDelta)?;
            let delta = after
                .checked_sub(before)
                .ok_or(Error::InvalidBalanceDelta)?;

            let count = counts.entry(zigzag(delta)).or_insert(0_usize);
            *count = count.saturating_add(1);
        }

        Ok(counts
            .into_iter()
            // Ties are broken by the smaller zigzagged delta to keep diffs deterministic.
            .max_by_key(|&(delta, count)| (count, Reverse(delta)))
            .map_or(0, |(delta, _)| delta))
    }
}

fn next_balance(remaining: &mut &[u8], mode: i64, balance: Gwei) -> Result<Gwei, Error> {
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

/// Rejects deltas that no recorded position claimed, which would otherwise be dropped silently.
const fn finish(remaining: &[u8]) -> Result<(), Error> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidPatchEncoding)
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
    use ssz::{PersistentList, SszList as _};
    use try_from_iterator::TryFromIterator as _;
    use typenum::U64;

    use super::*;

    type List = PersistentList<Gwei, U64>;

    fn list(balances: impl IntoIterator<Item = Gwei>) -> List {
        List::try_from_iter(balances).expect("length is below the maximum")
    }

    fn diff(base: &List, changed: &List) -> GweiDeltas {
        GweiDeltas::diff(base.len_usize(), || {
            base.iter()
                .zip(changed.iter())
                .map(|(&before, &after)| (before, after))
        })
        .expect("deltas should represent the change")
    }

    fn apply(deltas: GweiDeltas, base: &List) -> Result<List, Error> {
        let mut applied = base.clone();

        deltas.apply(&mut applied, |balance| balance)?;

        Ok(applied)
    }

    #[test]
    fn a_uniform_decrease_is_picked_as_the_mode() {
        let base = list((0..20).map(|index| 32_000_000_000 + index));
        let changed = list((0..20).map(|index| 31_999_900_000 + index));

        let deltas = diff(&base, &changed);

        assert_eq!(deltas.mode, zigzag(-100_000));

        // Every balance moved by the mode, so every delta encodes as the single byte 1.
        assert_eq!(deltas.deltas.as_bytes(), [1; 20]);
        assert_eq!(apply(deltas, &base).expect("deltas should apply"), changed);
    }

    #[test]
    fn zeroed_balances_do_not_contribute_to_the_mode() {
        let base = list([10, 10, 10, 40]);
        let changed = list([0, 0, 0, 47]);

        let deltas = diff(&base, &changed);

        // The -10 of the three zeroings is the most repeated delta, but zeroings are skipped,
        // which leaves the lone +7.
        assert_eq!(deltas.mode, zigzag(7));

        // The zeroings encode as the set-to-zero opcode, the increase as the mode itself.
        assert_eq!(deltas.deltas.as_bytes(), [0, 0, 0, 1]);
        assert_eq!(apply(deltas, &base).expect("deltas should apply"), changed);
    }

    #[test]
    fn truncated_and_overlong_delta_bytes_are_rejected() {
        let base = list([10, 20, 30]);
        let changed = list([11, 22, 33]);

        let deltas = diff(&base, &changed);

        let mut truncated = deltas.clone();

        truncated.deltas = ByteList::try_from(vec![]).expect("an empty byte list is valid");

        let error = apply(truncated, &base).expect_err("three positions need three deltas");

        assert!(matches!(error, Error::InvalidPatchEncoding));

        let mut overlong_bytes = deltas.deltas.as_bytes().to_vec();
        overlong_bytes.push(1);

        let mut overlong = deltas;

        overlong.deltas = ByteList::try_from(overlong_bytes).expect("length is below the maximum");

        let error = apply(overlong, &base)
            .expect_err("a delta no position claims must not be silently dropped");

        assert!(matches!(error, Error::InvalidPatchEncoding));
    }

    #[test]
    fn a_delta_that_drives_a_balance_negative_is_rejected() {
        let base = list([100]);
        let changed = list([50]);

        let deltas = diff(&base, &changed);

        assert_eq!(deltas.mode, zigzag(-50));

        let error = apply(deltas, &list([10])).expect_err("a balance cannot go below zero");

        assert!(matches!(error, Error::InvalidBalanceDelta));
    }

    #[test]
    fn apply_by_index_visits_the_changed_positions_in_order() {
        let base = list([10, 20, 30, 40, 50]);
        let changed = list([10, 22, 30, 0, 51]);

        let mut visited = Vec::new();

        diff(&base, &changed)
            .apply_by_index(|index, patch| {
                let before = *base.get(index).expect("index is within bounds");

                visited.push((index, patch(before)?));

                Ok(())
            })
            .expect("deltas should apply");

        assert_eq!(visited, [(1, 22), (3, 0), (4, 51)]);
    }
}
