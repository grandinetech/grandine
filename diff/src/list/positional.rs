use core::{borrow::Borrow, fmt::Debug};

use ssz::{ContiguousList, Size, Ssz, SszListMut, SszRead, SszSize, SszWrite};
use try_from_iterator::TryFromIterator as _;

use crate::{
    error::Error,
    list::Unlimited,
    patch::{Patch, PatchConfig},
};

#[derive(Ssz, Debug, Clone)]
#[ssz(
    derive_hash = false,
    bound = "T: SszWrite",
    bound_for_read = "T: SszRead<C> + SszWrite"
)]
pub struct PositionalPatch<T> {
    base_len: u32,
    edits: ContiguousList<PositionalEdit<T>, Unlimited>,
    appended: ContiguousList<T, Unlimited>,
    new_len: u32,
}

/// A run of consecutive values written starting at [`index`](Self::index).
///
/// Runs may cover positions whose value did not change, as long as merging them
/// costs less than encoding a separate edit (see [`merge_gap_threshold`]).
#[derive(Ssz, Debug, Clone)]
#[ssz(
    derive_hash = false,
    bound = "T: SszWrite",
    bound_for_read = "T: SszRead<C> + SszWrite"
)]
pub struct PositionalEdit<T> {
    index: u32,
    values: ContiguousList<T, Unlimited>,
}

/// Cost of encoding one more edit instead of extending the previous one: the
/// offset of the edit in the enclosing list, plus the edit's own fixed part
/// ([`index`](PositionalEdit::index) and the offset of its values).
const PER_EDIT_OVERHEAD: usize = 12;

const fn merge_gap_threshold<T: SszSize>() -> usize {
    match T::SIZE {
        Size::Fixed { size } if size > 0 => PER_EDIT_OVERHEAD.div_euclid(size),
        _ => 0,
    }
}

/// Collects positional edits from a stream of `(base, changed)` value pairs.
///
/// The values are fed in index order through [`Self::push`], which makes it
/// possible to compute several unrelated patches (each covering a different
/// field of the same item) in a single pass over the underlying collections.
pub struct EditAccumulator<T> {
    accumulated_edits: Vec<PositionalEdit<T>>,
    /// Start index, index of the last differing item, and values of the edit
    /// currently being built.
    last_edit: Option<(u32, usize, Vec<T>)>,
    /// Unchanged values trailing `last_edit`, kept around in case another change
    /// follows closely enough to merge. Reused across edits to avoid reallocating.
    buffer: Vec<T>,
}

impl<T: Clone + Eq + SszSize> EditAccumulator<T> {
    pub(crate) const fn new() -> Self {
        Self {
            accumulated_edits: Vec::new(),
            last_edit: None,
            buffer: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, i: usize, base_i: &T, changed_i: &T) {
        let threshold = merge_gap_threshold::<T>();

        if base_i == changed_i {
            if self.last_edit.is_some() && self.buffer.len() < threshold {
                self.buffer.push(changed_i.clone());
            }

            return;
        }

        match self.last_edit.as_mut() {
            Some((_, end, edits)) if i.saturating_sub(*end).saturating_sub(1) <= threshold => {
                edits.extend_from_slice(&self.buffer);
                self.buffer.clear();
                edits.push(changed_i.clone());
                *end = i;
            }
            _ => {
                self.flush();
                self.buffer.clear();

                self.last_edit = Some((
                    u32::try_from(i).expect("list index should fit in u32"),
                    i,
                    vec![changed_i.clone()],
                ))
            }
        }
    }

    pub(crate) fn finish(mut self) -> ContiguousList<PositionalEdit<T>, Unlimited> {
        self.flush();

        ContiguousList::try_from(self.accumulated_edits)
            .expect("positional patch should fit in the SSZ list")
    }

    fn flush(&mut self) {
        if let Some((start, _, edits)) = self.last_edit.take() {
            self.accumulated_edits.push(PositionalEdit {
                index: start,
                values: ContiguousList::try_from(edits)
                    .expect("positional edit chunk should fit in the SSZ list"),
            });
        }
    }
}

impl<T: Clone + Eq + SszSize> PositionalPatch<T> {
    /// Computes positional edits over the common prefix of two iterators.
    pub(crate) fn diff_edits(
        base: impl IntoIterator<Item: Borrow<T>>,
        changed: impl IntoIterator<Item: Borrow<T>>,
    ) -> ContiguousList<PositionalEdit<T>, Unlimited> {
        let mut accumulator = EditAccumulator::new();

        for (index, (base_item, changed_item)) in base.into_iter().zip(changed).enumerate() {
            accumulator.push(index, base_item.borrow(), changed_item.borrow());
        }

        accumulator.finish()
    }

    /// Replays positional edits by handing every `(index, value)` pair to `set`.
    pub(crate) fn apply_edits(
        edits: ContiguousList<PositionalEdit<T>, Unlimited>,
        mut set: impl FnMut(u64, T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for edit in edits {
            for (offset, value) in edit.values.into_iter().enumerate() {
                let index = u64::try_from(offset)
                    .ok()
                    .and_then(|offset| u64::from(edit.index).checked_add(offset))
                    .ok_or(Error::PatchIndexOutOfBounds)?;

                set(index, value)?;
            }
        }

        Ok(())
    }
}

impl<T, C> Patch<C> for PositionalPatch<T>
where
    T: Clone + Eq + SszSize,
    C: SszListMut<T> + ?Sized,
{
    fn diff(_config: PatchConfig, base: &C, changed: &C) -> Result<Self, Error> {
        let common_len = base.len_usize().min(changed.len_usize());

        Ok(Self {
            base_len: u32::try_from(base.len_usize()).map_err(|_| Error::PatchListLimitExceeded)?,
            edits: Self::diff_edits(base.iter(), changed.iter()),
            appended: ContiguousList::try_from_iter(changed.iter().skip(common_len).cloned())
                .expect("positional patch appended items should fit in the SSZ list"),
            new_len: u32::try_from(changed.len_usize()).expect("new list length should fit in u32"),
        })
    }

    fn apply(self, base: &mut C) -> Result<(), Error> {
        if base.len_usize()
            != usize::try_from(self.base_len).map_err(|_| Error::InvalidPatchEncoding)?
        {
            return Err(Error::PatchBaseLengthMismatch);
        }

        let new_len =
            usize::try_from(self.new_len).expect("patch length should fit in usize for comparison");

        if base.len_usize() > new_len {
            base.retain_range(0, u64::from(self.new_len))
                .map_err(|_| Error::PatchListLimitExceeded)?;
        }

        Self::apply_edits(self.edits, |index, value| {
            let ptr = base
                .get_mut(index)
                .map_err(|_| Error::PatchIndexOutOfBounds)?;

            *ptr = value;

            Ok(())
        })?;

        base.extend(&mut self.appended.into_iter())
            .map_err(|_| Error::PatchListLimitExceeded)?;

        if base.len_usize() != new_len {
            return Err(Error::PatchLengthMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ssz::{PersistentList, PersistentProgressiveList};
    use typenum::U64;

    use super::*;

    #[test]
    fn round_trips_over_persistent_list() {
        type List = PersistentList<u64, U64>;

        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        for changed in [
            List::try_from_iter(0..20),
            List::try_from_iter((0..20).map(|element| element * 3)),
            List::try_from_iter(0..30),
            List::try_from_iter(0..7),
            List::try_from_iter((0..7).map(|element| element * 3)),
            List::try_from_iter(0..0),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = PositionalPatch::diff(PatchConfig::default(), &base, &changed)
                .expect("positional patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    fn edits_of(base: &[u64], changed: &[u64]) -> Vec<(u32, Vec<u64>)> {
        let mut accumulator = EditAccumulator::new();

        for (index, (base_i, changed_i)) in base.iter().zip(changed).enumerate() {
            accumulator.push(index, base_i, changed_i);
        }

        accumulator
            .finish()
            .into_iter()
            .map(|edit| (edit.index, edit.values.into_iter().collect()))
            .collect()
    }

    #[test]
    fn a_single_unchanged_element_between_changes_is_merged_into_one_edit() {
        // `merge_gap_threshold::<u64>()` is 1, so exactly one unchanged element
        // is cheaper to rewrite than to start another edit.
        let base = (0..20).collect::<Vec<u64>>();
        let mut changed = base.clone();

        for index in [1, 3, 5] {
            changed[index] = changed[index].saturating_add(100);
        }

        assert_eq!(
            edits_of(&base, &changed),
            [(1, vec![101, 2, 103, 4, 105])],
            "unchanged elements 2 and 4 should be carried inside the merged edit",
        );
    }

    #[test]
    fn a_gap_above_the_threshold_starts_a_new_edit() {
        let base = (0..20).collect::<Vec<u64>>();
        let mut changed = base.clone();

        for index in [1, 4] {
            changed[index] = changed[index].saturating_add(100);
        }

        assert_eq!(edits_of(&base, &changed), [(1, vec![101]), (4, vec![104])]);
    }

    #[test]
    fn a_trailing_unchanged_run_is_not_written_into_the_last_edit() {
        let base = (0..20).collect::<Vec<u64>>();
        let mut changed = base.clone();

        changed[1] = 101;

        assert_eq!(edits_of(&base, &changed), [(1, vec![101])]);
    }

    #[test]
    fn merged_gaps_round_trip_through_a_list() {
        type List = PersistentList<u64, U64>;

        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        let changed = List::try_from_iter((0..20).map(|element| {
            if [1, 3, 5].contains(&element) {
                element + 100
            } else {
                element
            }
        }))
        .expect("length is below the maximum");

        let patch = PositionalPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("positional patch should represent the change");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        assert_eq!(applied, changed);
    }

    #[test]
    fn round_trips_over_persistent_progressive_list() {
        type List = PersistentProgressiveList<u64>;

        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        for changed in [
            List::try_from_iter(0..20),
            List::try_from_iter((0..20).map(|element| element * 3)),
            List::try_from_iter(0..30),
            List::try_from_iter(0..7),
            List::try_from_iter((0..7).map(|element| element * 3)),
            List::try_from_iter(0..0),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = PositionalPatch::diff(PatchConfig::default(), &base, &changed)
                .expect("positional patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn a_base_of_the_wrong_length_is_rejected() {
        type List = PersistentList<u64, U64>;

        // Edit positions are absolute, and a longer base would otherwise be silently truncated
        // to the recorded result length instead of being rejected.
        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        let changed = List::try_from_iter((0..20).map(|element| element * 3))
            .expect("length is below the maximum");

        let patch = PositionalPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("positional patch should represent the change");

        let mut longer = List::try_from_iter(0..30).expect("length is below the maximum");

        let error = patch
            .apply(&mut longer)
            .expect_err("the patch was diffed against a twenty-element list");

        assert!(matches!(error, Error::PatchBaseLengthMismatch));
    }
}
