use bitvec::{bitbox, boxed::BitBox, order::Lsb0, slice::BitSlice};
use ssz::{ByteList, Ssz, SszListMut};
use strum::FromRepr;
use typenum::U4294967296;

use crate::error::Error;

#[derive(Debug, Clone, FromRepr)]
#[repr(u8)]
enum PositionLayout {
    Gaps,
    Bitmap,
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct PositionSet {
    layout: u8,
    positions: ByteList<U4294967296>,
}

impl PositionSet {
    pub fn builder(total_len: usize) -> PositionSetBuilder {
        PositionSetBuilder {
            buffer: unsigned_varint::encode::u64_buffer(),
            gaps: Vec::new(),
            bitmap: bitbox![u8, Lsb0; 0; total_len],
            next: 0,
        }
    }

    pub fn apply_by_index(
        self,
        mut edit: impl FnMut(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some(layout) = PositionLayout::from_repr(self.layout) else {
            return Err(Error::InvalidPatchEncoding);
        };

        match layout {
            PositionLayout::Gaps => {
                let mut remaining = self.positions.as_bytes();
                let mut index: u64 = 0;

                while !remaining.is_empty() {
                    let gap;
                    (gap, remaining) = unsigned_varint::decode::u64(remaining)
                        .map_err(|_| Error::InvalidPatchEncoding)?;

                    index = index.checked_add(gap).ok_or(Error::InvalidPatchEncoding)?;

                    edit(index)?;

                    index = index.saturating_add(1);
                }

                Ok(())
            }
            PositionLayout::Bitmap => {
                let bitmap = BitSlice::<u8, Lsb0>::try_from_slice(self.positions.as_bytes())
                    .map_err(|_| Error::InvalidPatchEncoding)?;

                for index in bitmap.iter_ones() {
                    edit(u64::try_from(index).expect("list index should fit in u64"))?;
                }

                Ok(())
            }
        }
    }

    pub fn apply<T: Eq + Clone, C: SszListMut<T> + ?Sized>(
        self,
        list: &mut C,
        mut edit: impl FnMut(&mut T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some(layout) = PositionLayout::from_repr(self.layout) else {
            return Err(Error::InvalidPatchEncoding);
        };

        match layout {
            PositionLayout::Gaps => {
                let mut remaining = self.positions.as_bytes();
                let mut index: u64 = 0;

                while !remaining.is_empty() {
                    let gap;
                    (gap, remaining) = unsigned_varint::decode::u64(remaining)
                        .map_err(|_| Error::InvalidPatchEncoding)?;

                    index = index.checked_add(gap).ok_or(Error::InvalidPatchEncoding)?;

                    let value = list
                        .get_mut(index)
                        .map_err(|_| Error::PatchIndexOutOfBounds)?;

                    edit(value)?;

                    index = index.saturating_add(1);
                }

                Ok(())
            }
            PositionLayout::Bitmap => {
                let bitmap = BitSlice::<u8, Lsb0>::try_from_slice(self.positions.as_bytes())
                    .map_err(|_| Error::InvalidPatchEncoding)?;

                // `update` visits every element, so a bitmap that does not cover the whole list
                // would be indexed out of bounds below.
                if bitmap.len() < list.len_usize() {
                    return Err(Error::InvalidPatchEncoding);
                }

                let mut index = 0;
                let mut error = None;
                list.update(&mut |value| {
                    if error.is_none() && bitmap[index] {
                        error = edit(value).err();
                    }

                    index = index.saturating_add(1);
                });

                error.map_or(Ok(()), Err)
            }
        }
    }
}

pub struct PositionSetBuilder {
    /// Buffer for encoding u64 as `unsigned_varint`. Buffer size is hardcoded
    /// constant, because `unsigned_varint` didn't made `U64_LEN` constant public.
    buffer: [u8; 10],
    /// Buffer, which contains gaps, encoded via `unsigned_varint`.
    gaps: Vec<u8>,
    /// Bitmap, containing information about values changed.
    bitmap: BitBox<u8, Lsb0>,
    /// Tracking index, used for gap calculation.
    next: usize,
}

impl PositionSetBuilder {
    /// Record index of next changed value in list.
    ///
    /// # Panics
    ///
    /// Panics if `position` is not greater than every position recorded so far, or if it is
    /// outside the list the builder was created for. The two layouts are built in parallel and
    /// only the gap layout is order-dependent, so out-of-order input would otherwise make them
    /// disagree and corrupt whichever `finish` picks.
    pub fn record(&mut self, position: usize) {
        assert!(
            position >= self.next,
            "positions must be recorded in ascending order",
        );

        let gap = u64::try_from(position.saturating_sub(self.next))
            .expect("list index should fit in u64");

        self.gaps
            .extend_from_slice(unsigned_varint::encode::u64(gap, &mut self.buffer));
        self.bitmap.set(position, true);
        self.next = position.saturating_add(1);
    }

    pub fn finish(self) -> PositionSet {
        let (layout, positions) = if self.gaps.len() <= self.bitmap.as_raw_slice().len() {
            (PositionLayout::Gaps, self.gaps)
        } else {
            (PositionLayout::Bitmap, self.bitmap.into_bitvec().into_vec())
        };

        PositionSet {
            layout: layout as u8,
            positions: ByteList::try_from(positions)
                .expect("balance position bytes should fit in the SSZ byte list"),
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::PersistentList;
    use try_from_iterator::TryFromIterator as _;
    use typenum::U4096;

    use super::*;

    type List = PersistentList<u64, U4096>;

    fn position_set(total_len: usize, positions: impl IntoIterator<Item = usize>) -> PositionSet {
        let mut builder = PositionSet::builder(total_len);

        for position in positions {
            builder.record(position);
        }

        builder.finish()
    }

    fn apply_to(positions: PositionSet, length: usize) -> Result<Vec<u64>, Error> {
        let mut list = List::try_from_iter(core::iter::repeat_n(0, length))
            .expect("length is below the maximum");

        positions.apply(&mut list, |value| {
            *value = 1;
            Ok(())
        })?;

        Ok(list.into_iter().copied().collect())
    }

    #[test]
    fn sparse_changes_are_encoded_as_gaps_and_applied_at_the_recorded_positions()
    -> Result<(), Error> {
        // Adjacent positions produce a zero gap, and the distant ones produce multi-byte varints.
        let changed = [0, 1, 2, 127, 128, 4000, 4095];
        let positions = position_set(4096, changed);

        assert_eq!(positions.layout, PositionLayout::Gaps as u8);

        let expected = (0..4096)
            .map(|index| u64::from(changed.contains(&index)))
            .collect::<Vec<_>>();

        assert_eq!(apply_to(positions, 4096)?, expected);

        Ok(())
    }

    #[test]
    fn dense_changes_are_encoded_as_a_bitmap_and_applied_at_the_recorded_positions()
    -> Result<(), Error> {
        let positions = position_set(20, 0..20);

        assert_eq!(positions.layout, PositionLayout::Bitmap as u8);
        assert_eq!(apply_to(positions, 20)?, vec![1; 20]);

        Ok(())
    }

    #[test]
    fn a_gap_past_the_end_of_the_list_is_rejected() {
        let positions = position_set(4096, [4095]);

        assert!(matches!(
            apply_to(positions, 10),
            Err(Error::PatchIndexOutOfBounds),
        ));
    }

    #[test]
    fn a_bitmap_that_does_not_cover_the_whole_list_is_rejected() {
        let mut positions = position_set(20, 0..20);

        assert_eq!(positions.layout, PositionLayout::Bitmap as u8);

        // A corrupt row can hold fewer bytes than the list it is applied to.
        positions.positions =
            ByteList::try_from(vec![0xff]).expect("a single byte fits in the SSZ byte list");

        assert!(matches!(
            apply_to(positions, 20),
            Err(Error::InvalidPatchEncoding),
        ));
    }

    #[test]
    fn an_unknown_layout_is_rejected() {
        let mut positions = position_set(20, 0..20);

        positions.layout = 2;

        assert!(matches!(
            apply_to(positions, 20),
            Err(Error::InvalidPatchEncoding),
        ));
    }
}
