use core::{
    num::NonZeroUsize,
    ops::{Index, IndexMut, RangeInclusive, RangeToInclusive},
};

use anyhow::Result;
use derive_more::Debug;
#[cfg(not(target_os = "zkvm"))]
use im::{
    vector::{Iter, IterMut},
    Vector,
};
#[cfg(target_os = "zkvm")]
use std::vec::Vec as Vector;
use thiserror::Error;
use types::{phase0::primitives::Slot, preset::Preset};

use crate::misc::{ChainLink, UnfinalizedBlock};

#[derive(Clone, Debug)]
pub struct Segment<P: Preset> {
    // This is never empty. A segment always contains at least one block.
    blocks: Vector<UnfinalizedBlock<P>>,
    // A nonzero value in `Segment.first_position` indicates that the segment has been partially
    // finalized and the finalized blocks have been removed from it. The number of finalized blocks
    // is equal to `Segment.first_position`.
    first_position: Position,
}

impl<P: Preset> From<Segment<P>> for Vector<UnfinalizedBlock<P>> {
    fn from(segment: Segment<P>) -> Self {
        segment.blocks
    }
}

impl<P: Preset> Index<Position> for Segment<P> {
    type Output = UnfinalizedBlock<P>;

    fn index(&self, position: Position) -> &Self::Output {
        let index = self.resolve_position(position);
        &self.blocks[index]
    }
}

impl<P: Preset> IndexMut<Position> for Segment<P> {
    fn index_mut(&mut self, position: Position) -> &mut Self::Output {
        let index = self.resolve_position(position);
        &mut self.blocks[index]
    }
}

#[expect(clippy::into_iter_without_iter)]
impl<'segment, P: Preset> IntoIterator for &'segment Segment<P> {
    type Item = &'segment UnfinalizedBlock<P>;
    type IntoIter = Iter<'segment, UnfinalizedBlock<P>>;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter()
    }
}

#[expect(clippy::into_iter_without_iter)]
impl<'segment, P: Preset> IntoIterator for &'segment mut Segment<P> {
    type Item = &'segment mut UnfinalizedBlock<P>;
    type IntoIter = IterMut<'segment, UnfinalizedBlock<P>>;

    fn into_iter(self) -> Self::IntoIter {
        self.blocks.iter_mut()
    }
}

// TODO(Grandine Team): Optimize valid and invalid block lookup methods.
//                      Blocks can be looked up using binary search instead of linear search.

impl<P: Preset> Segment<P> {
    #[must_use]
    pub fn new(chain_link: ChainLink<P>) -> Self {
        Self {
            blocks: Vector::unit(UnfinalizedBlock::new(chain_link)),
            first_position: Position::default(),
        }
    }

    #[must_use]
    pub fn len(&self) -> NonZeroUsize {
        self.blocks
            .len()
            .try_into()
            .expect("every segment contains at least one block")
    }

    #[must_use]
    pub fn non_invalid_len(&self) -> usize {
        self.blocks
            .iter()
            .take_while(|block| block.non_invalid())
            .count()
    }

    #[must_use]
    pub fn first_block(&self) -> &UnfinalizedBlock<P> {
        self.blocks
            .front()
            .expect("every segment contains at least one block")
    }

    #[must_use]
    pub fn last_block(&self) -> &UnfinalizedBlock<P> {
        self.blocks
            .back()
            .expect("every segment contains at least one block")
    }

    #[must_use]
    pub fn last_non_invalid_block(&self) -> Option<&UnfinalizedBlock<P>> {
        self.blocks.iter().rev().find(|block| block.non_invalid())
    }

    #[must_use]
    pub const fn first_position(&self) -> Position {
        self.first_position
    }

    #[must_use]
    pub fn last_position(&self) -> Position {
        Position(self.first_position.get() + self.len().get() - 1)
    }

    #[must_use]
    pub fn block_before_or_at(
        &self,
        slot: Slot,
        position: Position,
    ) -> Option<&UnfinalizedBlock<P>> {
        let index_before_or_at_slot = match self
            .blocks
            .binary_search_by_key(&slot, UnfinalizedBlock::slot)
        {
            Ok(match_index) => match_index,
            Err(0) => return None,
            Err(nonzero) => nonzero - 1,
        };

        // The `position` parameter and call to `usize::min` here was needed to implement
        // `Store::ancestor` correctly but led to an unexpectedly large slowdown of 10-25% when
        // processing attestations received at close to real time. This is because an incorrect
        // result causes more attestations to be rejected as invalid, reducing the number of
        // checkpoint states that need to be computed.
        let index = self.resolve_position(position).min(index_before_or_at_slot);

        Some(&self.blocks[index])
    }

    pub fn chain_ending_at(&self, position: Position) -> impl Iterator<Item = &ChainLink<P>> {
        self.iter_up_to(..=position)
            .map(|unfinalized_block| &unfinalized_block.chain_link)
            .rev()
    }

    #[must_use]
    pub fn len_up_to(&self, last_included: Position) -> NonZeroUsize {
        (self.resolve_position(last_included) + 1)
            .try_into()
            .expect("range measured by Segment::len_up_to always contains at least one block")
    }

    // pub fn iter(&mut self) -> impl Iterator<Item = &UnfinalizedBlock<P>> {
    //     self.blocks.iter()
    // }

    // The `#[must_use]` is redundant starting with Rust 1.66.0, but Clippy hasn't caught up yet.
    // See <https://github.com/rust-lang/rust/pull/102287/>.
    // There seems to be no issue about this in <https://github.com/rust-lang/rust-clippy>.
    #[must_use]
    pub fn iter_up_to(
        &self,
        positions: RangeToInclusive<Position>,
    ) -> impl DoubleEndedIterator<Item = &UnfinalizedBlock<P>> {
        let length = self.resolve_position(positions.end) + 1;
        self.blocks.iter().take(length)
    }

    pub fn iter_mut_range(
        &mut self,
        positions: RangeInclusive<Position>,
    ) -> impl Iterator<Item = &mut UnfinalizedBlock<P>> {
        let (first_included, last_included) = positions.into_inner();
        let start = self.resolve_position(first_included);
        let length = self.resolve_position(last_included) - start + 1;
        self.blocks.iter_mut().skip(start).take(length)
    }

    pub fn push(&mut self, block: UnfinalizedBlock<P>) {
        self.blocks.push_back(block);
    }

    pub fn finalize_up_to(&mut self, last_included: Position) -> Vector<UnfinalizedBlock<P>> {
        let first_excluded_index = self.resolve_position(last_included) + 1;
        let remaining = self.blocks.split_off(first_excluded_index);

        assert!(!remaining.is_empty());

        self.first_position = last_included
            .next()
            .expect("position must be valid because it is already filled");

        core::mem::replace(&mut self.blocks, remaining)
    }

    #[must_use]
    pub fn split_at(
        self,
        last_before_split: Position,
    ) -> (Vector<UnfinalizedBlock<P>>, Vector<UnfinalizedBlock<P>>) {
        let index = self.resolve_position(last_before_split) + 1;
        self.blocks.split_at(index)
    }

    fn resolve_position(&self, position: Position) -> usize {
        let index = position.get() - self.first_position.get();

        assert!(index < self.len().get());

        index
    }
}

// Using `NonZeroUsize` instead of `usize` would make `DissolvedDifference` smaller,
// but the difference isn't worth the trouble.
//
// If the proposal in <https://github.com/ethereum/consensus-specs/pull/2197> gets accepted,
// identifying blocks in a segment by their position may no longer be an option.
// Slots should work as a substitute but would require binary search or interpolation search.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
#[debug("{_0}")]
pub struct Position(usize);

impl Position {
    pub fn next(self) -> Result<Self> {
        self.get()
            .checked_add(1)
            .ok_or(Error)
            .map(Self)
            .map_err(Into::into)
    }

    const fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug, Error)]
#[error("ran out of block positions in segment")]
struct Error;
