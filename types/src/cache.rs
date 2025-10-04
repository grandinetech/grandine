use core::{iter::FusedIterator, ops::Range, slice::Iter};
use std::sync::Arc;

use bls::PublicKeyBytes;
use duplicate::duplicate;
use enum_map::EnumMap;
#[cfg(not(target_os = "zkvm"))]
use im::HashMap;
use once_cell::sync::OnceCell;
#[cfg(target_os = "zkvm")]
use std::collections::HashMap;

use crate::{
    altair::primitives::NonZeroGwei, nonstandard::RelativeEpoch, phase0::primitives::ValidatorIndex,
};

// Possible optimization: cache all proposer indices in an epoch.
// If possible, compute proposer indices in one go along with
// `Cache.active_validator_indices_shuffled` and remove `Cache.active_validator_indices_ordered`.
// Optionally cache more epochs and rotate proposer indices just like active validator indices.
//
// The fields in `Cache` are ordered from short-lived to long-lived.
#[derive(Clone, Default, Debug)]
pub struct Cache {
    // The proposer index is only used in functions that either own the state or have a mutable
    // reference to it, so this could be an `Option<ValidatorIndex>`, but accessing an initialized
    // `OnceCell<ValidatorIndex>` with `get_or_try_init` is about 4 times faster.
    //
    // `std::sync::OnceLock` cannot fully replace `once_cell::sync::OnceCell` until feature
    // `once_cell_try` is stabilized. `get_or_try_init` can be emulated with `get` and `set`,
    // but that is subject to a race condition that may affect performance.
    pub proposer_index: OnceCell<ValidatorIndex>,
    pub active_validator_indices_ordered: EnumMap<RelativeEpoch, OnceCell<PackedIndices>>,
    pub active_validator_indices_shuffled: EnumMap<RelativeEpoch, OnceCell<PackedIndices>>,
    pub total_active_balance: EnumMap<RelativeEpoch, OnceCell<NonZeroGwei>>,
    pub validator_indices: OnceCell<HashMap<PublicKeyBytes, ValidatorIndex>>,
}

impl Cache {
    pub fn advance_slot(&mut self) {
        self.proposer_index.take();
    }

    pub fn advance_epoch(&mut self) {
        let ordered = &mut self.active_validator_indices_ordered;
        let shuffled = &mut self.active_validator_indices_shuffled;
        let balance = &mut self.total_active_balance;

        ordered[RelativeEpoch::Previous] = core::mem::take(&mut ordered[RelativeEpoch::Current]);
        shuffled[RelativeEpoch::Previous] = core::mem::take(&mut shuffled[RelativeEpoch::Current]);
        balance[RelativeEpoch::Previous] = core::mem::take(&mut balance[RelativeEpoch::Current]);

        ordered[RelativeEpoch::Current] = core::mem::take(&mut ordered[RelativeEpoch::Next]);
        shuffled[RelativeEpoch::Current] = core::mem::take(&mut shuffled[RelativeEpoch::Next]);
        balance[RelativeEpoch::Current] = core::mem::take(&mut balance[RelativeEpoch::Next]);
    }
}

// Possible optimization: store the discriminant in alignment bits.
// `triomphe` provides an `ArcUnion` type, but it only supports 2 variants.
// `elysees` (a fork of `triomphe`) used to support 4 variants, but it does not as of version 0.3.0.
// This could be done using `ptr-union` and `slice-dst`, but those are not usable with `triomphe`
// because `triomphe` does not implement the required traits as of version 0.1.8.
// Alignment shouldn't be an issue because `ArcInner` contains `AtomicUsize`.
//
// Possible optimization: assume the number of validators will stay low and use only `u32`.
#[derive(Clone, Debug)]
pub enum PackedIndices {
    U8(Arc<[u8]>),
    U16(Arc<[u16]>),
    U32(Arc<[u32]>),
    U64(Arc<[u64]>),
}

impl PackedIndices {
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::U8(indices) => indices.len(),
            Self::U16(indices) => indices.len(),
            Self::U32(indices) => indices.len(),
            Self::U64(indices) => indices.len(),
        }
    }

    // This cannot be an `Index` impl because this has to return an owned value.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u64> {
        match self {
            Self::U8(indices) => indices.get(index).copied().map(Into::into),
            Self::U16(indices) => indices.get(index).copied().map(Into::into),
            Self::U32(indices) => indices.get(index).copied().map(Into::into),
            Self::U64(indices) => indices.get(index).copied(),
        }
    }

    // This cannot be an `Index` impl because this has to return an owned value.
    #[inline]
    #[must_use]
    pub fn slice(&self, range: Range<usize>) -> IndexSlice<'_> {
        match self {
            Self::U8(indices) => IndexSlice::U8(&indices[range]),
            Self::U16(indices) => IndexSlice::U16(&indices[range]),
            Self::U32(indices) => IndexSlice::U32(&indices[range]),
            Self::U64(indices) => IndexSlice::U64(&indices[range]),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IndexSlice<'indices> {
    U8(&'indices [u8]),
    U16(&'indices [u16]),
    U32(&'indices [u32]),
    U64(&'indices [u64]),
}

impl<'indices> IntoIterator for IndexSlice<'indices> {
    type Item = u64;
    type IntoIter = IndexSliceIter<'indices>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::U8(indices) => IndexSliceIter::U8(indices.iter()),
            Self::U16(indices) => IndexSliceIter::U16(indices.iter()),
            Self::U32(indices) => IndexSliceIter::U32(indices.iter()),
            Self::U64(indices) => IndexSliceIter::U64(indices.iter()),
        }
    }
}

impl IndexSlice<'_> {
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::U8(indices) => indices.len(),
            Self::U16(indices) => indices.len(),
            Self::U32(indices) => indices.len(),
            Self::U64(indices) => indices.len(),
        }
    }
}

pub enum IndexSliceIter<'indices> {
    U8(Iter<'indices, u8>),
    U16(Iter<'indices, u16>),
    U32(Iter<'indices, u32>),
    U64(Iter<'indices, u64>),
}

impl Iterator for IndexSliceIter<'_> {
    type Item = u64;

    // Override the stable methods that `core::slice::Iter` does,
    // except the ones overridden exclusively for compilation speed.
    duplicate! {
        [
            signature
            expression;

            [fn next(&mut self) -> Option<Self::Item>]
            [inner.next().copied().map(Into::into)];

            [fn size_hint(&self) -> (usize, Option<usize>)]
            [inner.size_hint()];

            [fn count(self) -> usize]
            [inner.count()];

            [fn last(self) -> Option<Self::Item>]
            [inner.last().copied().map(Into::into)];

            [fn nth(&mut self, n: usize) -> Option<Self::Item>]
            [inner.nth(n).copied().map(Into::into)];
        ]
        #[inline]
        signature {
            match self {
                Self::U8(inner) => expression,
                Self::U16(inner) => expression,
                Self::U32(inner) => expression,
                Self::U64(inner) => expression,
            }
        }
    }
}

impl DoubleEndedIterator for IndexSliceIter<'_> {
    // Override the stable methods that `core::slice::Iter` does.
    duplicate! {
        [
            signature
            expression;

            [fn next_back(&mut self) -> Option<Self::Item>]
            [inner.next_back().copied().map(Into::into)];

            [fn nth_back(&mut self, n: usize) -> Option<Self::Item>]
            [inner.nth_back(n).copied().map(Into::into)];
        ]
        #[inline]
        signature {
            match self {
                Self::U8(inner) => expression,
                Self::U16(inner) => expression,
                Self::U32(inner) => expression,
                Self::U64(inner) => expression,
            }
        }
    }
}

impl ExactSizeIterator for IndexSliceIter<'_> {
    // Override the stable methods that `core::slice::Iter` does.
    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::U8(inner) => inner.len(),
            Self::U16(inner) => inner.len(),
            Self::U32(inner) => inner.len(),
            Self::U64(inner) => inner.len(),
        }
    }
}

impl FusedIterator for IndexSliceIter<'_> {}
