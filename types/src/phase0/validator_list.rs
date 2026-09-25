use core::{fmt, iter, marker::PhantomData, ops::Range};
#[cfg(target_os = "zkvm")]
use std::slice::Iter as VectorIter;
use std::sync::Arc;

use anyhow::Result;
use arithmetic::{NonZeroExt as _, U64Ext as _};
use bls::PublicKeyBytes;
use derivative::Derivative;
#[cfg(not(target_os = "zkvm"))]
use im::vector::Iter as VectorIter;
use once_cell::race::OnceBox;
use serde::{
    Deserialize, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use ssz::{
    BundleSize, H256, IndexError, MinimumBundleSize, PushError, SszHash, SszRead, SszSize,
    SszWrite, U1, hashing, mix_in_length, read_list, saturating_usize, write_list,
};
use std_ext::CopyExt;
use try_from_iterator::TryFromIterator;
use typenum::Unsigned;

use crate::{
    nonstandard::{PartialValidator, PubkeyList, RawValidatorList, ValidatorListIter},
    phase0::{containers::Validator, primitives::Gwei},
    traits::SszValidatorList,
};

#[derive(Clone, Debug, Default, Derivative)]
#[derivative(PartialEq(bound = ""), Eq(bound = ""))]
pub struct ValidatorList<N: Unsigned> {
    /// Validator memory representation, backing container.
    pub(crate) buf: RawValidatorList,

    /// Merkle root cache.
    #[derivative(PartialEq = "ignore")]
    cache: Option<Arc<CacheNode>>,

    phantom: PhantomData<N>,
}

#[derive(Clone, Debug)]
pub(crate) enum CacheNode {
    Leaf(OnceBox<H256>),
    Internal {
        root: OnceBox<H256>,
        left: Arc<Self>,
        right: Arc<Self>,
    },
}

impl CacheNode {
    pub(crate) fn empty_leaf() -> Arc<Self> {
        Arc::new(Self::Leaf(OnceBox::new()))
    }

    pub(crate) fn build_empty(length: usize) -> Arc<Self> {
        if length == 1 {
            return Self::empty_leaf();
        }

        let left_length = length.next_power_of_two() / 2;
        let right_length = length
            .checked_sub(left_length)
            .expect("left_length never exceeds length");

        Arc::new(Self::Internal {
            root: OnceBox::new(),
            left: Self::build_empty(left_length),
            right: Self::build_empty(right_length),
        })
    }

    pub(crate) fn push_leaf(self: &mut Arc<Self>, old_length: usize) {
        if old_length.is_power_of_two() {
            *self = Arc::new(Self::Internal {
                root: OnceBox::new(),
                left: Arc::clone(self),
                right: Self::empty_leaf(),
            });

            return;
        }

        let left_length = old_length.next_power_of_two() / 2;
        let right_length = old_length
            .checked_sub(left_length)
            .expect("left_length never exceeds old_length");

        match Arc::make_mut(self) {
            Self::Internal { root, right, .. } => {
                *root = OnceBox::new();
                right.push_leaf(right_length);
            }
            Self::Leaf(_) => unreachable!("non-power-of-two length implies an internal node"),
        }
    }

    pub(crate) fn invalidate(self: &mut Arc<Self>, index: usize, length: usize) {
        match Arc::make_mut(self) {
            Self::Leaf(root) => *root = OnceBox::new(),
            Self::Internal { root, left, right } => {
                *root = OnceBox::new();

                let left_length = length.next_power_of_two() / 2;

                if index < left_length {
                    left.invalidate(index, left_length);
                } else {
                    let right_index = index
                        .checked_sub(left_length)
                        .expect("index >= left_length in this branch");
                    let right_length = length
                        .checked_sub(left_length)
                        .expect("left_length never exceeds length");

                    right.invalidate(right_index, right_length);
                }
            }
        }
    }

    /// Invalidates every cached root that covers an index in `range`.
    pub(crate) fn invalidate_range(self: &mut Arc<Self>, range: Range<usize>, length: usize) {
        if range.is_empty() {
            return;
        }

        match Arc::make_mut(self) {
            Self::Leaf(root) => *root = OnceBox::new(),
            Self::Internal { root, left, right } => {
                *root = OnceBox::new();

                let left_length = length.next_power_of_two() / 2;
                let right_length = length
                    .checked_sub(left_length)
                    .expect("left_length never exceeds length");

                left.invalidate_range(
                    range.start.min(left_length)..range.end.min(left_length),
                    left_length,
                );

                right.invalidate_range(
                    range.start.saturating_sub(left_length)
                        ..range.end.saturating_sub(left_length).min(right_length),
                    right_length,
                );
            }
        }
    }

    pub(crate) fn hash(&self, buf: &RawValidatorList, len: usize, offset: usize) -> H256 {
        match self {
            Self::Leaf(root) => root
                .get_or_init(|| {
                    let validator = buf
                        .get(offset.try_into().expect("offset doesn't fit in usize"))
                        .expect(
                            "validator list invariant violated: partial \
                                validator list is out of sync with current length",
                        );

                    Box::new(validator.hash_tree_root())
                })
                .copy(),
            Self::Internal { root, left, right } => root
                .get_or_init(|| {
                    let left_len = len.next_power_of_two() / 2;
                    let right_len = len
                        .checked_sub(left_len)
                        .expect("left_len never exceeds len");

                    let left_height =
                        <MinimumBundleSize<Validator> as BundleSize<Validator>>::depth_of_length(
                            left_len,
                        );
                    let right_height =
                        <MinimumBundleSize<Validator> as BundleSize<Validator>>::depth_of_length(
                            right_len,
                        );

                    let right_offset = offset
                        .checked_add(left_len)
                        .expect("offset + left_len never overflows usize");

                    let left = left.hash(buf, left_len, offset);
                    let right = right.hash(buf, right_len, right_offset);

                    let right_hash = (right_height..left_height)
                        .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                        .fold(right, hashing::hash_256_256);

                    Box::new(hashing::hash_256_256(left, right_hash))
                })
                .copy(),
        }
    }
}

impl<N: Unsigned> ValidatorList<N> {
    fn depth(&self) -> u8 {
        <MinimumBundleSize<Validator> as BundleSize<Validator>>::depth_of_length(self.len_usize())
    }

    fn max_depth() -> u8 {
        N::U64
            .ilog2_ceil()
            .saturating_sub(MinimumBundleSize::<Validator>::ilog2())
    }

    fn invalidate_index(&mut self, index: usize) {
        let len = self.len_usize();

        if index >= len {
            return;
        }

        if let Some(cache) = self.cache.as_mut() {
            cache.invalidate(index, len);
        }
    }

    /// Invalidates the cached hashes of the validators in `range`.
    fn invalidate_pubkey_range(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }

        let length = self.len_usize();

        match self.cache.as_mut() {
            Some(cache) => cache.invalidate_range(range, length),
            None => self.cache = (length > 0).then(|| CacheNode::build_empty(length)),
        }
    }
}

impl<N: Unsigned> SszValidatorList for ValidatorList<N> {
    fn get(&self, index: u64) -> Result<Validator, IndexError> {
        self.buf.get(index)
    }

    fn pubkey(&self, index: u64) -> Result<&PublicKeyBytes, IndexError> {
        self.buf.pubkey(index)
    }

    fn effective_balance(&self, index: u64) -> Result<u64, IndexError> {
        self.buf.effective_balance(index)
    }

    fn effective_balance_mut(&mut self, index: u64) -> Result<&mut u64, IndexError> {
        self.invalidate_index(
            index
                .try_into()
                .map_err(|_| IndexError::DoesNotFitInUsize { index })?,
        );

        self.buf.effective_balance_mut(index)
    }

    fn partial_validator(&self, index: u64) -> Result<&PartialValidator, IndexError> {
        self.buf.partial_validator(index)
    }

    fn partial_validator_mut(&mut self, index: u64) -> Result<&mut PartialValidator, IndexError> {
        self.invalidate_index(
            index
                .try_into()
                .map_err(|_| IndexError::DoesNotFitInUsize { index })?,
        );

        self.buf.partial_validator_mut(index)
    }

    fn pubkeys(&self) -> &PubkeyList {
        self.buf.pubkeys()
    }

    fn restore_pubkeys(&mut self, pubkeys: &PubkeyList) -> Result<()> {
        let restored = self.buf.restore_pubkeys(pubkeys)?;

        self.invalidate_pubkey_range(restored);

        Ok(())
    }

    fn restore_pubkeys_in(&mut self, pubkeys: &PubkeyList, range: Range<usize>) -> Result<()> {
        let restored = self.buf.restore_pubkeys_in(pubkeys, range)?;

        self.invalidate_pubkey_range(restored);

        Ok(())
    }

    fn clear_pubkeys(&mut self, count: usize) {
        self.buf.clear_pubkeys(count);
        let length = self.len_usize();
        self.cache = (length > 0).then(|| CacheNode::build_empty(length));
    }

    fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.buf.partial_validators()
    }

    fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.buf.effective_balances()
    }

    fn update_effective_balances(
        &mut self,
        updater: &mut dyn FnMut(&PartialValidator, Gwei) -> Result<Gwei, anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        self.buf.update_effective_balances(updater, |index, len| {
            if let Some(cache) = self.cache.as_mut() {
                cache.invalidate(index, len);
            }
        })
    }

    fn push(&mut self, validator: Validator) -> Result<(), PushError> {
        let old_length = self.len_usize();

        if old_length.saturating_add(1) >= saturating_usize::<N>() {
            return Err(PushError::ListFull);
        }

        self.buf.push(validator);

        match &mut self.cache {
            Some(cache) => cache.push_leaf(old_length),
            None => self.cache = Some(CacheNode::empty_leaf()),
        }

        Ok(())
    }

    fn len_usize(&self) -> usize {
        self.buf.len_usize()
    }

    fn len_u64(&self) -> u64 {
        self.buf.len_u64()
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = Validator> + 'a> {
        Box::new(self.into_iter())
    }

    fn clone_boxed(&self) -> Box<dyn SszValidatorList> {
        Box::new(self.clone())
    }
}

impl<N: Unsigned> TryFromIterator<Validator> for ValidatorList<N> {
    type Error = ssz::ReadError;

    fn try_from_iter(items: impl IntoIterator<Item = Validator>) -> Result<Self, Self::Error> {
        let buf = items.into_iter().collect::<RawValidatorList>();

        if buf.len_usize() > saturating_usize::<N>() {
            return Err(ssz::ReadError::ListTooLong {
                maximum: saturating_usize::<N>(),
                actual: buf.len_usize(),
            });
        }

        Ok(Self {
            cache: (buf.len_usize() > 0).then(|| CacheNode::build_empty(buf.len_usize())),

            buf,

            phantom: PhantomData,
        })
    }
}

impl<N: Unsigned> Serialize for ValidatorList<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self)
    }
}

impl<'de, N: Unsigned> Deserialize<'de> for ValidatorList<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValidatorListVisitor<N: Unsigned>(PhantomData<N>);

        impl<'de, N: Unsigned> Visitor<'de> for ValidatorListVisitor<N> {
            type Value = ValidatorList<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a validator list of length up to {}",
                    saturating_usize::<N>()
                )
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                itertools::process_results(
                    iter::from_fn(|| seq.next_element().transpose()),
                    |elements| ValidatorList::try_from_iter(elements).map_err(S::Error::custom),
                )?
            }
        }

        deserializer.deserialize_seq(ValidatorListVisitor(PhantomData))
    }
}

impl<N: Unsigned> SszHash for ValidatorList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = match self.len_usize() {
            0 => {
                <MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash(Self::max_depth())
            }
            _ => (self.depth()..Self::max_depth())
                .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                .fold(
                    self.cache
                        .as_ref()
                        .expect("non-empty list has a cache")
                        .hash(&self.buf, self.len_usize(), 0),
                    hashing::hash_256_256,
                ),
        };

        mix_in_length(root, self.len_usize())
    }
}

impl<N: Unsigned> SszSize for ValidatorList<N> {
    const SIZE: ssz::Size = ssz::Size::Variable { minimum_size: 0 };
}

impl<N: Unsigned> SszWrite for ValidatorList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), ssz::WriteError> {
        write_list(bytes, self)
    }
}

impl<C, N: Unsigned> SszRead<C> for ValidatorList<N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
        read_list(saturating_usize::<N>(), context, bytes)
    }
}

impl<'list, N: Unsigned> IntoIterator for &'list ValidatorList<N> {
    type Item = Validator;
    type IntoIter = ValidatorListIter<'list>;

    fn into_iter(self) -> Self::IntoIter {
        self.buf.into_iter()
    }
}

impl<N: Unsigned, const SIZE: usize> TryFrom<[Validator; SIZE]> for ValidatorList<N> {
    type Error = ssz::ReadError;

    fn try_from(array: [Validator; SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_iter(array)
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use typenum::U16;

    use super::*;

    type TestValidatorList = ValidatorList<U16>;

    const LENGTH: usize = 10;

    fn test_pubkey(index: u64) -> PublicKeyBytes {
        PublicKeyBytes::from_low_u64_be(index.saturating_add(1))
    }

    fn test_list(pubkeys: impl IntoIterator<Item = PublicKeyBytes>) -> TestValidatorList {
        TestValidatorList::try_from_iter(pubkeys.into_iter().map(|pubkey| Validator {
            pubkey,
            ..Validator::default()
        }))
        .expect("the test list fits")
    }

    fn full_list() -> TestValidatorList {
        test_list((0..u64::try_from(LENGTH).expect("LENGTH fits")).map(test_pubkey))
    }

    #[test]
    fn restoring_a_cleared_prefix_reproduces_the_original_root() {
        let expected = full_list().hash_tree_root();

        let mut list = full_list();

        list.clear_pubkeys(7);

        // Warm the cache so that the restore has stale roots to invalidate.
        assert_ne!(list.hash_tree_root(), expected);

        list.restore_pubkeys(full_list().pubkeys())
            .expect("the source covers the cleared prefix");

        assert_eq!(list.hash_tree_root(), expected);
    }

    // Restoring an appended range keeps the cached roots below it, which is the
    // whole point of taking a range. They have to be the roots of keys that did
    // not move, or the state root comes out wrong with nothing to report it.
    #[test]
    fn restoring_an_appended_range_reproduces_the_original_root() {
        let expected = full_list().hash_tree_root();

        let mut list = test_list(
            (0..7)
                .map(test_pubkey)
                .chain(iter::repeat_n(PublicKeyBytes::zero(), 3)),
        );

        // Warm the cache so that the restore has stale roots to invalidate.
        assert_ne!(list.hash_tree_root(), expected);

        list.restore_pubkeys_in(full_list().pubkeys(), 7..LENGTH)
            .expect("the source covers the range");

        assert_eq!(list.hash_tree_root(), expected);
    }

    // The same, with the appended keys arriving one range at a time, the way a
    // chain of state diffs applies them.
    #[test]
    fn restoring_appended_ranges_one_at_a_time_reproduces_the_original_root() {
        let expected = full_list().hash_tree_root();

        let mut list = test_list((0..6).map(test_pubkey));

        for range in [6..8, 8..LENGTH] {
            for _ in range.clone() {
                list.push(Validator::default()).expect("the test list fits");
            }

            assert_ne!(list.hash_tree_root(), expected);

            list.restore_pubkeys_in(full_list().pubkeys(), range)
                .expect("the source covers the range");
        }

        assert_eq!(list.hash_tree_root(), expected);
    }

    // `invalidate_range` walks the tree once instead of once per index, so it
    // has to drop every root that invalidating the indices one by one would.
    // Dropping too few leaves a stale root behind with nothing to report it,
    // and the shapes that catch that are the ones straddling a subtree
    // boundary.
    #[test_case(0..1)]
    #[test_case(0..7)]
    #[test_case(0..LENGTH; "the whole list")]
    #[test_case(3..4)]
    #[test_case(3..9)]
    #[test_case(7..LENGTH)]
    #[test_case(LENGTH - 1..LENGTH; "the last validator")]
    fn invalidate_range_drops_every_stale_root(range: Range<usize>) {
        let mut list = full_list();

        // Warm the cache with the keys the list starts out with.
        list.hash_tree_root();

        // Replace the keys in `range` behind the cache's back: `RawValidatorList`
        // knows nothing about the cache, so nothing is invalidated yet.
        let replacements = test_list((100..110).map(test_pubkey));

        list.buf
            .restore_pubkeys_in(replacements.pubkeys(), range.clone())
            .expect("the source covers the range");

        let length = list.len_usize();

        list.cache
            .as_mut()
            .expect("the list is not empty")
            .invalidate_range(range.clone(), length);

        let expected = test_list((0..LENGTH).map(|index| {
            let index = u64::try_from(index).expect("index fits");

            if range.contains(&usize::try_from(index).expect("index fits")) {
                test_pubkey(index.saturating_add(100))
            } else {
                test_pubkey(index)
            }
        }))
        .hash_tree_root();

        assert_eq!(list.hash_tree_root(), expected);
    }
}
