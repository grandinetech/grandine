use core::{convert::Infallible, fmt, iter, ops::Range};
#[cfg(target_os = "zkvm")]
use std::slice::Iter as VectorIter;
use std::sync::Arc;

use derivative::Derivative;

use anyhow::Result;
use bls::PublicKeyBytes;
#[cfg(not(target_os = "zkvm"))]
use im::vector::Iter as VectorIter;
use once_cell::race::OnceBox;
use serde::{
    Deserialize, Serialize,
    de::{SeqAccess, Visitor},
};
use ssz::{
    BundleSize, H256, IndexError, MinimumBundleSize, PushError, SszHash, SszRead, SszSize,
    SszWrite, hashing, mix_in_length, read_list, write_list,
};
use std_ext::CopyExt;
use try_from_iterator::TryFromIterator;
use typenum::{U1, Unsigned};

use crate::{
    nonstandard::{PartialValidator, PubkeyList, RawValidatorList, ValidatorListIter},
    phase0::{
        containers::Validator,
        primitives::Gwei,
        validator_list::{CacheNode as MerkleTreeCacheNode, ValidatorList},
    },
    traits::SszValidatorList,
};

#[derive(Clone, Debug, Default, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct ProgressiveValidatorList {
    /// Validator memory representation, backing container.
    buf: RawValidatorList,

    /// Merkle root cache.
    #[derivative(PartialEq = "ignore")]
    cache: Option<Arc<CacheNode>>,
}

#[derive(Clone, Debug)]
struct CacheNode {
    root: OnceBox<H256>,
    left: Arc<MerkleTreeCacheNode>,
    right: Option<Arc<Self>>,
    height: u8,
}

impl CacheNode {
    fn empty_single(height: u8) -> Arc<Self> {
        Arc::new(Self {
            root: OnceBox::new(),
            left: MerkleTreeCacheNode::empty_leaf(),
            right: None,
            height,
        })
    }

    fn build_empty(length: usize, height: u8) -> Arc<Self> {
        let capacity = MinimumBundleSize::<Validator>::USIZE << height;
        let left_length = length.min(capacity);
        let right_length = length
            .checked_sub(left_length)
            .expect("left_length never exceeds length");

        Arc::new(Self {
            root: OnceBox::new(),
            left: MerkleTreeCacheNode::build_empty(left_length),
            right: (right_length > 0)
                .then(|| Self::build_empty(right_length, height.saturating_add(2))),
            height,
        })
    }

    fn push_leaf(self: &mut Arc<Self>, old_length: usize) {
        let capacity = MinimumBundleSize::<Validator>::USIZE << self.height;
        let node = Arc::make_mut(self);
        let height = node.height;

        node.root = OnceBox::new();

        if old_length < capacity {
            node.left.push_leaf(old_length);
            return;
        }

        let right_length = old_length
            .checked_sub(capacity)
            .expect("old_length >= capacity in this branch");

        match node.right.as_mut() {
            Some(right) => right.push_leaf(right_length),
            None => {
                assert_eq!(right_length, 0, "all subtrees before the last are full");
                node.right = Some(Self::empty_single(height.saturating_add(2)));
            }
        }
    }

    fn invalidate(self: &mut Arc<Self>, index: usize, length: usize) {
        let capacity = MinimumBundleSize::<Validator>::USIZE << self.height;
        let node = Arc::make_mut(self);

        node.root = OnceBox::new();

        if index < capacity {
            node.left.invalidate(index, length.min(capacity));
        } else {
            let right_index = index
                .checked_sub(capacity)
                .expect("index >= capacity in this branch");
            let right_length = length
                .checked_sub(capacity)
                .expect("capacity never exceeds length in this branch");

            node.right
                .as_mut()
                .expect("index below length implies an existing subtree")
                .invalidate(right_index, right_length);
        }
    }

    /// Invalidates every cached root that covers an index in `range`.
    fn invalidate_range(self: &mut Arc<Self>, range: Range<usize>, length: usize) {
        if range.is_empty() {
            return;
        }

        let capacity = MinimumBundleSize::<Validator>::USIZE << self.height;
        let node = Arc::make_mut(self);

        node.root = OnceBox::new();

        let left_length = length.min(capacity);

        node.left.invalidate_range(
            range.start.min(left_length)..range.end.min(left_length),
            left_length,
        );

        let right_length = length.saturating_sub(capacity);

        let right_range = range.start.saturating_sub(capacity)
            ..range.end.saturating_sub(capacity).min(right_length);

        if !right_range.is_empty() {
            node.right
                .as_mut()
                .expect("a range reaching past the capacity implies an existing subtree")
                .invalidate_range(right_range, right_length);
        }
    }

    fn hash(&self, buf: &RawValidatorList, len: usize, offset: usize) -> H256 {
        self.root
            .get_or_init(|| {
                let capacity = MinimumBundleSize::<Validator>::USIZE << self.height;
                let left_len = len.min(capacity);
                let right_len = len
                    .checked_sub(left_len)
                    .expect("left_len never exceeds len");

                let left_height =
                    <MinimumBundleSize<Validator> as BundleSize<Validator>>::depth_of_length(
                        left_len,
                    );

                let right_offset = offset
                    .checked_add(left_len)
                    .expect("offset + left_len never overflows usize");

                let left_hash = (left_height..self.height)
                    .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                    .fold(self.left.hash(buf, left_len, offset), hashing::hash_256_256);

                let right_hash = match self.right.as_ref() {
                    Some(node) => node.hash(buf, right_len, right_offset),
                    None => H256::zero(),
                };

                Box::new(hashing::hash_256_256(left_hash, right_hash))
            })
            .copy()
    }
}

impl ProgressiveValidatorList {
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
            None => self.cache = (length > 0).then(|| CacheNode::build_empty(length, 0)),
        }
    }
}

impl SszValidatorList for ProgressiveValidatorList {
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
        self.cache = (length > 0).then(|| CacheNode::build_empty(length, 0));
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

        self.buf.push(validator);

        match &mut self.cache {
            Some(cache) => cache.push_leaf(old_length),
            None => self.cache = Some(CacheNode::empty_single(0)),
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

impl FromIterator<Validator> for ProgressiveValidatorList {
    fn from_iter<T: IntoIterator<Item = Validator>>(iter: T) -> Self {
        let buf = iter.into_iter().collect::<RawValidatorList>();

        Self {
            cache: (buf.len_usize() > 0).then(|| CacheNode::build_empty(buf.len_usize(), 0)),

            buf,
        }
    }
}

impl TryFromIterator<Validator> for ProgressiveValidatorList {
    type Error = Infallible;

    fn try_from_iter(items: impl IntoIterator<Item = Validator>) -> Result<Self, Self::Error> {
        Ok(Self::from_iter(items))
    }
}

impl<'list> IntoIterator for &'list ProgressiveValidatorList {
    type Item = Validator;
    type IntoIter = ValidatorListIter<'list>;

    fn into_iter(self) -> Self::IntoIter {
        self.buf.into_iter()
    }
}

impl Serialize for ProgressiveValidatorList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self)
    }
}

impl<'de> Deserialize<'de> for ProgressiveValidatorList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValidatorListVisitor;

        impl<'de> Visitor<'de> for ValidatorListVisitor {
            type Value = ProgressiveValidatorList;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a progressive validator list")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                iter::from_fn(|| seq.next_element().transpose()).collect()
            }
        }

        deserializer.deserialize_seq(ValidatorListVisitor)
    }
}

impl SszHash for ProgressiveValidatorList {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = match self.cache.as_ref() {
            Some(cache) => cache.hash(&self.buf, self.len_usize(), 0),
            None => H256::zero(),
        };

        mix_in_length(root, self.len_usize())
    }
}

impl SszSize for ProgressiveValidatorList {
    const SIZE: ssz::Size = ssz::Size::Variable { minimum_size: 0 };
}

impl SszWrite for ProgressiveValidatorList {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), ssz::WriteError> {
        write_list(bytes, self)
    }
}

impl<C> SszRead<C> for ProgressiveValidatorList {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ssz::ReadError> {
        read_list(usize::MAX, context, bytes)
    }
}

impl<N: Unsigned> From<ValidatorList<N>> for ProgressiveValidatorList {
    fn from(value: ValidatorList<N>) -> Self {
        let buf = value.buf;

        Self {
            cache: (buf.len_usize() > 0).then(|| CacheNode::build_empty(buf.len_usize(), 0)),

            buf,
        }
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    // The progressive layout splits the list into subtrees of capacity
    // `MinimumBundleSize << height`, with `height` going up by two each time, so
    // a list this long spans several of them and the ranges below straddle
    // their boundaries.
    const LENGTH: usize = 40;

    fn test_pubkey(index: u64) -> PublicKeyBytes {
        PublicKeyBytes::from_low_u64_be(index.saturating_add(1))
    }

    fn test_list(pubkeys: impl IntoIterator<Item = PublicKeyBytes>) -> ProgressiveValidatorList {
        pubkeys
            .into_iter()
            .map(|pubkey| Validator {
                pubkey,
                ..Validator::default()
            })
            .collect()
    }

    fn full_list() -> ProgressiveValidatorList {
        test_list((0..u64::try_from(LENGTH).expect("LENGTH fits")).map(test_pubkey))
    }

    #[test]
    fn restoring_a_cleared_prefix_reproduces_the_original_root() {
        let expected = full_list().hash_tree_root();

        let mut list = full_list();

        list.clear_pubkeys(LENGTH - 3);

        // Warm the cache so that the restore has stale roots to invalidate.
        assert_ne!(list.hash_tree_root(), expected);

        list.restore_pubkeys(full_list().pubkeys())
            .expect("the source covers the cleared prefix");

        assert_eq!(list.hash_tree_root(), expected);
    }

    #[test]
    fn restoring_an_appended_range_reproduces_the_original_root() {
        let expected = full_list().hash_tree_root();

        let mut list = test_list(
            (0..u64::try_from(LENGTH - 3).expect("LENGTH fits"))
                .map(test_pubkey)
                .chain(iter::repeat_n(PublicKeyBytes::zero(), 3)),
        );

        // Warm the cache so that the restore has stale roots to invalidate.
        assert_ne!(list.hash_tree_root(), expected);

        list.restore_pubkeys_in(full_list().pubkeys(), LENGTH - 3..LENGTH)
            .expect("the source covers the range");

        assert_eq!(list.hash_tree_root(), expected);
    }

    #[test_case(0..1)]
    #[test_case(0..LENGTH; "the whole list")]
    #[test_case(0..21)]
    #[test_case(1..5; "the second subtree")]
    #[test_case(4..6; "across a subtree boundary")]
    #[test_case(3..37)]
    #[test_case(21..LENGTH)]
    #[test_case(LENGTH - 1..LENGTH; "the last validator")]
    fn invalidate_range_drops_every_stale_root(range: Range<usize>) {
        let mut list = full_list();

        // Warm the cache with the keys the list starts out with.
        list.hash_tree_root();

        // Replace the keys in `range` behind the cache's back: `RawValidatorList`
        // knows nothing about the cache, so nothing is invalidated yet.
        let replacements = test_list(
            (0..u64::try_from(LENGTH).expect("LENGTH fits"))
                .map(|index| test_pubkey(index.saturating_add(100))),
        );

        list.buf
            .restore_pubkeys_in(replacements.pubkeys(), range.clone())
            .expect("the source covers the range");

        let length = list.len_usize();

        list.cache
            .as_mut()
            .expect("the list is not empty")
            .invalidate_range(range.clone(), length);

        let expected = test_list((0..LENGTH).map(|index| {
            let key = u64::try_from(index).expect("index fits");

            if range.contains(&index) {
                test_pubkey(key.saturating_add(100))
            } else {
                test_pubkey(key)
            }
        }))
        .hash_tree_root();

        assert_eq!(list.hash_tree_root(), expected);
    }
}
