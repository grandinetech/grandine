use core::{fmt, iter, marker::PhantomData};
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
    traits::{SszValidatorList, SszValidatorListMut},
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

    fn partial_validator(&self, index: u64) -> Result<&PartialValidator, IndexError> {
        self.buf.partial_validator(index)
    }

    fn pubkeys(&self) -> &PubkeyList {
        self.buf.pubkeys()
    }

    fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.buf.partial_validators()
    }

    fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.buf.effective_balances()
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

impl<N: Unsigned> SszValidatorListMut for ValidatorList<N> {
    fn effective_balance_mut(&mut self, index: u64) -> Result<&mut u64, IndexError> {
        self.invalidate_index(
            index
                .try_into()
                .map_err(|_| IndexError::DoesNotFitInUsize { index })?,
        );

        self.buf.effective_balance_mut(index)
    }

    fn partial_validator_mut(&mut self, index: u64) -> Result<&mut PartialValidator, IndexError> {
        self.invalidate_index(
            index
                .try_into()
                .map_err(|_| IndexError::DoesNotFitInUsize { index })?,
        );

        self.buf.partial_validator_mut(index)
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

    fn restore_pubkeys(&mut self, pubkeys: &PubkeyList) -> Result<()> {
        self.buf.restore_pubkeys(pubkeys)?;

        let length = self.len_usize();
        self.cache = (length > 0).then(|| CacheNode::build_empty(length));

        Ok(())
    }

    fn clear_pubkeys(&mut self, count: usize) {
        self.buf.clear_pubkeys(count);
        let length = self.len_usize();
        self.cache = (length > 0).then(|| CacheNode::build_empty(length));
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
