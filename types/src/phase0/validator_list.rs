use core::{fmt, iter, marker::PhantomData};
use std::sync::Arc;

use anyhow::{Result, ensure};
use arithmetic::{NonZeroExt as _, U64Ext as _};
use bls::PublicKeyBytes;
use derivative::Derivative;
#[cfg(not(target_os = "zkvm"))]
use im::{Vector, vector::Iter as VectorIter};
use once_cell::race::OnceBox;
use serde::{
    Deserialize, Serialize,
    de::{Error as _, Visitor},
};
use ssz::{
    BundleSize, FitsInU64, H256, IndexError, MinimumBundleSize, PushError, SszHash, SszRead,
    SszSize, SszWrite, U1, hashing, mix_in_length, read_list, saturating_usize, write_list,
};
#[cfg(target_os = "zkvm")]
use std::{slice::Iter as VectorIter, vec::Vec as Vector};
use std_ext::CopyExt;
use try_from_iterator::TryFromIterator;
use typenum::Unsigned;

use crate::phase0::{
    containers::Validator,
    primitives::{Epoch, Gwei},
};

#[cfg(target_os = "zkvm")]
trait VectorExt<T> {
    fn push_back(&mut self, value: T);
    fn slice(&mut self, range: core::ops::Range<usize>) -> Self;
}

#[cfg(target_os = "zkvm")]
impl<T> VectorExt<T> for Vec<T> {
    fn push_back(&mut self, value: T) {
        self.push(value);
    }

    fn slice(&mut self, range: core::ops::Range<usize>) -> Self {
        // Mirror `im::Vector::slice`: remove `range` from `self` and return it as a new vector,
        // leaving the elements outside the range in `self`.
        self.drain(range).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialValidator {
    pub withdrawal_credentials: H256,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl From<&Validator> for PartialValidator {
    fn from(value: &Validator) -> Self {
        Self {
            withdrawal_credentials: value.withdrawal_credentials.copy(),
            slashed: value.slashed.copy(),
            activation_eligibility_epoch: value.activation_eligibility_epoch.copy(),
            activation_epoch: value.activation_epoch.copy(),
            exit_epoch: value.exit_epoch.copy(),
            withdrawable_epoch: value.withdrawable_epoch.copy(),
        }
    }
}

#[derive(Clone, Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct ValidatorList<N: Unsigned> {
    /// Validator public keys never change, so we keep them separately, to
    /// structurally share keys even if any other field changes.
    pubkeys: Vector<PublicKeyBytes>,

    /// Validator effective balances change very frequently, comparing to other
    /// fields, so we keep them separately, so that we don't have to clone every
    /// other field when only balance changes.
    effective_balances: Vector<Gwei>,

    /// Rest validator fields. These change rarely, so kept separately.
    items: Vector<PartialValidator>,

    /// Merkle root cache.
    #[derivative(PartialEq = "ignore")]
    cache: Option<Arc<CacheNode>>,

    phantom: PhantomData<N>,
}

#[derive(Clone, Debug)]
enum CacheNode {
    Leaf(OnceBox<H256>),
    Internal {
        root: OnceBox<H256>,
        left: Arc<Self>,
        right: Arc<Self>,
    },
}

impl CacheNode {
    fn empty_leaf() -> Arc<Self> {
        Arc::new(Self::Leaf(OnceBox::new()))
    }

    fn build_empty(length: usize) -> Arc<Self> {
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

    fn push_leaf(self: &mut Arc<Self>, old_length: usize) {
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

    fn invalidate(self: &mut Arc<Self>, index: usize, length: usize) {
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
}

impl<N: Unsigned> Default for ValidatorList<N> {
    fn default() -> Self {
        Self {
            pubkeys: Vector::new(),
            effective_balances: Vector::new(),
            items: Vector::new(),
            cache: None,
            phantom: PhantomData,
        }
    }
}

impl<N: Unsigned> ValidatorList<N> {
    pub fn get(&self, index: u64) -> Result<Validator, IndexError> {
        let index = self.validate_index(index)?;

        let pubkey = self.pubkeys.get(index).expect(
            "validator list invariant violated: \
                pubkey list is out of sync with current length",
        );
        let effective_balance = self.effective_balances.get(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );
        let partial_validator = self.items.get(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(Validator {
            pubkey: pubkey.copy(),
            withdrawal_credentials: partial_validator.withdrawal_credentials.copy(),
            effective_balance: effective_balance.copy(),
            slashed: partial_validator.slashed.copy(),
            activation_eligibility_epoch: partial_validator.activation_eligibility_epoch.copy(),
            activation_epoch: partial_validator.activation_epoch.copy(),
            exit_epoch: partial_validator.exit_epoch.copy(),
            withdrawable_epoch: partial_validator.withdrawable_epoch.copy(),
        })
    }

    pub fn pubkey(&self, index: u64) -> Result<&PublicKeyBytes, IndexError> {
        let index = self.validate_index(index)?;

        let pubkey = self.pubkeys.get(index).expect(
            "validator list invariant violated: \
                pubkey list is out of sync with current length",
        );

        Ok(pubkey)
    }

    pub fn pubkey_mut(&mut self, index: u64) -> Result<&mut PublicKeyBytes, IndexError> {
        let index = self.validate_index(index)?;

        self.invalidate_index(index);

        let pubkey = self.pubkeys.get_mut(index).expect(
            "validator list invariant violated: \
                pubkey list is out of sync with current length",
        );

        Ok(pubkey)
    }

    pub fn effective_balance(&self, index: u64) -> Result<u64, IndexError> {
        let index = self.validate_index(index)?;

        let effective_balance = self.effective_balances.get(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );

        Ok(effective_balance.copy())
    }

    pub fn effective_balance_mut(&mut self, index: u64) -> Result<&mut u64, IndexError> {
        let index = self.validate_index(index)?;

        self.invalidate_index(index);

        let effective_balance = self.effective_balances.get_mut(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );

        Ok(effective_balance)
    }

    pub fn partial_validator(&self, index: u64) -> Result<&PartialValidator, IndexError> {
        let index = self.validate_index(index)?;

        let partial_validator = self.items.get(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(partial_validator)
    }

    pub fn partial_validator_mut(
        &mut self,
        index: u64,
    ) -> Result<&mut PartialValidator, IndexError> {
        let index = self.validate_index(index)?;

        self.invalidate_index(index);

        let partial_validator = self.items.get_mut(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(partial_validator)
    }

    pub fn update_effective_balances<E>(
        &mut self,
        mut updater: impl FnMut(&PartialValidator, Gwei) -> Result<Gwei, E>,
    ) -> Result<(), E> {
        let len = self.len_usize();

        let Self {
            effective_balances,
            items,
            cache,
            ..
        } = self;

        for (index, (partial_validator, effective_balance)) in
            items.iter().zip(effective_balances.iter_mut()).enumerate()
        {
            let old_effective_balance = *effective_balance;
            let new_effective_balance = updater(partial_validator, old_effective_balance)?;

            if new_effective_balance == old_effective_balance {
                continue;
            }

            if let Some(cache) = cache.as_mut() {
                cache.invalidate(index, len);
            }

            *effective_balance = new_effective_balance;
        }

        Ok(())
    }

    #[must_use]
    pub const fn pubkeys(&self) -> &Vector<PublicKeyBytes> {
        &self.pubkeys
    }

    pub fn set_pubkeys(&mut self, pubkeys: &Vector<PublicKeyBytes>) -> Result<()> {
        let length = self.len_usize();

        ensure!(
            pubkeys.len() >= length,
            "pubkey list is shorter than validator count (expected at least {length}, got {})",
            pubkeys.len(),
        );

        let mut pubkeys = pubkeys.clone();
        let pubkeys = pubkeys.slice(0..length);

        self.pubkeys = pubkeys;

        self.cache = (length > 0).then(|| CacheNode::build_empty(length));

        Ok(())
    }

    pub fn clear_pubkeys(&mut self, count: usize) {
        let length = self.len_usize();
        let count = count.min(length);

        if count == 0 {
            return;
        }

        let mut pubkeys: Vector<PublicKeyBytes> =
            iter::repeat_n(PublicKeyBytes::zero(), count).collect();

        let mut tail = self.pubkeys.clone();

        #[cfg(not(target_os = "zkvm"))]
        pubkeys.append(tail.slice(count..length));
        #[cfg(target_os = "zkvm")]
        pubkeys.append(&mut tail.slice(count..length));

        self.pubkeys = pubkeys;

        self.cache = (length > 0).then(|| CacheNode::build_empty(length));
    }

    #[must_use]
    pub fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.items.iter()
    }

    #[must_use]
    pub fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.effective_balances.iter()
    }

    #[must_use]
    pub fn len_usize(&self) -> usize {
        self.pubkeys.len()
    }

    #[must_use]
    pub fn len_u64(&self) -> u64
    where
        N: FitsInU64,
    {
        self.len_usize()
            .try_into()
            .expect("the bound on N ensures that self.length fits in u64")
    }

    fn depth(&self) -> u8 {
        <MinimumBundleSize<Validator> as BundleSize<Validator>>::depth_of_length(self.len_usize())
    }

    fn max_depth() -> u8 {
        N::U64
            .ilog2_ceil()
            .saturating_sub(MinimumBundleSize::<Validator>::ilog2())
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "takes the validator by value to mirror the conventional collection \
                  push API, even though every field happens to be Copy"
    )]
    pub fn push(&mut self, validator: Validator) -> Result<(), PushError> {
        if self.len_usize() >= saturating_usize::<N>() {
            return Err(PushError::ListFull);
        }

        let old_length = self.len_usize();

        let Validator {
            pubkey,
            withdrawal_credentials,
            effective_balance,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        } = validator;

        self.items.push_back(PartialValidator {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        });
        self.pubkeys.push_back(pubkey);
        self.effective_balances.push_back(effective_balance);

        match &mut self.cache {
            Some(cache) => cache.push_leaf(old_length),
            None => self.cache = Some(CacheNode::empty_leaf()),
        }

        Ok(())
    }

    fn validate_index(&self, index: u64) -> Result<usize, IndexError> {
        let index = index
            .try_into()
            .map_err(|_| IndexError::DoesNotFitInUsize { index })?;

        if index >= self.len_usize() {
            return Err(IndexError::OutOfBounds {
                length: self.len_usize(),
                index,
            });
        }

        Ok(index)
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

    fn hash_node(&self, node: &CacheNode, len: usize, offset: usize) -> H256 {
        match node {
            CacheNode::Leaf(root) => root
                .get_or_init(|| {
                    let PartialValidator {
                        withdrawal_credentials,
                        slashed,
                        activation_eligibility_epoch,
                        activation_epoch,
                        exit_epoch,
                        withdrawable_epoch,
                    } = self
                        .items
                        .get(offset)
                        .expect(
                            "validator list invariant violated: \
                                partial validator list is out of sync with current length",
                        )
                        .copy();

                    let validator = Validator {
                        pubkey: self
                            .pubkeys
                            .get(offset)
                            .expect(
                                "validator list invariant violated: \
                                    pubkey list is out of sync with current length",
                            )
                            .copy(),
                        withdrawal_credentials,
                        effective_balance: self
                            .effective_balances
                            .get(offset)
                            .expect(
                                "validator list invariant violated: \
                                    effective balance list is out of sync with current length",
                            )
                            .copy(),
                        slashed,
                        activation_eligibility_epoch,
                        activation_epoch,
                        exit_epoch,
                        withdrawable_epoch,
                    };

                    Box::new(validator.hash_tree_root())
                })
                .copy(),
            CacheNode::Internal { root, left, right } => root
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

                    let left = self.hash_node(left, left_len, offset);
                    let right = self.hash_node(right, right_len, right_offset);

                    let right_hash = (right_height..left_height)
                        .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                        .fold(right, hashing::hash_256_256);

                    Box::new(hashing::hash_256_256(left, right_hash))
                })
                .copy(),
        }
    }
}

impl<N: Unsigned> TryFromIterator<Validator> for ValidatorList<N> {
    type Error = ssz::ReadError;

    fn try_from_iter(items: impl IntoIterator<Item = Validator>) -> Result<Self, Self::Error> {
        let mut iter = items
            .into_iter()
            .map(|validator| {
                (
                    PartialValidator {
                        withdrawal_credentials: validator.withdrawal_credentials,
                        slashed: validator.slashed,
                        activation_eligibility_epoch: validator.activation_eligibility_epoch,
                        activation_epoch: validator.activation_epoch,
                        exit_epoch: validator.exit_epoch,
                        withdrawable_epoch: validator.withdrawable_epoch,
                    },
                    (validator.pubkey, validator.effective_balance),
                )
            })
            .fuse();

        let (items, (pubkeys, effective_balances)): (Vector<_>, (Vector<_>, Vector<_>)) =
            iter.by_ref().take(saturating_usize::<N>()).unzip();

        if iter.next().is_some() {
            return Err(ssz::ReadError::ListTooLong {
                maximum: saturating_usize::<N>(),
                actual: saturating_usize::<N>()
                    .saturating_add(1)
                    .saturating_add(iter.count()),
            });
        }

        Ok(Self {
            cache: (!pubkeys.is_empty()).then(|| CacheNode::build_empty(pubkeys.len())),

            pubkeys,
            effective_balances,
            items,

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
                S: serde::de::SeqAccess<'de>,
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
                    self.hash_node(
                        self.cache.as_ref().expect("non-empty list has a cache"),
                        self.len_usize(),
                        0,
                    ),
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

pub struct ValidatorListIter<'a, N: Unsigned> {
    pubkeys: VectorIter<'a, PublicKeyBytes>,
    effective_balances: VectorIter<'a, Gwei>,
    items: VectorIter<'a, PartialValidator>,
    phantom: PhantomData<N>,
}

impl<N: Unsigned> Iterator for ValidatorListIter<'_, N> {
    type Item = Validator;

    fn next(&mut self) -> Option<Self::Item> {
        let pubkey = self.pubkeys.next()?;
        let effective_balance = self.effective_balances.next()?;
        let PartialValidator {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        } = self.items.next()?.copy();

        Some(Validator {
            pubkey: pubkey.copy(),
            withdrawal_credentials,
            effective_balance: effective_balance.copy(),
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pubkeys.size_hint()
    }
}

impl<N: Unsigned> ExactSizeIterator for ValidatorListIter<'_, N> {
    fn len(&self) -> usize {
        self.pubkeys.len()
    }
}

impl<'list, N: Unsigned> IntoIterator for &'list ValidatorList<N> {
    type Item = Validator;
    type IntoIter = ValidatorListIter<'list, N>;

    fn into_iter(self) -> Self::IntoIter {
        ValidatorListIter {
            pubkeys: self.pubkeys.iter(),
            effective_balances: self.effective_balances.iter(),
            items: self.items.iter(),
            phantom: PhantomData,
        }
    }
}

impl<N: Unsigned, const SIZE: usize> TryFrom<[Validator; SIZE]> for ValidatorList<N> {
    type Error = ssz::ReadError;

    fn try_from(array: [Validator; SIZE]) -> Result<Self, Self::Error> {
        Self::try_from_iter(array)
    }
}
