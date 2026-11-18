use core::{fmt, iter, marker::PhantomData, ops::Range};
#[cfg(target_os = "zkvm")]
use std::slice::Iter as VectorIter;
use std::sync::{Arc, OnceLock};

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
    nonstandard::{
        EffectiveBalanceList, PartialValidator, PartialValidatorList, PubkeyList, RawValidatorList,
        ValidatorListIter,
    },
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
    cache: Arc<CacheNode>,

    phantom: PhantomData<N>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CacheNode {
    root: OnceBox<H256>,
    children: OnceLock<(Arc<Self>, Arc<Self>)>,
}

impl CacheNode {
    fn children(&self) -> &(Arc<Self>, Arc<Self>) {
        self.children.get_or_init(Default::default)
    }

    fn unshare(self: &mut Arc<Self>) -> &mut (Arc<Self>, Arc<Self>) {
        self.children();

        let node = Arc::make_mut(self);

        node.root = OnceBox::new();

        node.children
            .get_mut()
            .expect("children are created before the node is copied")
    }

    pub(crate) fn push_leaf(self: &mut Arc<Self>, old_length: usize) {
        if old_length == 0 {
            *self = Arc::default();
            return;
        }

        if old_length.is_power_of_two() {
            *self = Arc::new(Self {
                root: OnceBox::new(),
                children: OnceLock::from((Arc::clone(self), Arc::default())),
            });

            return;
        }

        let left_length = old_length.next_power_of_two() / 2;
        let right_length = old_length
            .checked_sub(left_length)
            .expect("left_length never exceeds old_length");

        self.unshare().1.push_leaf(right_length);
    }

    pub(crate) fn invalidate(self: &mut Arc<Self>, index: usize, length: usize) {
        if length == 1 {
            *self = Arc::default();
            return;
        }

        let left_length = length.next_power_of_two() / 2;
        let (left, right) = self.unshare();

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

    /// Invalidates every cached root that covers an index in `range`.
    pub(crate) fn invalidate_range(self: &mut Arc<Self>, range: Range<usize>, length: usize) {
        if range.is_empty() {
            return;
        }

        if range == (0..length) {
            *self = Arc::default();
            return;
        }

        let left_length = length.next_power_of_two() / 2;
        let right_length = length
            .checked_sub(left_length)
            .expect("left_length never exceeds length");

        let (left, right) = self.unshare();

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

    pub(crate) fn hash(&self, buf: &RawValidatorList, len: usize, offset: usize) -> H256 {
        self.root
            .get_or_init(|| {
                if len == 1 {
                    let validator = buf
                        .get(offset.try_into().expect("offset doesn't fit in usize"))
                        .expect(
                            "validator list invariant violated: partial \
                                validator list is out of sync with current length",
                        );

                    return Box::new(validator.hash_tree_root());
                }

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

                let (left, right) = self.children();

                let left = left.hash(buf, left_len, offset);
                let right = right.hash(buf, right_len, right_offset);

                let right_hash = (right_height..left_height)
                    .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                    .fold(right, hashing::hash_256_256);

                Box::new(hashing::hash_256_256(left, right_hash))
            })
            .copy()
    }
}

impl<N: Unsigned> ValidatorList<N> {
    /// Wraps `buf`, which must hold no more than `N` validators.
    pub(crate) fn from_raw(buf: RawValidatorList) -> Self {
        Self {
            buf,
            cache: Arc::default(),
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn into_columns(self) -> (PubkeyList, EffectiveBalanceList, PartialValidatorList) {
        self.buf.into_columns()
    }

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

        self.cache.invalidate(index, len);
    }

    /// Invalidates the cached hashes of the validators in `range`.
    fn invalidate_pubkey_range(&mut self, range: Range<usize>) {
        let length = self.len_usize();

        self.cache.invalidate_range(range, length);
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
        self.cache = Arc::default();
    }

    fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.buf.partial_validators()
    }

    fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.buf.effective_balances()
    }

    fn columns(&self) -> (&PubkeyList, &EffectiveBalanceList, &PartialValidatorList) {
        self.buf.columns()
    }

    fn update_effective_balances(
        &mut self,
        updater: &mut dyn FnMut(&PartialValidator, Gwei) -> Result<Gwei, anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        self.buf.update_effective_balances(updater, |index, len| {
            self.cache.invalidate(index, len);
        })
    }

    fn push(&mut self, validator: Validator) -> Result<(), PushError> {
        let old_length = self.len_usize();

        if old_length.saturating_add(1) >= saturating_usize::<N>() {
            return Err(PushError::ListFull);
        }

        self.buf.push(validator);

        self.cache.push_leaf(old_length);

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
            buf,
            cache: Arc::default(),
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
            length => (self.depth()..Self::max_depth())
                .map(<MinimumBundleSize<Validator> as BundleSize<Validator>>::zero_hash)
                .fold(self.cache.hash(&self.buf, length, 0), hashing::hash_256_256),
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
pub(crate) mod tests {
    use std::{sync::Barrier, thread};

    use ssz::ContiguousList;
    use test_case::test_case;
    use typenum::{U16, U256};

    use super::*;

    type TestValidatorList = ValidatorList<U16>;
    type LargeValidatorList = ValidatorList<U256>;

    struct Rng(u64);

    impl Rng {
        fn value(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.value())
                .expect("u64 fits in usize")
                .checked_rem(bound)
                .expect("bound is positive")
        }

        fn range(&mut self, length: usize) -> Range<usize> {
            let first = self.below(length.saturating_add(1));
            let second = self.below(length.saturating_add(1));

            first.min(second)..first.max(second)
        }

        fn validator(&mut self) -> Validator {
            Validator {
                pubkey: PublicKeyBytes::from_low_u64_be(self.value() | 1),
                withdrawal_credentials: H256::from_low_u64_be(self.value()),
                effective_balance: self.value(),
                slashed: self.value() & 1 == 1,
                activation_eligibility_epoch: self.value(),
                activation_epoch: self.value(),
                exit_epoch: self.value(),
                withdrawable_epoch: self.value(),
            }
        }
    }

    fn assert_matches<L: SszValidatorList>(
        list: &L,
        mirror: &[Validator],
        oracle: &impl Fn(&[Validator]) -> H256,
    ) {
        assert_eq!(list.iter().collect::<Vec<_>>(), mirror);
        assert_eq!(list.hash_tree_root(), oracle(mirror));
    }

    fn apply_random_operation<L: SszValidatorList + Clone>(
        rng: &mut Rng,
        lists: &mut Vec<(L, Vec<Validator>)>,
        source: &PubkeyList,
        oracle: &impl Fn(&[Validator]) -> H256,
    ) {
        let pick = rng.below(lists.len());
        let operation = rng.below(9);

        if operation == 0 {
            if lists.len() < 6 {
                lists.push(lists[pick].clone());
            }

            return;
        }

        let (list, mirror) = &mut lists[pick];
        let length = mirror.len();

        match operation {
            1 if length > 0 => {
                let index = rng.below(length);
                let value = rng.value();
                let list_index = u64::try_from(index).expect("index fits in u64");

                *list
                    .effective_balance_mut(list_index)
                    .expect("index is in the list") = value;

                mirror[index].effective_balance = value;
            }
            2 if length > 0 => {
                let index = rng.below(length);
                let value = rng.value();
                let credentials = H256::from_low_u64_be(value);
                let list_index = u64::try_from(index).expect("index fits in u64");
                let partial = list
                    .partial_validator_mut(list_index)
                    .expect("index is in the list");

                partial.exit_epoch = value;
                partial.withdrawal_credentials = credentials;

                mirror[index].exit_epoch = value;
                mirror[index].withdrawal_credentials = credentials;
            }
            3 if length < source.len() => {
                let validator = rng.validator();

                list.push(validator.clone()).expect("the list has room");
                mirror.push(validator);
            }
            4 => {
                let range = rng.range(length);

                list.restore_pubkeys_in(source, range.clone())
                    .expect("the source covers the list");

                for index in range {
                    mirror[index].pubkey = *source.get(index).expect("source covers the list");
                }
            }
            5 => {
                let count = rng.below(length.saturating_add(1));

                list.clear_pubkeys(count);

                for validator in &mut mirror[..count] {
                    validator.pubkey = PublicKeyBytes::zero();
                }
            }
            6 => {
                let cleared = mirror
                    .iter()
                    .take_while(|validator| validator.pubkey.is_zero())
                    .count();

                if mirror[cleared..]
                    .iter()
                    .all(|validator| !validator.pubkey.is_zero())
                {
                    list.restore_pubkeys(source)
                        .expect("the source covers the list");

                    for (index, validator) in mirror[..cleared].iter_mut().enumerate() {
                        validator.pubkey = *source.get(index).expect("source covers the list");
                    }
                }
            }
            7 => {
                let mut index = 0;

                list.update_effective_balances(&mut |_, old| {
                    let new = if rng.below(4) == 0 { rng.value() } else { old };

                    mirror[index].effective_balance = new;
                    index = index.saturating_add(1);

                    Ok(new)
                })
                .expect("the updater never fails");
            }
            _ => assert_matches(list, mirror, oracle),
        }
    }

    pub fn assert_random_operations_match_oracle<L: SszValidatorList + Clone>(
        seed: u64,
        max_length: usize,
        build: impl Fn(Vec<Validator>) -> L,
        oracle: impl Fn(&[Validator]) -> H256,
    ) {
        let mut rng = Rng(seed);

        let source = build(
            (0..max_length.saturating_mul(2))
                .map(|_| rng.validator())
                .collect(),
        );

        for _ in 0..2000 {
            let length = rng.below(max_length.saturating_add(1));
            let mirror = (0..length).map(|_| rng.validator()).collect::<Vec<_>>();
            let mut lists = vec![(build(mirror.clone()), mirror)];

            for _ in 0..40 {
                apply_random_operation(&mut rng, &mut lists, source.pubkeys(), &oracle);
            }

            for (list, mirror) in &lists {
                assert_matches(list, mirror, &oracle);
            }
        }
    }

    pub fn assert_concurrent_clones_match_oracle<L: SszValidatorList + Clone + Send + Sync>(
        seed: u64,
        build: impl Fn(Vec<Validator>) -> L,
        oracle: impl Fn(&[Validator]) -> H256 + Sync,
    ) {
        const THREADS: u64 = 8;

        let mut rng = Rng(seed);

        for _ in 0..20 {
            let validators = (0..512).map(|_| rng.validator()).collect::<Vec<_>>();
            let base = build(validators.clone());
            let barrier = Barrier::new(THREADS.try_into().expect("THREADS fits in usize"));

            thread::scope(|scope| {
                for thread_index in 1..=THREADS {
                    let (base, validators, barrier, oracle) =
                        (&base, &validators, &barrier, &oracle);
                    let thread_seed = rng.value() | thread_index;

                    scope.spawn(move || {
                        let mut rng = Rng(thread_seed);
                        let mut list = base.clone();
                        let mut mirror = validators.clone();

                        barrier.wait();

                        for _ in 0..3 {
                            if thread_index & 1 == 0 {
                                let index = rng.below(mirror.len());
                                let value = rng.value();
                                let list_index = u64::try_from(index).expect("index fits in u64");

                                *list
                                    .effective_balance_mut(list_index)
                                    .expect("index is in the list") = value;

                                mirror[index].effective_balance = value;
                            }

                            assert_eq!(list.hash_tree_root(), oracle(&mirror));
                        }
                    });
                }
            });

            assert_eq!(base.hash_tree_root(), oracle(&validators));
        }
    }

    fn contiguous_list_root(validators: &[Validator]) -> H256 {
        ContiguousList::<Validator, U256>::try_from_iter(validators.iter().cloned())
            .expect("the validators fit")
            .hash_tree_root()
    }

    fn large_list(validators: Vec<Validator>) -> LargeValidatorList {
        LargeValidatorList::try_from_iter(validators).expect("the validators fit")
    }

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

    #[test]
    fn a_list_mutated_before_its_first_hash_matches_one_hashed_throughout() {
        let mut cold = test_list((0..6).map(test_pubkey));
        let mut warm = cold.clone();

        warm.hash_tree_root();

        for list in [&mut cold, &mut warm] {
            for _ in 6..LENGTH {
                list.push(Validator::default()).expect("the test list fits");
            }

            *list
                .effective_balance_mut(2)
                .expect("the list has a third validator") = 32;

            list.restore_pubkeys_in(full_list().pubkeys(), 6..LENGTH)
                .expect("the source covers the range");
        }

        let expected = TestValidatorList::try_from_iter((0..LENGTH).map(|index| Validator {
            pubkey: test_pubkey(u64::try_from(index).expect("index fits")),
            effective_balance: if index == 2 { 32 } else { 0 },
            ..Validator::default()
        }))
        .expect("the test list fits")
        .hash_tree_root();

        assert_eq!(cold.hash_tree_root(), expected);
        assert_eq!(warm.hash_tree_root(), expected);
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

        list.cache.invalidate_range(range.clone(), length);

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

    #[test]
    fn random_operations_on_clones_match_an_independent_merkleization() {
        assert_random_operations_match_oracle(
            0x9E37_79B9_7F4A_7C15,
            64,
            large_list,
            contiguous_list_root,
        );
    }

    #[test]
    fn clones_hashed_and_changed_concurrently_match_an_independent_merkleization() {
        assert_concurrent_clones_match_oracle(
            0xD1B5_4A32_D192_ED03,
            |validators| {
                ValidatorList::<typenum::U1024>::try_from_iter(validators)
                    .expect("the validators fit")
            },
            |validators| {
                ContiguousList::<Validator, typenum::U1024>::try_from_iter(
                    validators.iter().cloned(),
                )
                .expect("the validators fit")
                .hash_tree_root()
            },
        );
    }

    #[test]
    fn a_clone_shares_the_subtrees_it_did_not_change() {
        let original = test_list((0..8).map(test_pubkey));
        let mut clone = original.clone();

        assert!(Arc::ptr_eq(&original.cache, &clone.cache));

        *clone
            .effective_balance_mut(7)
            .expect("the list has an eighth validator") = 32;

        let (original_left, original_right) = original.cache.children();
        let (clone_left, clone_right) = clone.cache.children();

        assert!(!Arc::ptr_eq(&original.cache, &clone.cache));
        assert!(Arc::ptr_eq(original_left, clone_left));
        assert!(!Arc::ptr_eq(original_right, clone_right));
        assert!(original_left.root.get().is_none());

        clone.hash_tree_root();

        assert!(original_left.root.get().is_some());
        assert!(original.cache.root.get().is_none());
        assert!(original_right.root.get().is_none());
    }

    #[test]
    fn a_clone_shares_the_old_tree_after_pushing_past_a_power_of_two() {
        let original = test_list((0..4).map(test_pubkey));
        let mut clone = original.clone();

        clone
            .push(Validator::default())
            .expect("the test list fits");
        clone
            .push(Validator::default())
            .expect("the test list fits");

        assert!(Arc::ptr_eq(&original.cache, &clone.cache.children().0));

        clone.hash_tree_root();

        assert!(original.cache.root.get().is_some());
    }

    #[test]
    fn restoring_a_whole_unhashed_list_allocates_no_tree() {
        let mut list = full_list();

        list.clear_pubkeys(LENGTH);

        list.restore_pubkeys(full_list().pubkeys())
            .expect("the source covers the cleared prefix");

        assert!(list.cache.children.get().is_none());
        assert_eq!(list.hash_tree_root(), full_list().hash_tree_root());
    }

    #[test]
    fn restoring_part_of_a_list_keeps_the_roots_outside_the_range() {
        let list_source = full_list();
        let mut list = full_list();

        list.hash_tree_root();

        list.restore_pubkeys_in(list_source.pubkeys(), 0..1)
            .expect("the source covers the range");

        assert!(list.cache.root.get().is_none());
        assert!(list.cache.children().1.root.get().is_some());
    }

    #[test]
    fn clones_of_an_empty_list_do_not_share_their_first_leaf() {
        let empty = TestValidatorList::default();
        let mut first = empty.clone();
        let mut second = empty;

        first
            .push(Validator {
                pubkey: test_pubkey(1),
                ..Validator::default()
            })
            .expect("the test list fits");
        second
            .push(Validator {
                pubkey: test_pubkey(2),
                ..Validator::default()
            })
            .expect("the test list fits");

        assert_eq!(
            first.hash_tree_root(),
            test_list([test_pubkey(1)]).hash_tree_root(),
        );
        assert_eq!(
            second.hash_tree_root(),
            test_list([test_pubkey(2)]).hash_tree_root(),
        );
    }
}
