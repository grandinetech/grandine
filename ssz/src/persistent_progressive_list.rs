#![allow(clippy::type_complexity)]
#![allow(clippy::assertions_on_result_states)]
use arithmetic::NonZeroExt as _;
use core::{
    cmp::Ordering,
    convert::AsRef,
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
};
use derivative::Derivative;
use ethereum_types::H256;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use std_ext::ArcExt as _;
use triomphe::Arc;
use try_from_iterator::TryFromIterator;
use typenum::{U1, Unsigned};

use crate::{
    BundleSize, Hc, IndexError, MerkleElements, MinimumBundleSize, PushError, ReadError, Size,
    SszHash, SszList, SszListMut, SszRead, SszSize, SszWrite, WriteError,
    iter::ExactSize,
    merkle_tree,
    persistent_list::{
        Leaves as MerkleTreeLeaves, LeavesMut as MerkleTreeLeavesMut, Node as MerkleTreeNode,
        PersistentList,
    },
    shared,
};

type PrettyBigU = typenum::U4294967296;

type Height = u8;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Default(bound = "")
)]
pub struct PersistentProgressiveList<T: SszHash, B = MinimumBundleSize<T>> {
    root: Option<Arc<Hc<Node<T, B>>>>,
    length: usize,
}

impl<T: SszHash, B> PersistentProgressiveList<T, B> {
    const fn validate_length(actual: usize) -> Result<(), ReadError> {
        let maximum = shared::saturating_usize::<PrettyBigU>();

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        Ok(())
    }
}

impl<T, B> TryFromIterator<T> for PersistentProgressiveList<T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Error = ReadError;

    // Like `PersistentList::try_from_iter`, this does not deduplicate consecutive nodes.
    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let mut elements = elements.into_iter();
        let mut subtrees_with_heights = vec![];
        let mut length: usize = 0;
        let mut height: Height = 0;

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE
                .checked_shl(height.into())
                .unwrap_or(usize::MAX);

            let Some((subtree, count)) = Subtree::build(&mut elements, capacity, height) else {
                break;
            };

            length = length.saturating_add(count);
            subtrees_with_heights.push((subtree, height));

            if count < capacity {
                break;
            }

            height = height.saturating_add(2);
        }

        Self::validate_length(length)?;

        let mut root = None;

        for (left, height) in subtrees_with_heights.into_iter().rev() {
            root = Some(Hc::arc(Node {
                left,
                right: root,
                height,
            }));
        }

        Ok(Self { root, length })
    }
}

// The trees have different shapes (and possibly different bundle sizes),
// so no structural sharing is possible and the elements have to be cloned.
impl<T, N, B, B2> From<&PersistentList<T, N, B2>> for PersistentProgressiveList<T, B>
where
    T: SszHash + Clone,
    N: Unsigned,
    B: BundleSize<T>,
    B2: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from(list: &PersistentList<T, N, B2>) -> Self {
        Self::try_from_iter(list.into_iter().cloned())
            .expect("both lists have the same maximum length")
    }
}

impl<T, N, B, B2> From<PersistentList<T, N, B2>> for PersistentProgressiveList<T, B>
where
    T: SszHash + Clone,
    N: Unsigned,
    B: BundleSize<T>,
    B2: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from(list: PersistentList<T, N, B2>) -> Self {
        Self::from(&list)
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
enum Subtree<T: SszHash, B> {
    Narrow(Arc<Hc<MerkleTreeNode<T, MinimumBundleSize<T>>>>),
    Wide(Arc<Hc<MerkleTreeNode<T, B>>>),
}

impl<T, B> Subtree<T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn shift() -> Height {
        B::ilog2().saturating_sub(MinimumBundleSize::<T>::ilog2())
    }

    fn is_wide(height: Height) -> bool {
        height >= Self::shift()
    }

    fn build(
        elements: &mut impl Iterator<Item = T>,
        capacity: usize,
        height: Height,
    ) -> Option<(Self, usize)> {
        if Self::is_wide(height) {
            MerkleTreeNode::build(elements, capacity).map(|(node, count)| (Self::Wide(node), count))
        } else {
            MerkleTreeNode::build(elements, capacity)
                .map(|(node, count)| (Self::Narrow(node), count))
        }
    }

    fn single(element: T, height: Height) -> Self {
        if Self::is_wide(height) {
            Self::Wide(Hc::arc(MerkleTreeNode::leaf([element])))
        } else {
            Self::Narrow(Hc::arc(MerkleTreeNode::leaf([element])))
        }
    }

    fn get(&self, index: usize) -> &T {
        match self {
            Self::Narrow(node) => node.as_ref().as_ref().get(index),
            Self::Wide(node) => node.as_ref().as_ref().get(index),
        }
    }

    fn get_mut(&mut self, index: usize) -> &mut T
    where
        T: Clone,
    {
        match self {
            Self::Narrow(node) => node.make_mut().as_mut().get_mut(index),
            Self::Wide(node) => node.make_mut().as_mut().get_mut(index),
        }
    }

    fn push(&mut self, element: T, index: usize)
    where
        T: Clone,
    {
        match self {
            Self::Narrow(node) => node.make_mut().as_mut().push(element, index),
            Self::Wide(node) => node.make_mut().as_mut().push(element, index),
        }
    }

    fn update(&self, updater: &mut impl FnMut(&mut T)) -> Option<Self>
    where
        T: Clone + PartialEq,
    {
        match self {
            Self::Narrow(node) => node.update(updater).map(Self::Narrow),
            Self::Wide(node) => node.update(updater).map(Self::Wide),
        }
    }

    fn root_at(&self, spine_height: Height) -> H256
    where
        T: SszWrite,
        B: MerkleElements<T>,
        MinimumBundleSize<T>: MerkleElements<T>,
    {
        match self {
            Self::Narrow(node) => node.root_at(spine_height),
            Self::Wide(node) => node.root_at(spine_height.saturating_sub(Self::shift())),
        }
    }

    fn leaves(&self) -> SubtreeLeaves<'_, T, B> {
        match self {
            Self::Narrow(node) => {
                SubtreeLeaves::Narrow(MerkleTreeLeaves::new(node.as_ref().as_ref()))
            }
            Self::Wide(node) => SubtreeLeaves::Wide(MerkleTreeLeaves::new(node.as_ref().as_ref())),
        }
    }

    fn leaves_mut(&mut self) -> SubtreeLeavesMut<'_, T, B>
    where
        T: Clone,
    {
        match self {
            Self::Narrow(node) => {
                SubtreeLeavesMut::Narrow(MerkleTreeLeavesMut::new(node.make_mut().as_mut()))
            }
            Self::Wide(node) => {
                SubtreeLeavesMut::Wide(MerkleTreeLeavesMut::new(node.make_mut().as_mut()))
            }
        }
    }
}

pub enum SubtreeLeaves<'list, T: SszHash, B> {
    Narrow(MerkleTreeLeaves<'list, T, MinimumBundleSize<T>>),
    Wide(MerkleTreeLeaves<'list, T, B>),
}

impl<'list, T: SszHash, B> Iterator for SubtreeLeaves<'list, T, B> {
    type Item = &'list [T];

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Narrow(leaves) => leaves.next(),
            Self::Wide(leaves) => leaves.next(),
        }
    }
}

impl<T: SszHash, B> FusedIterator for SubtreeLeaves<'_, T, B> {}

pub enum SubtreeLeavesMut<'list, T: SszHash, B> {
    Narrow(MerkleTreeLeavesMut<'list, T, MinimumBundleSize<T>>),
    Wide(MerkleTreeLeavesMut<'list, T, B>),
}

impl<'list, T: SszHash + Clone, B> Iterator for SubtreeLeavesMut<'list, T, B> {
    type Item = &'list mut [T];

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Narrow(leaves) => leaves.next(),
            Self::Wide(leaves) => leaves.next(),
        }
    }
}

impl<T: SszHash + Clone, B> FusedIterator for SubtreeLeavesMut<'_, T, B> {}

impl<T, B> SszList<T> for PersistentProgressiveList<T, B>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    B: BundleSize<T> + MerkleElements<T> + Send + Sync,
    MinimumBundleSize<T>: BundleSize<T> + MerkleElements<T> + Send + Sync,
{
    fn len_usize(&self) -> usize {
        self.length
    }

    fn len_u64(&self) -> u64 {
        u64::try_from(self.length).expect("list length fits in u64")
    }

    fn get(&self, index: u64) -> Result<&T, IndexError> {
        let mut index = shared::validate_index(self.length, index)?;

        let mut spine = self
            .root
            .as_deref()
            .expect("the length check in validate_index ensures that self.root is Some")
            .as_ref();

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE << spine.height;

            if let Some(new_index) = index.checked_sub(capacity) {
                index = new_index;

                spine = spine
                    .right
                    .as_deref()
                    .expect("the length check in validate_index ensures that the index falls within an existing subtree")
                    .as_ref();
            } else {
                break;
            }
        }

        Ok(spine.left.get(index))
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = &'a T> + 'a> {
        Box::new(self.into_iter())
    }

    fn clone_boxed(&self) -> Box<dyn SszList<T>>
    where
        T: Clone + 'static,
    {
        Box::new(self.clone())
    }
}

impl<T, B> SszListMut<T> for PersistentProgressiveList<T, B>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    B: BundleSize<T> + MerkleElements<T> + Send + Sync,
    MinimumBundleSize<T>: BundleSize<T> + MerkleElements<T> + Send + Sync,
{
    fn get_mut(&mut self, index: u64) -> Result<&mut T, IndexError>
    where
        T: Clone,
    {
        let mut index = shared::validate_index(self.length, index)?;

        let mut spine = self
            .root
            .as_mut()
            .expect("the length check in validate_index ensures that self.root is Some")
            .make_mut()
            .as_mut();

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE << spine.height;

            if let Some(new_index) = index.checked_sub(capacity) {
                index = new_index;

                spine = spine
                    .right
                    .as_mut()
                    .expect("the length check in validate_index ensures that the index falls within an existing subtree")
                    .make_mut()
                    .as_mut();
            } else {
                break;
            }
        }

        Ok(spine.left.get_mut(index))
    }

    fn push(&mut self, element: T) -> Result<(), PushError>
    where
        T: Clone,
    {
        let length_u64: u64 = self
            .length
            .try_into()
            .expect("PersistentProgressiveList length counter should fit to u64");

        match length_u64.cmp(&PrettyBigU::U64) {
            Ordering::Less => {}
            Ordering::Equal => return Err(PushError::ListFull),
            Ordering::Greater => unreachable!("case above prevents list from being overfilled"),
        }

        match self.root.as_mut() {
            Some(node) => {
                // The index of the new element within the subtree it falls into.
                // All subtrees before it are full, exactly like in `get`.
                let mut index = self.length;
                let mut spine = node.make_mut().as_mut();

                loop {
                    let capacity = MinimumBundleSize::<T>::USIZE << spine.height;

                    if index < capacity {
                        spine.left.push(element, index);
                        break;
                    }

                    index = index
                        .checked_sub(capacity)
                        .ok_or(PushError::IndexOutOfBounds)?;

                    if spine.right.is_none() {
                        assert_eq!(index, 0, "all subtrees before the last are full");

                        spine.right =
                            Some(Node::arc_single(element, spine.height.saturating_add(2)));

                        break;
                    }

                    spine = spine
                        .right
                        .as_mut()
                        .expect("the case above ensures that spine.right is Some")
                        .make_mut()
                        .as_mut();
                }
            }
            None => self.root = Some(Node::arc_single(element, 0)),
        }

        self.length = self.length.saturating_add(1);

        Ok(())
    }

    fn update(&mut self, updater: &mut dyn FnMut(&mut T))
    where
        T: Clone + PartialEq,
    {
        if let Some(node) = self.root.as_mut()
            && let Some(new_node) = node.update(&mut |element| updater(element))
        {
            *node = new_node;
        }
    }

    fn try_assign_from_iter(&mut self, iter: &mut dyn Iterator<Item = T>) -> Result<(), ReadError> {
        *self = Self::try_from_iter(iter)?;
        Ok(())
    }

    fn iter_mut<'a>(&'a mut self) -> Box<dyn ExactSizeIterator<Item = &'a mut T> + 'a>
    where
        T: Clone,
    {
        Box::new(self.into_iter())
    }
}

impl<'list, T, B> IntoIterator for &'list PersistentProgressiveList<T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = &'list T;
    type IntoIter = ExactSize<Flatten<Leaves<'list, T, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let leaves = Leaves {
            node: self.root.as_deref().map(AsRef::as_ref),
        };

        ExactSize::new(leaves.flatten(), self.length)
    }
}

impl<'list, T, B> IntoIterator for &'list mut PersistentProgressiveList<T, B>
where
    T: SszHash + Clone,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = &'list mut T;
    type IntoIter = ExactSize<Flatten<LeavesMut<'list, T, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let leaves = LeavesMut {
            node: self.root.as_mut().map(|node| node.make_mut().as_mut()),
        };

        ExactSize::new(leaves.flatten(), self.length)
    }
}

impl<T, B> Debug for PersistentProgressiveList<T, B>
where
    T: Debug + SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.debug_list().entries(self).finish()
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
struct Node<T: SszHash, B> {
    left: Subtree<T, B>,
    right: Option<Arc<Hc<Self>>>,
    height: Height,
}

impl<T, B> SszHash for Node<T, B>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
    MinimumBundleSize<T>: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let left_root = self.left.root_at(self.height);

        let right_root = match self.right.as_ref() {
            Some(node) => node.hash_tree_root(),
            None => H256::zero(),
        };

        hashing::hash_256_256(left_root, right_root)
    }
}

impl<T, B> Node<T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    // Construct a spine node whose subtree holds a single element.
    fn arc_single(element: T, height: Height) -> Arc<Hc<Self>> {
        Hc::arc(Self {
            left: Subtree::single(element, height),
            right: None,
            height,
        })
    }

    // Mutably borrowing an `FnMut` closure inside a recursive function causes infinite recursion
    // during monomorphization. Borrowing it outside and passing the reference prevents that.
    fn update(&self, updater: &mut impl FnMut(&mut T)) -> Option<Arc<Hc<Self>>>
    where
        T: Clone + PartialEq,
    {
        let new_left = self.left.update(updater);
        let new_right = self.right.as_ref().map(|right| right.update(updater));

        match (new_left, new_right) {
            (None, None | Some(None)) => None,
            (new_left, new_right) => {
                let left = new_left.unwrap_or_else(|| self.left.clone());

                let right = match new_right {
                    Some(Some(arc)) => Some(arc),
                    Some(None) => self.right.clone(),
                    None => None,
                };

                Some(Hc::arc(Self {
                    left,
                    right,
                    height: self.height,
                }))
            }
        }
    }
}

pub struct Leaves<'list, T: SszHash, B> {
    node: Option<&'list Node<T, B>>,
}

impl<'list, T, B> Iterator for Leaves<'list, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = Flatten<SubtreeLeaves<'list, T, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;

        self.node = node.right.as_deref().map(AsRef::as_ref);

        Some(node.left.leaves().flatten())
    }
}

impl<T, B> FusedIterator for Leaves<'_, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
}

// Like `MerkleTreeLeavesMut`, this clones `right` spine nodes earlier than needed.
pub struct LeavesMut<'list, T: SszHash, B> {
    node: Option<&'list mut Node<T, B>>,
}

impl<'list, T, B> Iterator for LeavesMut<'list, T, B>
where
    T: SszHash + Clone,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = Flatten<SubtreeLeavesMut<'list, T, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;

        self.node = node.right.as_mut().map(|node| node.make_mut().as_mut());

        Some(node.left.leaves_mut().flatten())
    }
}

impl<T, B> FusedIterator for LeavesMut<'_, T, B>
where
    T: SszHash + Clone,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
}

impl<'de, T, B> Deserialize<'de> for PersistentProgressiveList<T, B>
where
    T: Deserialize<'de> + SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PersistentProgressiveListVisitor<T, B>(PhantomData<(T, B)>);

        impl<'de, T, B> Visitor<'de> for PersistentProgressiveListVisitor<T, B>
        where
            T: Deserialize<'de> + SszHash,
            B: BundleSize<T>,
            MinimumBundleSize<T>: BundleSize<T>,
        {
            type Value = PersistentProgressiveList<T, B>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(
                    formatter,
                    "a list of length up to {}",
                    shared::saturating_usize::<PrettyBigU>(),
                )
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                itertools::process_results(
                    core::iter::from_fn(|| seq.next_element().transpose()),
                    |elements| {
                        PersistentProgressiveList::try_from_iter(elements).map_err(S::Error::custom)
                    },
                )?
            }
        }

        deserializer.deserialize_seq(PersistentProgressiveListVisitor(PhantomData))
    }
}

impl<T, B> Serialize for PersistentProgressiveList<T, B>
where
    T: Serialize + SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self)
    }
}

impl<T: SszSize + SszHash, B> SszSize for PersistentProgressiveList<T, B> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<T, B> SszHash for PersistentProgressiveList<T, B>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
    MinimumBundleSize<T>: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = match self.root.as_ref() {
            Some(node) => node.hash_tree_root(),
            None => H256::zero(),
        };

        merkle_tree::mix_in_length(root, self.length)
    }
}

impl<T, B> SszWrite for PersistentProgressiveList<T, B>
where
    T: SszWrite + SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self)
    }
}

impl<C, T, B> SszRead<C> for PersistentProgressiveList<T, B>
where
    T: SszRead<C> + SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        shared::read_list(shared::saturating_usize::<PrettyBigU>(), context, bytes)
    }
}

#[cfg(test)]
mod tests {
    use typenum::{U16, U64, U256};

    use crate::ProgressiveList;

    use super::*;

    type TestList = PersistentProgressiveList<u64, U64>;
    type ReferenceList = ProgressiveList<u64>;

    type BigList = PersistentProgressiveList<u64, U64>;
    type BigReferenceList = ProgressiveList<u64>;

    type UnpackedList = PersistentProgressiveList<H256, U64>;
    type UnpackedReferenceList = ProgressiveList<H256>;

    // Lengths up to 300 cover the boundaries of the first several subtrees,
    // whose capacities in elements are 4, 16, 64 and 256 for `u64`.
    const LENGTHS: core::ops::Range<u64> = 0..300;

    #[test]
    fn roots_match_the_reference_for_every_bundle_size() {
        fn check<B: BundleSize<u64> + MerkleElements<u64>>(width: &str) {
            for length in LENGTHS {
                let persistent = PersistentProgressiveList::<u64, B>::try_from_iter(0..length)
                    .expect("length is below the maximum");
                let reference =
                    ReferenceList::try_from_iter(0..length).expect("length is below the maximum");

                assert_eq!(
                    persistent.hash_tree_root(),
                    reference.hash_tree_root(),
                    "hash_tree_root mismatch at length {length} with bundle {width}",
                );

                assert!(
                    persistent.into_iter().copied().eq(0..length),
                    "elements mismatch at length {length} with bundle {width}",
                );
            }
        }

        check::<MinimumBundleSize<u64>>("minimum");
        check::<U16>("16");
        check::<U64>("64");
        check::<U256>("256");
    }

    #[test]
    fn try_from_iter_matches_progressive_list_root() {
        for length in LENGTHS {
            let persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");
            let reference =
                ReferenceList::try_from_iter(0..length).expect("length is below the maximum");

            assert_eq!(persistent.len_u64(), length);

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch at length {length}",
            );
        }
    }

    #[test]
    fn get_returns_every_element() {
        for length in LENGTHS {
            let persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            for index in 0..length {
                let element = persistent.get(index).expect("index is within bounds");

                assert_eq!(
                    *element, index,
                    "get mismatch at length {length}, index {index}"
                );
            }

            assert!(persistent.get(length).is_err());
            assert!(persistent.iter().copied().eq(0..length));
        }
    }

    #[test]
    fn get_mut_updates_hash_tree_root() {
        for length in LENGTHS.skip(1) {
            let mut persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            // Share all nodes with a clone to exercise copy-on-write.
            let original = persistent.clone();

            let index = length / 2;

            *persistent.get_mut(index).expect("index is within bounds") = u64::MAX;

            let reference = ReferenceList::try_from_iter(
                (0..length).map(|element| if element == index { u64::MAX } else { element }),
            )
            .expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch after get_mut at length {length}",
            );

            assert!(original.iter().copied().eq(0..length));
        }
    }

    #[test]
    fn get_and_hashing_work_at_subtree_boundaries() {
        // Subtree capacities in elements are 4, 16, 64, 256, 1024 and 4096 for `u64`,
        // so these lengths exercise the first 6 spine nodes and both edges of each boundary.
        let lengths = [1_u64, 4, 16, 64, 256, 1024, 4096]
            .into_iter()
            .flat_map(|boundary| [boundary - 1, boundary, boundary + 1]);

        for length in lengths {
            let persistent =
                BigList::try_from_iter(0..length).expect("length is below the maximum");
            let reference =
                BigReferenceList::try_from_iter(0..length).expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch at length {length}",
            );

            for index in [0, length / 2, length.saturating_sub(1)] {
                if index < length {
                    let element = persistent.get(index).expect("index is within bounds");

                    assert_eq!(
                        *element, index,
                        "get mismatch at length {length}, index {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn get_and_hashing_work_far_out_on_the_spine() {
        for length in [5_000_u64, 20_000, 100_000] {
            let persistent =
                BigList::try_from_iter(0..length).expect("length is below the maximum");
            let reference =
                BigReferenceList::try_from_iter(0..length).expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch at length {length}",
            );

            for index in [0, 1, length / 3, length / 2, length - 1] {
                let element = persistent.get(index).expect("index is within bounds");

                assert_eq!(
                    *element, index,
                    "get mismatch at length {length}, index {index}",
                );
            }
        }
    }

    #[test]
    fn push_matches_try_from_iter_far_out_on_the_spine() {
        let length = 5_000_u64;
        let mut pushed = BigList::default();

        for element in 0..length {
            pushed.push(element).expect("list is unbounded");
        }

        let built = BigList::try_from_iter(0..length).expect("length is below the maximum");

        assert_eq!(pushed.hash_tree_root(), built.hash_tree_root());
        assert_eq!(pushed, built);
        assert!(pushed.into_iter().copied().eq(0..length));
    }

    #[test]
    fn get_and_hashing_work_with_unpacked_elements() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..70 {
            let persistent = UnpackedList::try_from_iter((0..length).map(element))
                .expect("length is below the maximum");
            let reference = UnpackedReferenceList::try_from_iter((0..length).map(element))
                .expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch at length {length}",
            );

            for index in 0..length {
                let actual = persistent.get(index).expect("index is within bounds");

                assert_eq!(
                    *actual,
                    element(index),
                    "get mismatch at length {length}, index {index}",
                );
            }
        }
    }

    #[test]
    fn get_mut_invalidates_cached_roots() {
        for length in [1_u64, 5, 20, 100, 300] {
            let mut persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            let original = persistent.clone();
            let original_root = original.hash_tree_root();

            // Populate the root caches of all shared nodes before mutating.
            assert_eq!(persistent.hash_tree_root(), original_root);

            let mutated_indices = [0, length / 2, length - 1];

            for index in mutated_indices {
                *persistent.get_mut(index).expect("index is within bounds") =
                    index.saturating_add(1000);
            }

            let reference = ReferenceList::try_from_iter((0..length).map(|element| {
                if mutated_indices.contains(&element) {
                    element.saturating_add(1000)
                } else {
                    element
                }
            }))
            .expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch after get_mut at length {length}",
            );

            assert_eq!(
                original.hash_tree_root(),
                original_root,
                "mutation leaked into a structurally shared clone at length {length}",
            );
        }
    }

    #[test]
    fn get_mut_round_trips_every_element() {
        for length in [1_u64, 4, 17, 64, 100] {
            let mut persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            for index in 0..length {
                let element = persistent.get_mut(index).expect("index is within bounds");

                assert_eq!(
                    *element, index,
                    "get_mut mismatch at length {length}, index {index}"
                );

                *element = index.saturating_add(1000);
            }

            assert!(
                persistent
                    .iter()
                    .copied()
                    .eq(1000..length.saturating_add(1000))
            );
        }
    }

    #[test]
    fn iter_mut_visits_and_updates_every_element() {
        for length in [0_u64, 1, 4, 17, 64, 100, 300] {
            let mut persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            // Share all nodes with a clone to exercise copy-on-write.
            let original = persistent.clone();
            let original_root = original.hash_tree_root();

            let mut iterator = persistent.iter_mut();

            assert_eq!(Ok(iterator.len()), usize::try_from(length));

            for expected in 0..length {
                let element = iterator.next().expect("iterator yields length elements");

                assert_eq!(*element, expected, "iter_mut mismatch at length {length}");

                *element = expected.saturating_add(1000);
            }

            assert!(iterator.next().is_none());

            drop(iterator);

            let reference = ReferenceList::try_from_iter((0..length).map(|element| element + 1000))
                .expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch after iter_mut at length {length}",
            );

            assert_eq!(
                original.hash_tree_root(),
                original_root,
                "mutation leaked into a structurally shared clone at length {length}",
            );
        }
    }

    #[test]
    fn update_modifies_matching_elements() {
        for length in [0_u64, 1, 4, 17, 64, 100, 300] {
            let mut persistent =
                TestList::try_from_iter(0..length).expect("length is below the maximum");

            // Share all nodes with a clone to exercise copy-on-write.
            let original = persistent.clone();
            let original_root = original.hash_tree_root();

            persistent.update(&mut |element| {
                if *element % 2 == 0 {
                    *element = element.saturating_add(1000);
                }
            });

            let reference = ReferenceList::try_from_iter((0..length).map(|element| {
                if element % 2 == 0 {
                    element + 1000
                } else {
                    element
                }
            }))
            .expect("length is below the maximum");

            assert_eq!(
                persistent.hash_tree_root(),
                reference.hash_tree_root(),
                "hash_tree_root mismatch after update at length {length}",
            );

            assert_eq!(
                original.hash_tree_root(),
                original_root,
                "mutation leaked into a structurally shared clone at length {length}",
            );
        }
    }

    #[test]
    fn update_without_changes_keeps_the_tree() {
        let mut persistent = TestList::try_from_iter(0..100).expect("length is below the maximum");

        let root_before = persistent.root.clone().expect("list is not empty");

        persistent.update(&mut |_| {});

        let root_after = persistent.root.as_ref().expect("list is not empty");

        assert!(
            Arc::ptr_eq(&root_before, root_after),
            "an update that modifies nothing should not rebuild the tree",
        );
    }

    #[test]
    fn push_builds_the_same_tree_as_try_from_iter() {
        let mut pushed = TestList::default();

        // 300 elements cross the boundaries of the first several subtrees.
        for length in 0..300 {
            let built = TestList::try_from_iter(0..length).expect("length is below the maximum");

            assert_eq!(pushed, built, "tree mismatch at length {length}");

            assert_eq!(
                pushed.hash_tree_root(),
                built.hash_tree_root(),
                "hash_tree_root mismatch at length {length}",
            );

            pushed.push(length).expect("list is not full");
        }
    }

    #[test]
    fn push_preserves_structurally_shared_clones() {
        let mut persistent = TestList::try_from_iter(0..100).expect("length is below the maximum");

        let original = persistent.clone();
        let original_root = original.hash_tree_root();

        persistent.push(100).expect("list is not full");

        assert!(persistent.iter().copied().eq(0..101));
        assert!(original.iter().copied().eq(0..100));
        assert_eq!(original.hash_tree_root(), original_root);
    }

    #[test]
    fn get_and_get_mut_reject_out_of_bounds_indices() {
        let mut persistent = TestList::try_from_iter(0..10).expect("length is below the maximum");

        assert!(persistent.get(10).is_err());
        assert!(persistent.get(u64::MAX).is_err());
        assert!(persistent.get_mut(10).is_err());

        let mut empty = TestList::default();

        assert!(empty.get(0).is_err());
        assert!(empty.get_mut(0).is_err());
    }

    #[test]
    fn empty_list_hashes_like_reference() {
        assert_eq!(
            TestList::default().hash_tree_root(),
            ReferenceList::default().hash_tree_root(),
        );
    }
}
