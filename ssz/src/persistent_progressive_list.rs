#![allow(clippy::type_complexity)]
#![allow(clippy::assertions_on_result_states)]
use anyhow::ensure;
use arithmetic::NonZeroExt as _;
use core::{
    cmp::Ordering,
    convert::AsRef,
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
    slice,
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
        PersistentList, SubtreeCursor,
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

    fn update_at(
        &mut self,
        start: u64,
        indices: &[u64],
        f: &mut (impl FnMut(u64, &mut T) -> Result<(), anyhow::Error> + ?Sized),
    ) -> Result<(), anyhow::Error>
    where
        T: Clone,
    {
        match self {
            Self::Narrow(node) => node.make_mut().as_mut().update_at(start, indices, f),
            Self::Wide(node) => node.make_mut().as_mut().update_at(start, indices, f),
        }
    }

    fn append(&mut self, length: usize, elements: &[T]) -> usize
    where
        T: Clone,
    {
        match self {
            Self::Narrow(node) => MerkleTreeNode::append(node, length, elements),
            Self::Wide(node) => MerkleTreeNode::append(node, length, elements),
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

impl<'list, T, B> SubtreeLeaves<'list, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn next_leaf(&mut self) -> Option<&'list [T]> {
        match self {
            Self::Narrow(leaves) => leaves.next_leaf(),
            Self::Wide(leaves) => leaves.next_leaf(),
        }
    }
}

impl<'list, T, B> Iterator for SubtreeLeaves<'list, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = &'list T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Narrow(leaves) => leaves.next(),
            Self::Wide(leaves) => leaves.next(),
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        match self {
            Self::Narrow(leaves) => leaves.nth(n),
            Self::Wide(leaves) => leaves.nth(n),
        }
    }

    fn fold<A, F: FnMut(A, Self::Item) -> A>(self, init: A, f: F) -> A {
        match self {
            Self::Narrow(leaves) => leaves.fold(init, f),
            Self::Wide(leaves) => leaves.fold(init, f),
        }
    }
}

impl<T, B> FusedIterator for SubtreeLeaves<'_, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
}

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

    fn bundles<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [T]> + 'a> {
        let nodes = core::iter::successors(self.root.as_deref().map(AsRef::as_ref), |node| {
            node.right.as_deref().map(AsRef::as_ref)
        });

        Box::new(nodes.flat_map(|node| {
            let mut leaves = node.left.leaves();
            core::iter::from_fn(move || leaves.next_leaf())
        }))
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

    fn update_at(
        &mut self,
        indices: &[u64],
        f: &mut dyn FnMut(u64, &mut T) -> Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error>
    where
        T: Clone,
    {
        ensure!(indices.is_sorted(), "indices are not in ascending order");

        let Some(&last) = indices.last() else {
            return Ok(());
        };

        shared::validate_index(self.length, last)?;

        let mut indices = indices;
        let mut start = 0_u64;
        let mut spine = self.root.as_mut();

        while let Some(node) = spine {
            let node = node.make_mut().as_mut();

            let end = start.saturating_add(
                1_u64 << node.height.saturating_add(MinimumBundleSize::<T>::ilog2()),
            );

            let (left_indices, right_indices) =
                indices.split_at(indices.partition_point(|index| *index < end));

            if !left_indices.is_empty() {
                node.left.update_at(start, left_indices, f)?;
            }

            indices = right_indices;

            if indices.is_empty() {
                break;
            }

            start = end;
            spine = node.right.as_mut();
        }

        assert!(indices.is_empty());

        Ok(())
    }

    fn extend(&mut self, elements: &[T]) -> Result<(), PushError>
    where
        T: Clone,
    {
        let maximum = shared::saturating_usize::<PrettyBigU>();

        if elements.len() > maximum.saturating_sub(self.length) {
            return Err(PushError::ListFull);
        }

        let new_length = self.length.saturating_add(elements.len());
        let mut elements = elements;
        let mut unvisited = self.length;
        let mut height: Height = 0;
        let mut spine = &mut self.root;

        while !elements.is_empty() {
            let capacity = MinimumBundleSize::<T>::USIZE << height;
            let filled = unvisited.min(capacity);
            let (now, later) =
                elements.split_at(capacity.saturating_sub(filled).min(elements.len()));

            match spine {
                Some(node) => {
                    node.make_mut().as_mut().left.append(filled, now);
                }
                None => {
                    let (left, _) = Subtree::build(&mut now.iter().cloned(), capacity, height)
                        .expect("the loop only runs while elements remain");

                    *spine = Some(Hc::arc(Node {
                        left,
                        right: None,
                        height,
                    }));
                }
            }

            elements = later;
            unvisited = unvisited.saturating_sub(filled);
            height = height.saturating_add(2);

            spine = &mut spine
                .as_mut()
                .expect("the match above ensures that spine is Some")
                .make_mut()
                .as_mut()
                .right;
        }

        self.length = new_length;

        Ok(())
    }

    fn retain_range(&mut self, start: u64, end: u64) -> Result<(), IndexError>
    where
        T: Clone,
    {
        let (start, end) = shared::validate_range(self.length, start, end)?;
        let new_length = end.saturating_sub(start);

        if new_length == self.length {
            return Ok(());
        }

        let mut elements = (&*self).into_iter().skip(start).take(new_length).cloned();

        if B::index_in_bundle(start) != 0 {
            *self = Self::try_from_iter(elements).expect("the retained elements fit in the list");
            return Ok(());
        }

        let mut root = None;
        let mut spine = &mut root;
        let mut offset: usize = 0;
        let mut height: Height = 0;

        // All narrow partitions together hold fewer elements than a single wide bundle, so they are
        // built from copies.
        while offset < new_length && !Subtree::<T, B>::is_wide(height) {
            let capacity = MinimumBundleSize::<T>::USIZE << height;

            let (left, count) = Subtree::build(&mut elements, capacity, height)
                .expect("offset is below new_length, so elements remain");

            spine = &mut spine
                .insert(Hc::arc(Node {
                    left,
                    right: None,
                    height,
                }))
                .make_mut()
                .as_mut()
                .right;

            offset = offset.saturating_add(count);
            height = height.saturating_add(2);
        }

        if offset < new_length {
            // The new wide partitions take their elements from the wide partitions of the list,
            // each from at most two of them, because every one of those holds at least as many.
            let position = start.saturating_add(offset);
            let (mut source, mut source_start) = self
                .root
                .as_deref()
                .expect("a nonzero length means self.root is Some")
                .partition_holding(0, position);
            let mut cursor = source.cursor(source_start, self.length, position);

            while offset < new_length {
                let count = (MinimumBundleSize::<T>::USIZE << height)
                    .min(new_length.saturating_sub(offset));

                let left = if count <= cursor.remaining() {
                    cursor.slice(count)
                } else {
                    (source, source_start) = source.partition_holding(
                        source_start,
                        start
                            .saturating_add(offset)
                            .saturating_add(cursor.remaining()),
                    );

                    let mut next = source.cursor(source_start, self.length, source_start);
                    let left = slice_across(&mut cursor, &mut next, count);
                    cursor = next;
                    left
                };

                spine = &mut spine
                    .insert(Hc::arc(Node {
                        left: Subtree::Wide(left),
                        right: None,
                        height,
                    }))
                    .make_mut()
                    .as_mut()
                    .right;

                offset = offset.saturating_add(count);
                height = height.saturating_add(2);
            }
        }

        *self = Self {
            root,
            length: new_length,
        };

        Ok(())
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
    type IntoIter = ExactSize<Leaves<'list, T, B>>;

    fn into_iter(self) -> Self::IntoIter {
        let leaves = Leaves {
            bundle: [].iter(),
            end: 0,
            subtree: None,
            node: self.root.as_deref().map(AsRef::as_ref),
            start: 0,
        };

        ExactSize::new(leaves, self.length)
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

    fn partition_holding(&self, start: usize, index: usize) -> (&Self, usize) {
        let mut node = self;
        let mut start = start;

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE << node.height;

            if index < start.saturating_add(capacity) {
                return (node, start);
            }

            start = start.saturating_add(capacity);
            node = node
                .right
                .as_deref()
                .expect("the index is within bounds")
                .as_ref();
        }
    }

    fn cursor(&self, start: usize, length: usize, position: usize) -> SubtreeCursor<'_, T, B> {
        let Subtree::Wide(root) = &self.left else {
            unreachable!("only wide partitions hold the elements after the narrow ones");
        };

        let end = start
            .saturating_add(MinimumBundleSize::<T>::USIZE << self.height)
            .min(length);

        SubtreeCursor::new(
            root,
            end.saturating_sub(start),
            position.saturating_sub(start),
        )
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

fn slice_across<'list, T: Clone, B: BundleSize<T>>(
    cursor: &mut SubtreeCursor<'list, T, B>,
    next: &mut SubtreeCursor<'list, T, B>,
    length: usize,
) -> Arc<Hc<MerkleTreeNode<T, B>>> {
    let split = cursor.remaining();

    if split == 0 {
        return next.slice(length);
    }

    if split >= length {
        return cursor.slice(length);
    }

    let height = B::depth_of_length(length);

    if height == 0 {
        let mut bundle = Vec::with_capacity(length);
        cursor.copy_elements(split, &mut bundle);
        next.copy_elements(length.saturating_sub(split), &mut bundle);
        return Hc::arc(MerkleTreeNode::leaf(bundle));
    }

    let left_length = B::USIZE << height.saturating_sub(1);
    let left = slice_across(cursor, next, left_length);
    let right = slice_across(cursor, next, length.saturating_sub(left_length));

    Hc::arc(MerkleTreeNode::internal(left, right))
}

pub struct Leaves<'list, T: SszHash, B> {
    bundle: slice::Iter<'list, T>,
    end: usize,
    subtree: Option<SubtreeLeaves<'list, T, B>>,
    node: Option<&'list Node<T, B>>,
    start: usize,
}

impl<T, B> Leaves<'_, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn next_subtree(&mut self) -> Option<()> {
        let node = self.node?;

        self.subtree = Some(node.left.leaves());
        self.end = self.start;
        self.node = node.right.as_deref().map(AsRef::as_ref);
        self.start = self
            .start
            .saturating_add(MinimumBundleSize::<T>::USIZE << node.height);

        Some(())
    }
}

impl<'list, T, B> Iterator for Leaves<'list, T, B>
where
    T: SszHash,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Item = &'list T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(element) = self.bundle.next() {
                return Some(element);
            }

            match self.subtree.as_mut().and_then(SubtreeLeaves::next_leaf) {
                Some(leaf) => {
                    self.bundle = leaf.iter();
                    self.end = self.end.saturating_add(leaf.len());
                }
                None => self.next_subtree()?,
            }
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let index = self.end.saturating_sub(self.bundle.len()).saturating_add(n);

        if let Some(element) = self.bundle.nth(n) {
            return Some(element);
        }

        while self.start <= index {
            if self.next_subtree().is_none() {
                self.subtree = None;
                return None;
            }
        }

        let subtree = self.subtree.as_mut()?;
        let element = subtree.nth(index.saturating_sub(self.end))?;
        let leaf = subtree.next_leaf().unwrap_or_default();

        self.bundle = leaf.iter();
        self.end = index.saturating_add(1).saturating_add(leaf.len());

        Some(element)
    }

    fn fold<A, F: FnMut(A, Self::Item) -> A>(self, init: A, mut f: F) -> A {
        let mut accumulator = self.bundle.fold(init, &mut f);

        if let Some(subtree) = self.subtree {
            accumulator = subtree.fold(accumulator, &mut f);
        }

        let mut node = self.node;

        while let Some(spine) = node {
            accumulator = spine.left.leaves().fold(accumulator, &mut f);
            node = spine.right.as_deref().map(AsRef::as_ref);
        }

        accumulator
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
    use typenum::{U16, U64, U128, U256, U512, U2048};

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
    fn roots_match_the_reference_for_every_bundle_size_with_bytes() {
        fn check<B: BundleSize<u8> + MerkleElements<u8>>(width: &str) {
            for length in 0..2800 {
                let elements = (0..=u8::MAX).cycle().take(length);
                let persistent =
                    PersistentProgressiveList::<u8, B>::try_from_iter(elements.clone())
                        .expect("length is below the maximum");
                let reference = ProgressiveList::<u8>::try_from_iter(elements.clone())
                    .expect("length is below the maximum");

                assert_eq!(
                    persistent.hash_tree_root(),
                    reference.hash_tree_root(),
                    "hash_tree_root mismatch at length {length} with bundle {width}",
                );

                assert!(
                    persistent.into_iter().copied().eq(elements),
                    "elements mismatch at length {length} with bundle {width}",
                );
            }
        }

        check::<MinimumBundleSize<u8>>("minimum");
        check::<U128>("128");
        check::<U512>("512");
        check::<U2048>("2048");
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
    fn update_at_changes_the_same_elements_as_get_mut() {
        for length in LENGTHS.skip(1) {
            let base = TestList::try_from_iter(0..length).expect("length is below the maximum");

            for step in [1, 2, 3, 7, 64] {
                let indices = (0..length).step_by(step).collect::<Vec<_>>();

                let mut walked = base.clone();
                let mut looked_up = base.clone();

                walked
                    .update_at(&indices, &mut |index, element| {
                        *element += 1000 + index;
                        Ok(())
                    })
                    .expect("every index is in the list");

                for index in indices.iter().copied() {
                    *looked_up
                        .get_mut(index)
                        .expect("every index is in the list") += 1000 + index;
                }

                assert_eq!(walked, looked_up, "length {length}, step {step}");
                assert_eq!(walked.hash_tree_root(), looked_up.hash_tree_root());
            }

            let mut list = base.clone();

            assert!(
                list.update_at(&[0, length], &mut |_, element| {
                    *element += 1000;
                    Ok(())
                })
                .is_err(),
            );
            assert_eq!(list, base);
            assert!(list.update_at(&[1, 0], &mut |_, _| Ok(())).is_err());
        }
    }

    #[test]
    fn update_at_changes_the_same_elements_as_get_mut_with_bytes() {
        fn check<B: BundleSize<u8> + MerkleElements<u8> + Send + Sync>(width: &str) {
            for length in 1..2800 {
                let base = PersistentProgressiveList::<u8, B>::try_from_iter(
                    (0..=u8::MAX).cycle().take(length),
                )
                .expect("length is below the maximum");

                for step in [1, 3, 31, 512] {
                    let indices = (0..base.len_u64()).step_by(step).collect::<Vec<_>>();

                    let mut walked = base.clone();
                    let mut looked_up = base.clone();

                    walked
                        .update_at(&indices, &mut |_, element| {
                            *element = !*element;
                            Ok(())
                        })
                        .expect("every index is in the list");

                    for index in indices.iter().copied() {
                        let element = looked_up
                            .get_mut(index)
                            .expect("every index is in the list");

                        *element = !*element;
                    }

                    assert_eq!(
                        walked, looked_up,
                        "length {length}, step {step}, bundle {width}",
                    );
                    assert_eq!(walked.hash_tree_root(), looked_up.hash_tree_root());
                }
            }
        }

        check::<MinimumBundleSize<u8>>("minimum");
        check::<U512>("512");
        check::<U2048>("2048");
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
    fn extend_builds_the_same_tree_as_try_from_iter() {
        for length in LENGTHS {
            for split in [0, length / 2, length] {
                let built =
                    TestList::try_from_iter(0..length).expect("length is below the maximum");

                let mut extended =
                    TestList::try_from_iter(0..split).expect("length is below the maximum");
                extended
                    .extend(&(split..length).collect::<Vec<_>>())
                    .expect("list is not full");

                assert_eq!(
                    extended, built,
                    "tree mismatch at length {length}, split {split}",
                );

                assert_eq!(
                    extended.hash_tree_root(),
                    built.hash_tree_root(),
                    "hash_tree_root mismatch at length {length}, split {split}",
                );
            }
        }
    }

    #[test]
    fn extend_preserves_structurally_shared_clones() {
        let mut persistent = TestList::try_from_iter(0..100).expect("length is below the maximum");

        let original = persistent.clone();
        let original_root = original.hash_tree_root();

        persistent
            .extend(&(100..300).collect::<Vec<_>>())
            .expect("list is not full");

        assert!(persistent.iter().copied().eq(0..300));
        assert!(original.iter().copied().eq(0..100));
        assert_eq!(original.hash_tree_root(), original_root);
    }

    #[test]
    fn retain_range_with_start_greater_than_end_returns_an_error() {
        let mut list = TestList::try_from_iter(0..5).expect("length is below the maximum");

        list.retain_range(3, 1)
            .expect_err("start is greater than end");
    }

    #[test]
    fn retain_range_matches_try_from_iter_of_the_same_range() {
        for length in LENGTHS {
            for start in [0, length / 2, length] {
                for end in [start, start + 1, length] {
                    if end > length {
                        continue;
                    }

                    let mut sliced =
                        TestList::try_from_iter(0..length).expect("length is below the maximum");
                    sliced
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    let built =
                        TestList::try_from_iter(start..end).expect("length is below the maximum");

                    assert_eq!(
                        sliced, built,
                        "tree mismatch at length {length}, range {start}..{end}",
                    );

                    assert_eq!(
                        sliced.hash_tree_root(),
                        built.hash_tree_root(),
                        "hash_tree_root mismatch at length {length}, range {start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn nth_matches_a_vec_after_any_number_of_elements() {
        for length in 0..100 {
            let list = TestList::try_from_iter(0..length).expect("length is below the maximum");
            let vector = (0..length).collect::<Vec<_>>();

            for consumed in 0..=vector.len() {
                for n in 0..=vector.len() {
                    let mut actual = (&list).into_iter();
                    let mut expected = vector.iter();

                    for _ in 0..consumed {
                        assert_eq!(actual.next(), expected.next());
                    }

                    assert_eq!(
                        actual.nth(n),
                        expected.nth(n),
                        "length {length}, {consumed} consumed, nth({n})",
                    );
                    assert_eq!(actual.len(), expected.len());
                    assert!(actual.eq(expected));
                }
            }
        }
    }

    #[test]
    fn retain_range_matches_try_from_iter_for_all_small_ranges() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..24 {
            let packed = TestList::try_from_iter(0..length).expect("length is below the maximum");
            let unpacked = UnpackedList::try_from_iter((0..length).map(element))
                .expect("length is below the maximum");

            for start in 0..=length {
                for end in start..=length {
                    let mut retained_packed = packed.clone();
                    retained_packed
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    let expected_packed =
                        TestList::try_from_iter(start..end).expect("length is below the maximum");

                    assert_eq!(
                        retained_packed, expected_packed,
                        "packed tree mismatch at length {length}, range {start}..{end}",
                    );

                    let mut retained_unpacked = unpacked.clone();
                    retained_unpacked
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    let expected_unpacked = UnpackedList::try_from_iter((start..end).map(element))
                        .expect("length is below the maximum");

                    assert_eq!(
                        retained_unpacked, expected_unpacked,
                        "unpacked tree mismatch at length {length}, range {start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn retain_range_matches_try_from_iter_with_the_minimum_bundle_size() {
        type Packed = PersistentProgressiveList<u64>;
        type Unpacked = PersistentProgressiveList<H256>;

        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..90 {
            let packed = Packed::try_from_iter(0..length).expect("length is below the maximum");
            let unpacked = Unpacked::try_from_iter((0..length).map(element))
                .expect("length is below the maximum");

            for start in 0..=length {
                for end in start..=length {
                    let mut retained = packed.clone();
                    retained
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    assert_eq!(
                        retained,
                        Packed::try_from_iter(start..end).expect("length is below the maximum"),
                        "packed tree mismatch at length {length}, range {start}..{end}",
                    );

                    let mut retained = unpacked.clone();
                    retained
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    assert_eq!(
                        retained,
                        Unpacked::try_from_iter((start..end).map(element))
                            .expect("length is below the maximum"),
                        "unpacked tree mismatch at length {length}, range {start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn retain_range_shares_every_leaf_when_bundles_hold_one_element() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..90 {
            let original =
                PersistentProgressiveList::<H256>::try_from_iter((0..length).map(element))
                    .expect("length is below the maximum");

            for start in 0..=length {
                for end in start..=length {
                    let mut retained = original.clone();
                    retained
                        .retain_range(start, end)
                        .expect("range is within bounds");

                    let start = usize::try_from(start).expect("start fits in usize");

                    assert!(
                        (&retained)
                            .into_iter()
                            .zip((&original).into_iter().skip(start))
                            .all(|(retained, original)| core::ptr::eq(retained, original)),
                        "an element was copied at length {length}, range {start}..{end}",
                    );
                }
            }
        }
    }

    #[test]
    fn retain_range_preserves_structurally_shared_clones() {
        let persistent = TestList::try_from_iter(0..300).expect("length is below the maximum");
        let original_root = persistent.hash_tree_root();

        let mut sliced = persistent.clone();
        sliced.retain_range(0, 100).expect("range is within bounds");

        *sliced.get_mut(0).expect("index is within bounds") = u64::MAX;

        assert!(persistent.iter().copied().eq(0..300));
        assert_eq!(persistent.hash_tree_root(), original_root);
    }

    #[test]
    fn retain_range_of_full_list_keeps_the_root() {
        let mut persistent = TestList::try_from_iter(0..100).expect("length is below the maximum");
        let root = persistent.root.clone().expect("list is not empty");

        persistent
            .retain_range(0, 100)
            .expect("range is within bounds");

        assert!(Arc::ptr_eq(
            &root,
            persistent.root.as_ref().expect("list is not empty"),
        ));
    }

    #[test]
    fn retain_range_shares_shifted_leaf() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));
        let original = PersistentProgressiveList::<H256>::try_from_iter((0..21).map(element))
            .expect("length is below the maximum");
        let second_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(second_partition) = second_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let MerkleTreeNode::Internal {
            left: first_pair, ..
        } = second_partition.as_ref().as_ref()
        else {
            panic!("the full second partition is an internal node")
        };
        let MerkleTreeNode::Internal {
            left: original_leaf,
            ..
        } = first_pair.as_ref().as_ref()
        else {
            panic!("the first pair in the second partition is an internal node")
        };

        let mut retained = original.clone();
        retained
            .retain_range(1, 21)
            .expect("range is within bounds");

        let Subtree::Wide(retained_leaf) = &retained.root.as_ref().expect("list is not empty").left
        else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        assert!(Arc::ptr_eq(original_leaf, retained_leaf));
    }

    #[test]
    fn retain_range_shares_shifted_full_subtree() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));
        let original = PersistentProgressiveList::<H256>::try_from_iter((0..21).map(element))
            .expect("length is below the maximum");
        let third_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition")
            .left;
        let Subtree::Wide(third_partition) = third_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let MerkleTreeNode::Internal {
            left: first_half, ..
        } = third_partition.as_ref().as_ref()
        else {
            panic!("the full third partition is an internal node")
        };
        let MerkleTreeNode::Internal {
            left: original_subtree,
            ..
        } = first_half.as_ref().as_ref()
        else {
            panic!("the first half of the third partition is an internal node")
        };

        let mut retained = original.clone();
        retained
            .retain_range(4, 21)
            .expect("range is within bounds");

        let expected = PersistentProgressiveList::<H256>::try_from_iter((4..21).map(element))
            .expect("length is below the maximum");
        assert_eq!(retained, expected);

        let retained_subtree = &retained
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(retained_subtree) = retained_subtree else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        assert!(Arc::ptr_eq(original_subtree, retained_subtree));
    }

    #[test]
    fn retain_range_shares_shifted_partial_trailing_subtree() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));
        let original = PersistentProgressiveList::<H256>::try_from_iter((0..12).map(element))
            .expect("length is below the maximum");
        let third_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition")
            .left;
        let Subtree::Wide(third_partition) = third_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let MerkleTreeNode::Internal {
            right: original_subtree,
            ..
        } = third_partition.as_ref().as_ref()
        else {
            panic!("the partial third partition is an internal node")
        };

        let mut retained = original.clone();
        retained
            .retain_range(8, 12)
            .expect("range is within bounds");

        let expected = PersistentProgressiveList::<H256>::try_from_iter((8..12).map(element))
            .expect("length is below the maximum");
        assert_eq!(retained, expected);

        let retained_subtree = &retained
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(retained_subtree) = retained_subtree else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        assert!(Arc::ptr_eq(original_subtree, retained_subtree));
    }

    #[test]
    fn retain_range_shares_packed_subtrees() {
        let original = PersistentProgressiveList::<u64>::try_from_iter(0..84)
            .expect("length is below the maximum");
        let Subtree::Wide(first_partition) =
            &original.root.as_ref().expect("list is not empty").left
        else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let second_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(second_partition) = second_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        let mut prefix = original.clone();
        prefix.retain_range(0, 36).expect("range is within bounds");

        let prefix_root = prefix.root.as_ref().expect("list is not empty");
        let Subtree::Wide(prefix_first_partition) = &prefix_root.left else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let prefix_second_partition = &prefix_root
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(prefix_second_partition) = prefix_second_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        assert!(Arc::ptr_eq(first_partition, prefix_first_partition));
        assert!(Arc::ptr_eq(second_partition, prefix_second_partition));

        let third_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition")
            .left;
        let Subtree::Wide(third_partition) = third_partition else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };
        let MerkleTreeNode::Internal {
            left: first_half, ..
        } = third_partition.as_ref().as_ref()
        else {
            panic!("the full third partition is an internal node")
        };
        let MerkleTreeNode::Internal {
            left: original_subtree,
            ..
        } = first_half.as_ref().as_ref()
        else {
            panic!("the first half of the third partition is an internal node")
        };

        let mut shifted = original.clone();
        shifted
            .retain_range(16, 84)
            .expect("range is within bounds");

        let retained_subtree = &shifted
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;
        let Subtree::Wide(retained_subtree) = retained_subtree else {
            panic!("partitions of a list with the minimum bundle size are wide")
        };

        assert!(Arc::ptr_eq(original_subtree, retained_subtree));
    }

    #[test]
    fn retain_range_rejects_out_of_bounds_ranges() {
        let mut persistent = TestList::try_from_iter(0..10).expect("length is below the maximum");

        assert!(persistent.retain_range(0, 11).is_err());
        assert!(persistent.retain_range(5, 11).is_err());
    }

    #[test]
    fn empty_list_hashes_like_reference() {
        assert_eq!(
            TestList::default().hash_tree_root(),
            ReferenceList::default().hash_tree_root(),
        );
    }
}
