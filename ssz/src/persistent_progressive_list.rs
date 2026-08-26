#![allow(clippy::type_complexity)]
#![allow(clippy::assertions_on_result_states)]
use core::{
    cmp::Ordering,
    convert::AsRef,
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
};

use arithmetic::NonZeroExt as _;
use bit_field::BitField as _;
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
    persistent_list::{Leaves, LeavesMut, Node as MerkleTreeNode, PersistentList},
    shared,
};

type PrettyBigU = typenum::U1048576;

// Unlike `PersistentList`, this does not support bundle sizes other than the minimum.
// EIP-7916 partitions the chunk sequence at absolute positions (1, 4, 16, ... chunks),
// so a bundle spanning more than one chunk would straddle a subtree boundary.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Default(bound = "")
)]
pub struct PersistentProgressiveList<T: SszHash> {
    root: Option<Arc<Hc<Node<T, MinimumBundleSize<T>>>>>,
    length: usize,
}

impl<T: SszHash> PersistentProgressiveList<T> {
    const fn validate_length(actual: usize) -> Result<(), ReadError> {
        let maximum = shared::saturating_usize::<PrettyBigU>();

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        Ok(())
    }
}

impl<T> PersistentProgressiveList<T>
where
    T: SszHash,
    MinimumBundleSize<T>: BundleSize<T>,
{
    // Returns an existing subtree if it represents exactly the requested source range.
    fn shared_subtree(
        &self,
        start: usize,
        length: usize,
    ) -> Option<Arc<Hc<MerkleTreeNode<T, MinimumBundleSize<T>>>>> {
        let mut partition_start: usize = 0;
        let mut partition_capacity = MinimumBundleSize::<T>::USIZE;
        let mut spine = self.root.as_ref()?;

        while partition_start.saturating_add(partition_capacity) <= start {
            partition_start = partition_start.saturating_add(partition_capacity);
            partition_capacity = partition_capacity.saturating_mul(4);
            spine = spine.as_ref().as_ref().right.as_ref()?;
        }

        let filled = self
            .length
            .saturating_sub(partition_start)
            .min(partition_capacity);
        let local_start = start.saturating_sub(partition_start);

        MerkleTreeNode::shared_subtree(&spine.as_ref().as_ref().left, filled, local_start, length)
    }

    // Returns the bundle containing the element at `index`.
    // Callers must ensure that `index` is within bounds.
    fn bundle_containing(&self, mut index: usize) -> &[T] {
        let mut spine = self
            .root
            .as_deref()
            .expect("callers validate index against self.length, so self.root is Some")
            .as_ref();

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE << spine.height;

            if let Some(new_index) = index.checked_sub(capacity) {
                index = new_index;
                spine = spine
                    .right
                    .as_deref()
                    .expect("the validated index falls within an existing subtree")
                    .as_ref();
            } else {
                break;
            }
        }

        MerkleTreeNode::bundle_containing(&spine.left, index)
    }
}

impl<T> TryFromIterator<T> for PersistentProgressiveList<T>
where
    T: SszHash,
    MinimumBundleSize<T>: BundleSize<T>,
{
    type Error = ReadError;

    // Like `PersistentList::try_from_iter`, this does not deduplicate consecutive nodes.
    // Unlike it, this builds each subtree in a single pass by merging equal-height nodes,
    // which avoids collecting all nodes of a level into a `Vec` before pairing them up.
    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let mut elements = elements.into_iter();
        let mut subtrees_with_heights = vec![];
        let mut length: usize = 0;
        let mut height: u8 = 0;

        loop {
            let capacity = MinimumBundleSize::<T>::USIZE
                .checked_shl(height.into())
                .unwrap_or(usize::MAX);

            let Some((subtree, count)) = build_subtree(&mut elements, capacity) else {
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
            root = Some(Arc::new(Hc::new(Node {
                left,
                right: root,
                height,
            })));
        }

        Ok(Self { root, length })
    }
}

// The trees have different shapes (and possibly different bundle sizes),
// so no structural sharing is possible and the elements have to be cloned.
impl<T, N, B> From<&PersistentList<T, N, B>> for PersistentProgressiveList<T>
where
    T: SszHash + Clone,
    N: Unsigned,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from(list: &PersistentList<T, N, B>) -> Self {
        Self::try_from_iter(list.into_iter().cloned())
            .expect("both lists have the same maximum length")
    }
}

impl<T, N, B> From<PersistentList<T, N, B>> for PersistentProgressiveList<T>
where
    T: SszHash + Clone,
    N: Unsigned,
    B: BundleSize<T>,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from(list: PersistentList<T, N, B>) -> Self {
        Self::from(&list)
    }
}

// Build a left-aligned subtree holding up to `capacity` elements taken from `elements`.
// Nodes of equal height are merged eagerly, like carries in a binary counter,
// so the stack never holds more than one node per height.
fn build_subtree<T, B: BundleSize<T>>(
    elements: &mut impl Iterator<Item = T>,
    capacity: usize,
) -> Option<(Arc<Hc<MerkleTreeNode<T, B>>>, usize)> {
    let mut stack: Vec<(MerkleTreeNode<T, B>, u8)> = vec![];
    let mut count: usize = 0;

    while count < capacity {
        let bundle: Box<[T]> = elements.by_ref().take(B::USIZE).collect();

        if bundle.is_empty() {
            break;
        }

        let exhausted = bundle.len() < B::USIZE;

        count = count.saturating_add(bundle.len());

        let mut node = MerkleTreeNode::leaf(bundle);
        let mut node_height: u8 = 0;

        while stack
            .last()
            .is_some_and(|(_, top_height)| *top_height == node_height)
        {
            let (left, left_height) = stack.pop().expect("stack is not empty");

            node = MerkleTreeNode::Internal {
                left: Hc::arc(left),
                right: Hc::arc(node),
                left_height,
                right_height: node_height,
            };

            node_height = left_height.saturating_add(1);
        }

        stack.push((node, node_height));

        if exhausted {
            break;
        }
    }

    let (mut node, mut node_height) = stack.pop()?;

    while let Some((left, left_height)) = stack.pop() {
        node = MerkleTreeNode::Internal {
            left: Hc::arc(left),
            right: Hc::arc(node),
            left_height,
            right_height: node_height,
        };

        node_height = left_height.saturating_add(1);
    }

    Some((Arc::new(Hc::new(node)), count))
}

impl<T> SszList<T> for PersistentProgressiveList<T>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    MinimumBundleSize<T>: BundleSize<T> + MerkleElements<T> + Send + Sync,
{
    fn len_usize(&self) -> usize {
        self.length
    }

    fn len_u64(&self) -> u64 {
        u64::try_from(self.length).expect("list length fits in u64")
    }

    fn get(&self, index: u64) -> Result<&T, IndexError> {
        let index = shared::validate_index(self.length, index)?;
        let bundle = self.bundle_containing(index);

        Ok(&bundle[MinimumBundleSize::<T>::index_in_bundle(index)])
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

impl<T> SszListMut<T> for PersistentProgressiveList<T>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
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

        let mut node = spine.left.make_mut().as_mut();

        let mut height = match node {
            MerkleTreeNode::Internal { left_height, .. } => left_height.saturating_add(1),
            MerkleTreeNode::Leaf { .. } => 0,
        };

        let bundle = loop {
            match node {
                MerkleTreeNode::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                } => {
                    assert_eq!(height, left_height.saturating_add(1));

                    let bit_index = height
                        .saturating_add(MinimumBundleSize::<T>::ilog2())
                        .saturating_sub(1)
                        .into();

                    if index.get_bit(bit_index) {
                        height = *right_height;
                        node = right.make_mut();
                    } else {
                        height = *left_height;
                        node = left.make_mut();
                    }
                }
                MerkleTreeNode::Leaf { bundle, .. } => {
                    assert_eq!(height, 0);
                    break bundle;
                }
            }
        };

        Ok(&mut bundle[MinimumBundleSize::<T>::index_in_bundle(index)])
    }

    fn extend(&mut self, elements: &mut dyn Iterator<Item = T>) -> Result<(), PushError>
    where
        T: Clone,
    {
        let mut elements = elements.fuse().peekable();

        // Elements of `self` held by the subtrees the loop has not reached yet.
        let mut unvisited = self.length;
        let mut room = shared::saturating_usize::<PrettyBigU>().saturating_sub(self.length);
        let mut appended: usize = 0;
        let mut height: u8 = 0;
        let mut spine = &mut self.root;

        while room > 0 && elements.peek().is_some() {
            let capacity = MinimumBundleSize::<T>::USIZE << height;
            let filled = unvisited.min(capacity);

            let node = spine
                .get_or_insert_with(|| {
                    Arc::new(Hc::new(Node {
                        left: Hc::arc(MerkleTreeNode::leaf([])),
                        right: None,
                        height,
                    }))
                })
                .make_mut()
                .as_mut();

            let (new_filled, _) = MerkleTreeNode::append(
                &mut node.left,
                MinimumBundleSize::<T>::depth_of_length(filled),
                filled,
                capacity.min(filled.saturating_add(room)),
                &mut elements,
            );

            let count = new_filled.saturating_sub(filled);

            room = room.saturating_sub(count);
            appended = appended.saturating_add(count);
            unvisited = unvisited.saturating_sub(filled);
            height = height.saturating_add(2);
            spine = &mut node.right;
        }

        self.length = self.length.saturating_add(appended);

        if elements.peek().is_some() {
            return Err(PushError::ListFull);
        }

        Ok(())
    }

    fn retain_range(&mut self, start: u64, end: u64) -> Result<(), IndexError>
    where
        T: Clone,
    {
        let start =
            usize::try_from(start).map_err(|_| IndexError::DoesNotFitInUsize { index: start })?;
        let end = usize::try_from(end).map_err(|_| IndexError::DoesNotFitInUsize { index: end })?;

        assert!(
            start <= end,
            "retain_range start ({start}) is greater than retain_range end ({end})",
        );

        if self.length < end {
            return Err(IndexError::OutOfBounds {
                length: self.length,
                index: end,
            });
        }

        let new_length = end.saturating_sub(start);

        if new_length == self.length {
            return Ok(());
        }

        if new_length == 0 {
            *self = Self::default();
            return Ok(());
        }

        // Shifting elements requires a new EIP-7916 spine, but aligned Merkle subtrees below it
        // still represent the same ranges and can be shared.
        let mut subtrees_with_heights = vec![];
        let mut remaining = new_length;
        let mut offset: usize = 0;
        let mut height: u8 = 0;

        while remaining > 0 {
            let capacity = MinimumBundleSize::<T>::USIZE << height;
            let count = remaining.min(capacity);

            subtrees_with_heights.push((
                MerkleTreeNode::slice_subtree(
                    start.saturating_add(offset),
                    count,
                    &|start, length| self.shared_subtree(start, length),
                    &|index| self.bundle_containing(index),
                ),
                height,
            ));

            remaining = remaining.saturating_sub(count);
            offset = offset.saturating_add(count);
            height = height.saturating_add(2);
        }

        let mut root = None;

        for (left, height) in subtrees_with_heights.into_iter().rev() {
            root = Some(Arc::new(Hc::new(Node {
                left,
                right: root,
                height,
            })));
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
            .expect("PersistentProgressiveList length counter should fit in u64");

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
                        spine.left.make_mut().as_mut().push(element, index);
                        break;
                    }

                    index = index
                        .checked_sub(capacity)
                        .ok_or(PushError::IndexOutOfBounds)?;

                    if spine.right.is_none() {
                        assert_eq!(index, 0, "all subtrees before the last are full");

                        spine.right = Some(Node::single(element, spine.height.saturating_add(2)));

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
            None => self.root = Some(Node::single(element, 0)),
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

impl<'list, T: SszHash> IntoIterator for &'list PersistentProgressiveList<T> {
    type Item = &'list T;
    type IntoIter = ExactSize<Flatten<Nodes<'list, T, MinimumBundleSize<T>>>>;

    fn into_iter(self) -> Self::IntoIter {
        let nodes = Nodes {
            node: self.root.as_deref().map(AsRef::as_ref),
        };

        ExactSize::new(nodes.flatten(), self.length)
    }
}

impl<'list, T> IntoIterator for &'list mut PersistentProgressiveList<T>
where
    T: SszHash + Clone,
{
    type Item = &'list mut T;
    type IntoIter = ExactSize<Flatten<NodesMut<'list, T, MinimumBundleSize<T>>>>;

    fn into_iter(self) -> Self::IntoIter {
        let nodes = NodesMut {
            node: self.root.as_mut().map(|node| node.make_mut().as_mut()),
        };

        ExactSize::new(nodes.flatten(), self.length)
    }
}

impl<T: Debug + SszHash> Debug for PersistentProgressiveList<T> {
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
struct Node<T, B> {
    left: Arc<Hc<MerkleTreeNode<T, B>>>,
    right: Option<Arc<Hc<Self>>>,
    height: u8,
}

impl<T, B> SszHash for Node<T, B>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let left_height = match self.left.as_ref().as_ref() {
            MerkleTreeNode::Internal { left_height, .. } => left_height.saturating_add(1),
            MerkleTreeNode::Leaf { .. } => 0,
        };

        assert!(left_height <= self.height);

        let left_root = (left_height..self.height)
            .map(B::zero_hash)
            .fold(self.left.hash_tree_root(), hashing::hash_256_256);

        let right_root = match self.right.as_ref() {
            Some(node) => node.hash_tree_root(),
            None => H256::zero(),
        };

        hashing::hash_256_256(left_root, right_root)
    }
}

impl<T, B: BundleSize<T>> Node<T, B> {
    // Construct a spine node whose subtree holds a single element.
    fn single(element: T, height: u8) -> Arc<Hc<Self>> {
        Arc::new(Hc::new(Self {
            left: Arc::new(Hc::new(MerkleTreeNode::leaf([element]))),
            right: None,
            height,
        }))
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
                let left = match new_left {
                    Some(arc) => arc,
                    None => self.left.clone_arc(),
                };

                let right = match new_right {
                    Some(Some(arc)) => Some(arc),
                    Some(None) => self.right.clone(),
                    None => None,
                };

                Some(Arc::new(Hc::new(Self {
                    left,
                    right,
                    height: self.height,
                })))
            }
        }
    }
}

pub struct Nodes<'list, T, B> {
    node: Option<&'list Node<T, B>>,
}

impl<'list, T, B> Iterator for Nodes<'list, T, B> {
    type Item = Flatten<Leaves<'list, T, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;

        self.node = node.right.as_deref().map(AsRef::as_ref);

        Some(Leaves::new(node.left.as_ref().as_ref()).flatten())
    }
}

impl<T, B> FusedIterator for Nodes<'_, T, B> {}

// Like `LeavesMut`, this clones `right` spine nodes earlier than needed.
pub struct NodesMut<'list, T, B> {
    node: Option<&'list mut Node<T, B>>,
}

impl<'list, T: Clone, B> Iterator for NodesMut<'list, T, B> {
    type Item = Flatten<LeavesMut<'list, T, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;

        self.node = node.right.as_mut().map(|node| node.make_mut().as_mut());

        Some(LeavesMut::new(node.left.make_mut().as_mut()).flatten())
    }
}

impl<T: Clone, B> FusedIterator for NodesMut<'_, T, B> {}

impl<'de, T> Deserialize<'de> for PersistentProgressiveList<T>
where
    T: Deserialize<'de> + SszHash,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PersistentProgressiveListVisitor<T>(PhantomData<(T, PrettyBigU)>);

        impl<'de, T> Visitor<'de> for PersistentProgressiveListVisitor<T>
        where
            T: Deserialize<'de> + SszHash,
            MinimumBundleSize<T>: BundleSize<T>,
        {
            type Value = PersistentProgressiveList<T>;

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

impl<T: Serialize + SszHash> Serialize for PersistentProgressiveList<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self)
    }
}

impl<T: SszSize + SszHash> SszSize for PersistentProgressiveList<T> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<T> SszHash for PersistentProgressiveList<T>
where
    T: SszHash + SszWrite,
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

impl<T: SszWrite + SszHash> SszWrite for PersistentProgressiveList<T> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self)
    }
}

impl<C, T> SszRead<C> for PersistentProgressiveList<T>
where
    T: SszRead<C> + SszHash,
    MinimumBundleSize<T>: BundleSize<T>,
{
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        shared::read_list(shared::saturating_usize::<PrettyBigU>(), context, bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::ProgressiveList;

    use super::*;

    type TestList = PersistentProgressiveList<u64>;
    type ReferenceList = ProgressiveList<u64>;

    type BigList = PersistentProgressiveList<u64>;
    type BigReferenceList = ProgressiveList<u64>;

    type UnpackedList = PersistentProgressiveList<H256>;
    type UnpackedReferenceList = ProgressiveList<H256>;

    // Lengths up to 300 cover the boundaries of the first several subtrees,
    // whose capacities in elements are 4, 16, 64 and 256 for `u64`.
    const LENGTHS: core::ops::Range<u64> = 0..300;

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

    // `H256` has a packing factor of 1 and a minimum bundle size of 1,
    // so subtree capacities in chunks follow the progression from EIP-7916 exactly: 1, 4, 16, 64.
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
                    .extend(&mut (split..length))
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
            .extend(&mut (100..300))
            .expect("list is not full");

        assert!(persistent.iter().copied().eq(0..300));
        assert!(original.iter().copied().eq(0..100));
        assert_eq!(original.hash_tree_root(), original_root);
    }

    #[test]
    fn extend_fills_the_list_before_reporting_it_full() {
        let maximum = PrettyBigU::U64;

        let mut persistent = TestList::default();

        persistent
            .extend(&mut (0..maximum + 10))
            .expect_err("list only has room for maximum elements");

        assert_eq!(persistent.len_u64(), maximum);
        assert!(persistent.iter().copied().eq(0..maximum));

        persistent
            .extend(&mut core::iter::once(0))
            .expect_err("list has no room left");

        assert_eq!(persistent.len_u64(), maximum);
    }

    #[test]
    #[should_panic(expected = "retain_range start (3) is greater than retain_range end (1)")]
    fn retain_range_with_start_greater_than_end_panics() {
        let mut list = TestList::try_from_iter(0..5).expect("length is below the maximum");

        drop(list.retain_range(3, 1));
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
        let original =
            UnpackedList::try_from_iter((0..21).map(element)).expect("length is below the maximum");
        let second_partition = original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition");
        let MerkleTreeNode::Internal {
            left: first_pair, ..
        } = second_partition.left.as_ref().as_ref()
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

        let retained_leaf = &retained.root.as_ref().expect("list is not empty").left;

        assert!(Arc::ptr_eq(original_leaf, retained_leaf));
    }

    #[test]
    fn retain_range_shares_shifted_full_subtree() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));
        let original =
            UnpackedList::try_from_iter((0..21).map(element)).expect("length is below the maximum");
        let third_partition = original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition");
        let MerkleTreeNode::Internal {
            left: first_half, ..
        } = third_partition.left.as_ref().as_ref()
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

        let expected =
            UnpackedList::try_from_iter((4..21).map(element)).expect("length is below the maximum");
        assert_eq!(retained, expected);

        let retained_subtree = &retained
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;

        assert!(Arc::ptr_eq(original_subtree, retained_subtree));
    }

    #[test]
    fn retain_range_shares_shifted_partial_trailing_subtree() {
        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));
        let original =
            UnpackedList::try_from_iter((0..12).map(element)).expect("length is below the maximum");
        let third_partition = original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition");
        let MerkleTreeNode::Internal {
            right: original_subtree,
            ..
        } = third_partition.left.as_ref().as_ref()
        else {
            panic!("the partial third partition is an internal node")
        };

        let mut retained = original.clone();
        retained
            .retain_range(8, 12)
            .expect("range is within bounds");

        let expected =
            UnpackedList::try_from_iter((8..12).map(element)).expect("length is below the maximum");
        assert_eq!(retained, expected);

        let retained_subtree = &retained
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;

        assert!(Arc::ptr_eq(original_subtree, retained_subtree));
    }

    #[test]
    fn retain_range_shares_packed_subtrees() {
        let original = TestList::try_from_iter(0..84).expect("length is below the maximum");
        let first_partition = &original.root.as_ref().expect("list is not empty").left;
        let second_partition = &original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .left;

        let mut prefix = original.clone();
        prefix.retain_range(0, 36).expect("range is within bounds");

        let prefix_root = prefix.root.as_ref().expect("list is not empty");
        assert!(Arc::ptr_eq(first_partition, &prefix_root.left));
        assert!(Arc::ptr_eq(
            second_partition,
            &prefix_root
                .right
                .as_ref()
                .expect("list reaches the second partition")
                .left,
        ));

        let third_partition = original
            .root
            .as_ref()
            .expect("list is not empty")
            .right
            .as_ref()
            .expect("list reaches the second partition")
            .right
            .as_ref()
            .expect("list reaches the third partition");
        let MerkleTreeNode::Internal {
            left: first_half, ..
        } = third_partition.left.as_ref().as_ref()
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
