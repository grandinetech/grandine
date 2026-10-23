// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// This implementation is optimized for random access. Some of the lists in `BeaconState` are only
// ever appended to or cleared. An implementation specialized for append-only usage could use less
// memory by taking advantage of the fact that intermediate hashes don't need to be retained for
// subtrees that are completely full.

use core::{
    cmp::Ordering,
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
    slice,
};

use anyhow::ensure;
use arithmetic::{NonZeroExt as _, U64Ext as _};
use bit_field::BitField as _;
use derivative::Derivative;
use ethereum_types::H256;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
};
use static_assertions::assert_eq_size;
use std_ext::ArcExt as _;
use triomphe::Arc;
use try_from_iterator::TryFromIterator;
use typenum::{U1, U2, U4, Unsigned};

use crate::{
    bundle_size::BundleSize,
    cursor::SszCursor,
    error::{IndexError, PushError, ReadError, WriteError},
    hc::Hc,
    iter::ExactSize,
    list::{SszList, SszListMut},
    merkle_tree::{self, MerkleTree},
    porcelain::{SszHash, SszNavigable, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::{MerkleElements, MinimumBundleSize},
    zero_default::ZeroDefault,
};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Default(bound = "")
)]
pub struct PersistentList<T, N, B = MinimumBundleSize<T>> {
    root: Option<Arc<Hc<Node<T, B>>>>,
    // TODO(32-bit support): Consider changing the type of `length` to `u64`.
    //
    //                       Persistent lists could have more than `usize::MAX` elements due to
    //                       structural sharing, but changing the type of `PersistentList.length`
    //                       may necessitate intrusive changes to the rest of this crate.
    //
    //                       `VALIDATOR_REGISTRY_LIMIT` is 2 ** 40 in the mainnet preset,
    //                       but the number of validators will likely stay far below the maximum.
    //                       Also, `Validator` containers do not benefit from structural sharing,
    //                       so that many validators would not fit in memory on 32 bit machines.
    length: usize,
    phantom: PhantomData<N>,
}

// This could be a `From` impl if feature `generic_const_exprs` were stable.
// See <https://internals.rust-lang.org/t/const-generics-where-restrictions/12742/6>.
impl<T, N, B, const SIZE: usize> TryFrom<[T; SIZE]> for PersistentList<T, N, B>
where
    N: Unsigned,
    B: BundleSize<T>,
{
    type Error = ReadError;

    fn try_from(array: [T; SIZE]) -> Result<Self, Self::Error> {
        Self::validate_length(SIZE)?;
        Self::try_from_iter(array)
    }
}

#[expect(clippy::into_iter_without_iter)]
impl<'list, T, N, B: BundleSize<T>> IntoIterator for &'list PersistentList<T, N, B> {
    type Item = &'list T;
    type IntoIter = ExactSize<Leaves<'list, T, B>>;

    fn into_iter(self) -> Self::IntoIter {
        let leaves = match self.root.as_ref() {
            Some(node) => Leaves::new(node.as_ref().as_ref()),
            None => Leaves {
                stack: vec![],
                bundle: [].iter(),
            },
        };

        ExactSize::new(leaves, self.length)
    }
}

#[expect(clippy::into_iter_without_iter)]
impl<'list, T: Clone, N, B: BundleSize<T>> IntoIterator for &'list mut PersistentList<T, N, B> {
    type Item = &'list mut T;
    type IntoIter = ExactSize<Flatten<LeavesMut<'list, T, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let depth = self.depth();

        let mut stack;

        match self.root.as_mut() {
            Some(node) => {
                stack = Vec::with_capacity(depth.max(1).into());
                stack.push(node.make_mut().as_mut());
            }
            None => stack = vec![],
        }

        ExactSize::new(LeavesMut { stack }.flatten(), self.length)
    }
}

impl<T: Debug, N, B: BundleSize<T>> Debug for PersistentList<T, N, B> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.debug_list().entries(self).finish()
    }
}

impl<T, N: Unsigned, B: BundleSize<T>> TryFromIterator<T> for PersistentList<T, N, B> {
    type Error = ReadError;

    // Unlike `PersistentVector::try_from_iter`, this does not deduplicate consecutive nodes.
    // Due to the nature of data stored in lists, deduplication is far less effective than it is
    // with vectors. Deserializing lists without deduplication is about 20% faster. The absence of
    // deduplication increases memory consumption by a small amount. Interestingly, state
    // transitions appear to be faster when list nodes are not deduplicated. Is it because more
    // `Arc`s are uniquely owned?
    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let Some((node, length)) = Node::build(&mut elements.into_iter(), usize::MAX) else {
            return Ok(Self::default());
        };

        Self::validate_length(length)?;

        assert_eq!(node.height(), B::depth_of_length(length));

        Ok(Self {
            root: Some(node),
            length,
            phantom: PhantomData,
        })
    }
}

impl<'de, T, N, B> Deserialize<'de> for PersistentList<T, N, B>
where
    T: Deserialize<'de>,
    N: Unsigned,
    B: BundleSize<T>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PersistentListVisitor<T, N, B>(PhantomData<(T, N, B)>);

        impl<'de, T, N, B> Visitor<'de> for PersistentListVisitor<T, N, B>
        where
            T: Deserialize<'de>,
            N: Unsigned,
            B: BundleSize<T>,
        {
            type Value = PersistentList<T, N, B>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(
                    formatter,
                    "a list of length up to {}",
                    shared::saturating_usize::<N>(),
                )
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                itertools::process_results(
                    core::iter::from_fn(|| seq.next_element().transpose()),
                    |elements| PersistentList::try_from_iter(elements).map_err(S::Error::custom),
                )?
            }
        }

        deserializer.deserialize_seq(PersistentListVisitor(PhantomData))
    }
}

impl<T: Serialize, N, B: BundleSize<T>> Serialize for PersistentList<T, N, B> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self)
    }
}

impl<T: SszSize, N, B> SszSize for PersistentList<T, N, B> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, T: SszRead<C>, N: Unsigned, B: BundleSize<T>> SszRead<C> for PersistentList<T, N, B> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        // TODO(32-bit support): remove saturating_usize, in favor of using u64 for max length checks.
        //
        // this saturating_usize is setting hard limit on 32-bit architectures, where maximum length
        // doesn't fit in 4-byte usize. On 32-bit architectures (for instance zkvms), maximum overflows
        // and becomes 0, failing to deserialize valid structures - BeaconState for example, as it has
        // `validators` field, which upper limit is set to 1099511627776 (2^40).
        shared::read_list(shared::saturating_usize::<N>(), context, bytes)
    }
}

impl<T, N, B> TryFrom<SszCursor<'_>> for PersistentList<T, N, B>
where
    Self: SszRead<()>,
{
    type Error = ReadError;

    fn try_from(cursor: SszCursor<'_>) -> Result<Self, ReadError> {
        cursor.read(&())
    }
}

impl<T, N, B> SszNavigable for PersistentList<T, N, B>
where
    Self: SszRead<()>,
{
    type View<'cursor> = Self;
}

impl<T: SszWrite, N, B: BundleSize<T>> SszWrite for PersistentList<T, N, B> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self)
    }
}

impl<T, N, B> SszHash for PersistentList<T, N, B>
where
    T: SszHash + SszWrite,
    N: Unsigned,
    B: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = match self.root.as_ref() {
            Some(node) => node.root_at(Self::max_depth()),
            None => B::zero_hash(Self::max_depth()),
        };

        merkle_tree::mix_in_length(root, self.length)
    }
}

impl<T, N, B> PersistentList<T, N, B> {
    #[must_use]
    pub fn repeat_zero_with_length_of<U, B2>(other: &PersistentList<U, N, B2>) -> Self
    where
        T: ZeroDefault + SszHash + SszWrite + Clone,
        N: Unsigned,
        B: BundleSize<T> + MerkleElements<T>,
        B2: BundleSize<U>,
    {
        Self::repeat_zero(other.length).expect("lists have the same maximum length")
    }

    pub fn repeat_zero(length: usize) -> Result<Self, ReadError>
    where
        T: ZeroDefault + SszHash + SszWrite + Clone,
        N: Unsigned,
        B: BundleSize<T> + MerkleElements<T>,
    {
        Self::validate_length(length)?;

        if length == 0 {
            return Ok(Self::default());
        }

        // `From<[T; N]>` for `Box` cannot be used here until `generic_const_exprs` is stable.
        let mut node = Node::leaf(vec![T::default(); B::USIZE]);

        // Construct a perfect binary tree with full structural sharing, then prune it.
        for height in 0..B::depth_of_length(length) {
            // This is the part that relies on `T` implementing `ZeroDefault`.
            let hc = Hc::with_root(node, B::zero_hash(height));
            let arc = Arc::new(hc);

            node = Node::Internal {
                left: arc.clone_arc(),
                right: arc,
                left_height: height,
                right_height: height,
            };
        }

        node.prune(length);

        Ok(Self {
            root: Some(Hc::arc(node)),
            length,
            phantom: PhantomData,
        })
    }

    fn depth(&self) -> u8
    where
        B: BundleSize<T>,
    {
        B::depth_of_length(self.length)
    }

    fn max_depth() -> u8
    where
        N: Unsigned,
        B: BundleSize<T>,
    {
        // TODO(32-bit support): Rethink the new code.
        //                       Try to avoid referring to `Unsigned::U64` or `Unsigned::U128`.
        //                       Try to redesign `BundleSize::depth_of_length` to be usable again.
        N::U64.ilog2_ceil().saturating_sub(B::ilog2())
    }

    const fn validate_length(actual: usize) -> Result<(), ReadError>
    where
        N: Unsigned,
    {
        let maximum = shared::saturating_usize::<N>();

        if actual > maximum {
            return Err(ReadError::ListTooLong { maximum, actual });
        }

        Ok(())
    }
}

impl<T, N, B> SszList<T> for PersistentList<T, N, B>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    N: Unsigned + Send + Sync,
    B: BundleSize<T> + MerkleElements<T> + Send + Sync,
{
    fn len_usize(&self) -> usize {
        self.length
    }

    fn len_u64(&self) -> u64 {
        u64::try_from(self.length).expect("list length fits in u64")
    }

    fn get(&self, index: u64) -> Result<&T, IndexError> {
        let index = shared::validate_index(self.length, index)?;

        let node = self
            .root
            .as_deref()
            .expect("the length check in validate_index ensures that self.root is Some");

        Ok(node.get(index))
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

impl<T, N, B> SszListMut<T> for PersistentList<T, N, B>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    N: Unsigned + Send + Sync,
    B: BundleSize<T> + MerkleElements<T> + Send + Sync,
{
    fn get_mut(&mut self, index: u64) -> Result<&mut T, IndexError>
    where
        T: Clone,
    {
        let index = shared::validate_index(self.length, index)?;

        let node = self
            .root
            .as_mut()
            .expect("the length check in validate_index ensures that self.root is Some")
            .make_mut()
            .as_mut();

        Ok(node.get_mut(index))
    }

    fn extend(&mut self, elements: &[T]) -> Result<(), PushError>
    where
        T: Clone,
    {
        if elements.len() > shared::saturating_usize::<N>().saturating_sub(self.length) {
            return Err(PushError::ListFull);
        }

        match self.root.as_mut() {
            Some(root) => self.length = Node::append(root, self.length, elements),
            None => {
                if let Some((root, length)) =
                    Node::build(&mut elements.iter().cloned(), elements.len())
                {
                    self.root = Some(root);
                    self.length = length;
                }
            }
        }

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

        if new_length == 0 {
            *self = Self::default();
            return Ok(());
        }

        if B::index_in_bundle(start) != 0 {
            *self = Self::try_from_iter((&*self).into_iter().skip(start).take(new_length).cloned())
                .expect("the retained elements fit in the list");

            return Ok(());
        }

        let root = self
            .root
            .as_ref()
            .expect("a nonzero length means self.root is Some");

        let mut cursor = SubtreeCursor::new(root, self.length, start);

        *self = Self {
            root: Some(cursor.slice(new_length)),
            length: new_length,
            phantom: PhantomData,
        };

        Ok(())
    }

    fn push(&mut self, element: T) -> Result<(), PushError>
    where
        T: Clone,
    {
        // TODO(32-bit support): Review change.
        let length_u64: u64 = self
            .length
            .try_into()
            .expect("PersistentList length counter should fit to u64");

        match length_u64.cmp(&N::U64) {
            Ordering::Less => {}
            Ordering::Equal => return Err(PushError::ListFull),
            Ordering::Greater => unreachable!("case above prevents list from being overfilled"),
        }

        match self.root.as_mut() {
            Some(node) => node.make_mut().push(element, self.length),
            None => self.root = Some(Node::arc_single(element)),
        }

        self.length = self.length.saturating_add(1);

        Ok(())
    }

    // This clones the elements being visited and checks them for mutations to avoid rebuilding
    // parts of the tree that have not been modified. An `Iterator` that behaves the same way would
    // be more convenient, but items returned by an iterator cannot borrow from the iterator itself.
    // The `streaming-iterator` crate attempts to solve that but falls short because it does not
    // allow mutable borrows.
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

    fn iter_mut<'a>(&'a mut self) -> Box<dyn ExactSizeIterator<Item = &'a mut T> + 'a>
    where
        T: Clone,
    {
        Box::new(self.into_iter())
    }

    fn try_assign_from_iter(&mut self, iter: &mut dyn Iterator<Item = T>) -> Result<(), ReadError> {
        *self = Self::try_from_iter(iter)?;
        Ok(())
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

        self.root
            .as_mut()
            .expect("the checks above ensure that self.root is Some")
            .make_mut()
            .as_mut()
            .update_at(0, indices, f)
    }
}

type Height = u8;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
pub enum Node<T, B> {
    Internal {
        left: Arc<Hc<Self>>,
        right: Arc<Hc<Self>>,
        left_height: Height,
        right_height: Height,
    },
    Leaf {
        // Box the bundle to make `Node` smaller at the cost of a small slowdown.
        // This saves ~450 MB (according to profilers) when processing 1024 mainnet Altair blocks.
        // `Box<GenericArrayVec<T, B>>` is easier to use but makes the allocation bigger.
        // Using `Box<[T]>` saves another 50 MB.
        // `Vec` is too complicated for enum layout optimizations.
        bundle: Box<[T]>,
        phantom: PhantomData<B>,
    },
}

assert_eq_size!(Node<H256, U1>, Node<H256, U2>, Node<H256, U4>, [usize; 3]);

impl<T, B> SszHash for Node<T, B>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Internal {
                left,
                right,
                left_height,
                ..
            } => hashing::hash_256_256(left.hash_tree_root(), right.root_at(*left_height)),
            Self::Leaf { bundle, .. } => {
                if T::PackingFactor::USIZE == 1 {
                    let chunks = bundle.iter().map(SszHash::hash_tree_root);
                    MerkleTree::<<B as MerkleElements<T>>::UnpackedMerkleTreeDepth>
                        ::merkleize_chunks(chunks)
                } else {
                    MerkleTree::<<B as MerkleElements<T>>::PackedMerkleTreeDepth>::merkleize_packed(
                        bundle,
                    )
                }
            }
        }
    }
}

impl<T, B> Hc<Node<T, B>>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
{
    pub(crate) fn root_at(&self, height: Height) -> H256 {
        assert!(self.height() <= height);

        (self.height()..height)
            .map(B::zero_hash)
            .fold(self.hash_tree_root(), hashing::hash_256_256)
    }
}

impl<T, B: BundleSize<T>> Node<T, B> {
    pub(crate) fn update_at(
        &mut self,
        start: u64,
        indices: &[u64],
        f: &mut (impl FnMut(u64, &mut T) -> Result<(), anyhow::Error> + ?Sized),
    ) -> Result<(), anyhow::Error>
    where
        T: Clone,
    {
        match self {
            Self::Internal {
                left,
                right,
                left_height,
                ..
            } => {
                let right_start =
                    start.saturating_add(1_u64 << left_height.saturating_add(B::ilog2()));

                let (left_indices, right_indices) =
                    indices.split_at(indices.partition_point(|index| *index < right_start));

                if !left_indices.is_empty() {
                    left.make_mut().as_mut().update_at(start, left_indices, f)?;
                }

                if !right_indices.is_empty() {
                    right
                        .make_mut()
                        .as_mut()
                        .update_at(right_start, right_indices, f)?;
                }
            }
            Self::Leaf { bundle, .. } => {
                for &index in indices {
                    let element = &mut bundle[usize::try_from(index.saturating_sub(start))?];
                    f(index, element)?;
                }
            }
        }

        Ok(())
    }

    fn arc_single(element: T) -> Arc<Hc<Self>> {
        Hc::arc(Self::leaf([element]))
    }

    pub(crate) fn leaf(bundle: impl Into<Box<[T]>>) -> Self {
        let bundle = bundle.into();
        let phantom = PhantomData;

        assert!(bundle.len() <= B::USIZE);

        Self::Leaf { bundle, phantom }
    }

    pub(crate) fn internal(left: Arc<Hc<Self>>, right: Arc<Hc<Self>>) -> Self {
        Self::Internal {
            left_height: left.height(),
            right_height: right.height(),
            left,
            right,
        }
    }

    pub(crate) const fn height(&self) -> Height {
        match self {
            Self::Internal { left_height, .. } => left_height.saturating_add(1),
            Self::Leaf { .. } => 0,
        }
    }

    // All leaves are allocated before any internal node, and internal nodes one level at a time.
    // Trees built in that order are iterated about twice as fast as ones built depth-first.
    pub(crate) fn build(
        elements: &mut impl Iterator<Item = T>,
        capacity: usize,
    ) -> Option<(Arc<Hc<Self>>, usize)> {
        let mut nodes_with_heights = vec![];
        let mut count: usize = 0;

        while count < capacity {
            let bundle: Box<[T]> = elements.by_ref().take(B::USIZE).collect();

            if bundle.is_empty() {
                break;
            }

            let exhausted = bundle.len() < B::USIZE;

            count = count.saturating_add(bundle.len());
            nodes_with_heights.push((Hc::arc(Self::leaf(bundle)), 0));

            if exhausted {
                break;
            }
        }

        while nodes_with_heights.len() > 1 {
            let mut level = nodes_with_heights.into_iter();

            nodes_with_heights = core::iter::from_fn(|| {
                let (left, left_height) = level.next()?;

                let Some((right, right_height)) = level.next() else {
                    return Some((left, left_height));
                };

                let node = Self::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                };

                Some((Hc::arc(node), left_height.saturating_add(1)))
            })
            .collect();
        }

        let (node, _) = nodes_with_heights.pop()?;

        Some((node, count))
    }

    pub(crate) fn get(&self, index: usize) -> &T {
        let mut node = self;
        let mut height = self.height();

        let bundle = loop {
            match node {
                Self::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                } => {
                    assert_eq!(height, left_height.saturating_add(1));

                    let bit_index = height.saturating_add(B::ilog2()).saturating_sub(1).into();

                    if index.get_bit(bit_index) {
                        height = *right_height;
                        node = right;
                    } else {
                        height = *left_height;
                        node = left;
                    }
                }
                Self::Leaf { bundle, .. } => {
                    assert_eq!(height, 0);
                    break bundle;
                }
            }
        };

        &bundle[B::index_in_bundle(index)]
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> &mut T
    where
        T: Clone,
    {
        let mut height = self.height();
        let mut node = self;

        let bundle = loop {
            match node {
                Self::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                } => {
                    assert_eq!(height, left_height.saturating_add(1));

                    let bit_index = height.saturating_add(B::ilog2()).saturating_sub(1).into();

                    if index.get_bit(bit_index) {
                        height = *right_height;
                        node = right.make_mut();
                    } else {
                        height = *left_height;
                        node = left.make_mut();
                    }
                }
                Self::Leaf { bundle, .. } => {
                    assert_eq!(height, 0);
                    break bundle;
                }
            }
        };

        &mut bundle[B::index_in_bundle(index)]
    }

    fn prune(&mut self, mut length: usize)
    where
        T: Clone,
    {
        assert!(0 < length);

        let mut node = self;

        loop {
            match node {
                Self::Internal {
                    left, left_height, ..
                } if B::depth_of_length(length) <= *left_height => {
                    *node = left.as_ref().as_ref().clone();
                }
                Self::Internal {
                    right,
                    right_height,
                    ..
                } => {
                    let left_length = length.next_power_of_two() / 2;
                    let right_length = length.saturating_sub(left_length);

                    assert!(0 < right_length);

                    if left_length == right_length {
                        return;
                    }

                    *right_height = B::depth_of_length(right_length);

                    node = right.make_mut().as_mut();
                    length = right_length;
                }
                Self::Leaf { bundle, .. } => {
                    assert!(length <= B::USIZE);

                    replace_with::replace_with_or_default(bundle, |bundle| {
                        let mut vec = Vec::from(bundle);
                        vec.truncate(length);
                        vec.into_boxed_slice()
                    });

                    return;
                }
            }
        }
    }

    pub(crate) fn push(&mut self, element: T, index: usize)
    where
        T: Clone,
    {
        // Leaves are normally never empty. An empty leaf should only be created if the call to
        // `replace_with` below panics. Using `replace_with::replace_with_or_abort` would make this
        // unnecessary but would leave no stacktrace if the code below panicked due to a bug.
        let make_dummy_leaf = || Self::leaf([]);

        replace_with::replace_with(self, make_dummy_leaf, |node| match node {
            Self::Internal {
                left,
                mut right,
                left_height,
                mut right_height,
            } => {
                if Self::pushing_increases_height(index) {
                    assert_eq!(left_height, right_height);

                    Self::Internal {
                        left: Hc::arc(Self::Internal {
                            left,
                            right,
                            left_height,
                            right_height,
                        }),
                        right: Self::arc_single(element),
                        left_height: left_height.saturating_add(1),
                        right_height: 0,
                    }
                } else {
                    let left_length = B::USIZE << left_height;
                    assert!(left_length < index);

                    let right_length = index.saturating_sub(left_length);
                    assert!(right_length < left_length);

                    right.make_mut().push(element, right_length);
                    if Self::pushing_increases_height(right_length) {
                        right_height = right_height.saturating_add(1);
                    }
                    assert!(right_height <= left_height);

                    Self::Internal {
                        left,
                        right,
                        left_height,
                        right_height,
                    }
                }
            }
            Self::Leaf { bundle, .. } => {
                if bundle.len() == B::USIZE {
                    Self::Internal {
                        left: Hc::arc(Self::leaf(bundle)),
                        right: Self::arc_single(element),
                        left_height: 0,
                        right_height: 0,
                    }
                } else {
                    let mut vec = Vec::from(bundle);
                    vec.reserve_exact(1);
                    vec.push(element);
                    Self::leaf(vec)
                }
            }
        })
    }

    pub(crate) fn append(node: &mut Arc<Hc<Self>>, length: usize, elements: &[T]) -> usize
    where
        T: Clone,
    {
        let (length, elements) = Self::fill(node, length, elements);

        Self::grow(node, length, elements)
    }

    // Appends elements without making `node` taller, so only as many as it has room for:
    //
    //               h3                                h3
    //          /          \                      /          \
    //       h2              4                 h2              h2
    //     /    \                + 5..7      /    \          /    \
    //   h1      h1               -->      h1      h1      h1      h1
    //  /  \    /  \                      /  \    /  \    /  \    /  \
    // 0    1  2    3                    0    1  2    3  4    5  6    7
    fn fill<'elements>(
        node: &mut Arc<Hc<Self>>,
        length: usize,
        elements: &'elements [T],
    ) -> (usize, &'elements [T])
    where
        T: Clone,
    {
        let room = (B::USIZE << node.height()).saturating_sub(length);

        if room == 0 || elements.is_empty() {
            return (length, elements);
        }

        let (now, later) = elements.split_at(room.min(elements.len()));

        let length = match node.make_mut().as_mut() {
            // The left child of an internal node is always full, so the elements can only go into
            // the right one.
            Self::Internal {
                right,
                left_height,
                right_height,
                ..
            } => {
                let left_length = B::USIZE << *left_height;
                let right_length = Self::append(right, length.saturating_sub(left_length), now);

                *right_height = right.height();

                left_length.saturating_add(right_length)
            }
            Self::Leaf { bundle, .. } => {
                replace_with::replace_with_or_default(bundle, |bundle| {
                    let mut vec = Vec::from(bundle);
                    vec.extend_from_slice(now);
                    vec.into_boxed_slice()
                });

                bundle.len()
            }
        };

        (length, later)
    }

    // Makes the full `node` the left child of a new root, until all elements are in:
    //
    //                                     h4
    //                                /          \
    //     h3      + 8..11         h3              h2
    //   (0..7)      -->         (0..7)          /    \
    //                                         h1      h1
    //                                        /  \    /  \
    //                                       8    9  10   11
    fn grow(node: &mut Arc<Hc<Self>>, mut length: usize, mut elements: &[T]) -> usize
    where
        T: Clone,
    {
        while !elements.is_empty() {
            let height = node.height();

            assert_eq!(length, B::USIZE << height);

            // The new right child is as tall as its sibling at most, so it holds as many elements.
            let (now, later) = elements.split_at(length.min(elements.len()));

            let (right, right_length) =
                Self::build(&mut now.iter().cloned(), now.len()).expect("now is not empty");

            *node = Hc::arc(Self::internal(node.clone_arc(), right));

            length = length.saturating_add(right_length);
            elements = later;
        }

        length
    }

    // Mutably borrowing an `FnMut` closure inside a recursive function causes infinite recursion
    // during monomorphization. Borrowing it outside and passing the reference prevents that.
    pub(crate) fn update(&self, updater: &mut impl FnMut(&mut T)) -> Option<Arc<Hc<Self>>>
    where
        T: Clone + PartialEq,
    {
        match self {
            Self::Internal {
                left,
                right,
                left_height,
                right_height,
            } => {
                let (left, right) = match (left.update(updater), right.update(updater)) {
                    (Some(new_left), Some(new_right)) => (new_left, new_right),
                    (Some(new_left), None) => (new_left, right.clone_arc()),
                    (None, Some(new_right)) => (left.clone_arc(), new_right),
                    (None, None) => return None,
                };
                Some(Hc::arc(Self::Internal {
                    left,
                    right,
                    left_height: *left_height,
                    right_height: *right_height,
                }))
            }
            Self::Leaf { bundle, .. } => {
                let mut clone = bundle.clone();
                clone.iter_mut().for_each(updater);
                (bundle != &clone).then(|| Hc::arc(Self::leaf(clone)))
            }
        }
    }

    fn pushing_increases_height(index: usize) -> bool {
        B::index_of_bundle(index).is_power_of_two() && B::index_in_bundle(index) == 0
    }
}

pub struct SubtreeCursor<'tree, T, B> {
    // The nodes from the root down to one holding the element at `position`.
    path: Vec<SubtreeCursorFrame<'tree, T, B>>,
    position: usize,
    end: usize,
}

struct SubtreeCursorFrame<'tree, T, B> {
    node: &'tree Arc<Hc<Node<T, B>>>,
    start: usize,
    end: usize,
}

impl<'tree, T, B: BundleSize<T>> SubtreeCursor<'tree, T, B> {
    pub(crate) fn new(root: &'tree Arc<Hc<Node<T, B>>>, length: usize, position: usize) -> Self {
        Self {
            path: vec![SubtreeCursorFrame {
                node: root,
                start: 0,
                end: length,
            }],
            position,
            end: length,
        }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.end.saturating_sub(self.position)
    }

    pub(crate) fn slice(&mut self, length: usize) -> Arc<Hc<Node<T, B>>>
    where
        T: Clone,
    {
        if let Some(node) = self.next_subtree(length) {
            return node;
        }

        let height = B::depth_of_length(length);

        if height == 0 {
            let mut bundle = Vec::with_capacity(length);
            self.copy_elements(length, &mut bundle);
            return Hc::arc(Node::leaf(bundle));
        }

        let left_length = B::USIZE << height.saturating_sub(1);
        let left = self.slice(left_length);
        let right = self.slice(length.saturating_sub(left_length));

        Hc::arc(Node::internal(left, right))
    }

    fn next_subtree(&mut self, length: usize) -> Option<Arc<Hc<Node<T, B>>>> {
        let end = self.position.saturating_add(length);

        self.descend(end);

        let node = self
            .path
            .last()
            .filter(|frame| frame.start == self.position && frame.end == end)?
            .node
            .clone_arc();

        self.advance(length);

        Some(node)
    }

    pub(crate) fn copy_elements(&mut self, count: usize, elements: &mut Vec<T>)
    where
        T: Clone,
    {
        let end = self.position.saturating_add(count);

        while self.position < end {
            // No node ends where it starts, so this descends to a leaf.
            self.descend(self.position);

            let &SubtreeCursorFrame {
                node,
                start,
                end: leaf_end,
            } = self
                .path
                .last()
                .expect("the cursor is not past the end of the tree");

            let Node::Leaf { bundle, .. } = node.as_ref().as_ref() else {
                unreachable!("the path was just extended down to a leaf");
            };

            let first = self.position.saturating_sub(start);
            let last = end.min(leaf_end).saturating_sub(start);

            elements.extend_from_slice(&bundle[first..last]);
            self.advance(last.saturating_sub(first));
        }
    }

    fn advance(&mut self, count: usize) {
        self.position = self.position.saturating_add(count);

        while let Some(frame) = self.path.last()
            && frame.end <= self.position
        {
            self.path.pop();
        }
    }

    // Descends to the first node that starts at `position` and ends at or before `end`, or to the
    // leaf holding the element at `position` if there is no such node.
    fn descend(&mut self, end: usize) {
        while let Some(&SubtreeCursorFrame {
            node,
            start,
            end: node_end,
        }) = self.path.last()
            && (start < self.position || end < node_end)
            && let Node::Internal {
                left,
                right,
                left_height,
                ..
            } = node.as_ref().as_ref()
        {
            let middle = start.saturating_add(B::USIZE << left_height);

            let frame = if self.position < middle {
                SubtreeCursorFrame {
                    node: left,
                    start,
                    end: middle,
                }
            } else {
                SubtreeCursorFrame {
                    node: right,
                    start: middle,
                    end: node_end,
                }
            };

            self.path.push(frame);
        }
    }
}

pub struct Leaves<'list, T, B> {
    // This cannot be an array because array sizes cannot depend on generic parameters. Making this
    // a `GenericArray` of size `PersistentList::depth()` would require a huge number of trait
    // bounds which might not even be expressible because of the lifetime in the element type.
    stack: Vec<&'list Node<T, B>>,
    bundle: slice::Iter<'list, T>,
}

impl<'list, T, B: BundleSize<T>> Leaves<'list, T, B> {
    pub(crate) fn new(node: &'list Node<T, B>) -> Self {
        Self {
            stack: vec![node],
            bundle: [].iter(),
        }
    }

    // Returns what is left of the current leaf, or the next leaf if nothing is.
    pub(crate) fn next_leaf(&mut self) -> Option<&'list [T]> {
        if self.bundle.len() == 0 {
            let node = self.stack.pop()?;
            self.descend(node, 0);
        }

        Some(core::mem::take(&mut self.bundle).as_slice())
    }

    // Returns the index of the element within the leaf it descends to.
    fn descend(&mut self, mut node: &'list Node<T, B>, mut index: usize) -> usize {
        loop {
            match node {
                Node::Internal {
                    left,
                    right,
                    left_height,
                    ..
                } => {
                    let left_length = B::USIZE << left_height;

                    if index < left_length {
                        self.stack.push(right);
                        node = left;
                    } else {
                        index = index.saturating_sub(left_length);
                        node = right;
                    }
                }
                Node::Leaf { bundle, .. } => {
                    self.bundle = bundle.iter();
                    return index;
                }
            }
        }
    }
}

impl<'list, T, B: BundleSize<T>> Iterator for Leaves<'list, T, B> {
    type Item = &'list T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(element) = self.bundle.next() {
                return Some(element);
            }

            let node = self.stack.pop()?;
            self.descend(node, 0);
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let remaining = self.bundle.len();

        if let Some(element) = self.bundle.nth(n) {
            return Some(element);
        }

        let mut n = n.saturating_sub(remaining);

        // Only the last subtree on the stack can be partially filled. Skipping past its capacity
        // means skipping past the end.
        while let Some(node) = self.stack.pop() {
            let length = B::USIZE << node.height();

            if n < length {
                let index = self.descend(node, n);
                return self.bundle.nth(index);
            }

            n = n.saturating_sub(length);
        }

        None
    }

    fn fold<A, F: FnMut(A, Self::Item) -> A>(mut self, init: A, mut f: F) -> A {
        let mut accumulator = init;

        loop {
            accumulator = core::mem::take(&mut self.bundle).fold(accumulator, &mut f);

            let Some(node) = self.stack.pop() else {
                return accumulator;
            };

            self.descend(node, 0);
        }
    }
}

impl<T, B: BundleSize<T>> FusedIterator for Leaves<'_, T, B> {}

// TODO(Grandine Team): `LeavesMut::next` clones `right` nodes earlier than needed.
//                      Try replacing the `Vec` with a stack of mutable references
//                      from the `recursive_reference` or `generic-cursors` crates.
pub struct LeavesMut<'list, T, B> {
    // This cannot be an array because array sizes cannot depend on generic parameters. Making this
    // a `GenericArray` of size `PersistentList::depth()` would require a huge number of trait
    // bounds which might not even be expressible because of the lifetime in the element type.
    stack: Vec<&'list mut Node<T, B>>,
}

impl<'list, T, B> LeavesMut<'list, T, B> {
    pub(crate) fn new(node: &'list mut Node<T, B>) -> Self {
        Self { stack: vec![node] }
    }
}

impl<'list, T: Clone, B> Iterator for LeavesMut<'list, T, B> {
    type Item = &'list mut [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| {
            loop {
                match node {
                    Node::Internal { left, right, .. } => {
                        self.stack.push(right.make_mut());
                        node = left.make_mut();
                    }
                    Node::Leaf { bundle, .. } => break bundle.as_mut(),
                }
            }
        })
    }
}

impl<T: Clone, B> FusedIterator for LeavesMut<'_, T, B> {}

#[cfg(test)]
mod tests {
    use typenum::{U8, U64};

    use super::*;

    #[test]
    fn update_at_changes_the_same_elements_as_get_mut() {
        type List = PersistentList<u64, typenum::U4096, U4>;

        for length in [1_u64, 3, 4, 5, 15, 16, 17, 100, 1023, 1024, 1025, 3000] {
            let base = List::try_from_iter(0..length).expect("length is below the maximum");

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
                "an index past the end is reported",
            );
            assert_eq!(list, base, "nothing is changed before the error");
        }
    }

    #[test]
    fn update_at_stops_at_the_first_callback_error() {
        let mut list = PersistentList::<u64, typenum::U4096, U4>::try_from_iter(0..100)
            .expect("length is below the maximum");

        let indices = (0..100).collect::<Vec<_>>();

        let result = list.update_at(&indices, &mut |index, element| {
            ensure!(index != 50, "callback failed");
            *element += 1000;
            Ok(())
        });

        assert!(result.is_err());

        for index in 0..100 {
            let expected = if index < 50 { index + 1000 } else { index };
            assert_eq!(*list.get(index).expect("index is in the list"), expected);
        }
    }

    #[test]
    fn update_at_rejects_unsorted_indices() {
        let mut list = PersistentList::<u64, typenum::U4096, U4>::try_from_iter(0..16)
            .expect("length is below the maximum");

        assert!(list.update_at(&[1, 0], &mut |_, _| Ok(())).is_err());
    }

    #[test]
    fn extend_appends_elements_to_empty_list() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::default();
        actual.extend(&[1, 2, 3]).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_appends_elements_to_nonempty_list() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual.extend(&[4, 5]).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_with_no_elements_does_nothing() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual.extend(&[]).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_fills_the_list_to_capacity() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual.extend(&[4, 5, 6, 7, 8]).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_leaves_the_list_unchanged_when_it_would_overflow() {
        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        actual
            .extend(&[4, 5, 6, 7, 8, 9])
            .expect_err("list only has room for 5 more elements");

        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_does_not_affect_a_cloned_original() {
        let original =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut extended = original.clone();
        extended.extend(&[4, 5]).expect("list is not full");

        let expected_original =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        assert_eq!(original, expected_original);
        assert_eq!(
            original.hash_tree_root(),
            expected_original.hash_tree_root(),
        );

        let expected_extended = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        assert_eq!(extended, expected_extended);
        assert_eq!(
            extended.hash_tree_root(),
            expected_extended.hash_tree_root(),
        );
    }

    #[test]
    fn extend_returns_error_when_list_is_already_full() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");

        actual.extend(&[9]).expect_err("list has no room left");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_grows_an_empty_list_across_multiple_levels() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual = PersistentList::<u64, U64, U4>::default();
        actual
            .extend(&(1..=20).collect::<Vec<_>>())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_appends_elements_to_a_multi_level_list() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual
            .extend(&(4..=20).collect::<Vec<_>>())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_in_two_steps_matches_extending_at_once() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual
            .extend(&(4..=10).collect::<Vec<_>>())
            .expect("list is not full");
        actual
            .extend(&(11..=20).collect::<Vec<_>>())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_leaves_a_multi_level_list_unchanged_when_it_would_overflow() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual = expected.clone();

        actual
            .extend(&(21..=100).collect::<Vec<_>>())
            .expect_err("list only has room for 44 more elements");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_full_range_keeps_the_whole_list() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(0, 5).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_middle_range_keeps_the_elements_in_that_range() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([2, 3, 4]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(1, 4).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_prefix_keeps_the_leading_elements() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(0, 3).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_suffix_keeps_the_trailing_elements() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([3, 4, 5]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(2, 5).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_empty_range_empties_the_list() {
        let expected = PersistentList::<u64, U8, U4>::default();

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(2, 2).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_out_of_bounds_returns_an_error() {
        let mut list =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        list.retain_range(0, 10)
            .expect_err("list only has 3 elements");
    }

    #[test]
    fn retain_range_of_empty_list_keeps_it_empty() {
        let expected = PersistentList::<u64, U8, U4>::default();

        let mut actual = PersistentList::<u64, U8, U4>::default();
        actual.retain_range(0, 0).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_spanning_multiple_bundles_keeps_the_elements_in_that_range() {
        let expected = PersistentList::<u64, U8, U4>::try_from([3, 4, 5, 6, 7])
            .expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");
        actual.retain_range(2, 7).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_with_start_greater_than_end_returns_an_error() {
        let mut list = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");

        list.retain_range(3, 1)
            .expect_err("start is greater than end");
    }

    #[test]
    fn retain_range_starting_at_the_end_empties_the_list() {
        let expected = PersistentList::<u64, U8, U4>::default();

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(5, 5).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_nonempty_range_of_empty_list_returns_an_error() {
        let mut list = PersistentList::<u64, U8, U4>::default();

        list.retain_range(0, 1).expect_err("list has no elements");
    }

    #[test]
    fn retain_range_of_a_retain_range_keeps_the_elements_in_both_ranges() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([3, 4]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(1, 5).expect("range is within bounds");
        actual.retain_range(1, 3).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_aligned_multi_level_range_keeps_the_elements_in_that_range() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(5..=20).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");
        actual.retain_range(4, 20).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn retain_range_of_unaligned_multi_level_range_keeps_the_elements_in_that_range() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(6..=17).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");
        actual.retain_range(5, 17).expect("range is within bounds");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn nth_matches_a_vec_after_any_number_of_elements() {
        for length in 0..40 {
            let list = PersistentList::<u64, U64, U4>::try_from_iter(0..length)
                .expect("length is below the maximum");
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
        type Packed = PersistentList<u64, U64, U4>;
        type Unpacked = PersistentList<H256, U64, U1>;

        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..40 {
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
        type List = PersistentList<H256, U64, U1>;

        let element = |index: u64| H256::from_low_u64_be(index.saturating_add(1));

        for length in 0..40 {
            let original =
                List::try_from_iter((0..length).map(element)).expect("length is below the maximum");

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
    fn retain_range_of_an_aligned_full_subtree_shares_it_with_the_original() {
        let list =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual = list.clone();
        actual.retain_range(0, 16).expect("range is within bounds");

        let Node::Internal { left, .. } = list
            .root
            .as_ref()
            .expect("a list of 20 elements has a root")
            .as_ref()
            .as_ref()
        else {
            unreachable!("a list of 20 elements has an internal root")
        };

        let root = actual.root.as_ref().expect("the slice is not empty");

        assert!(Arc::ptr_eq(left, root));
    }

    #[test]
    fn extend_after_retain_range_appends_from_the_new_end() {
        let expected = PersistentList::<u64, U8, U4>::try_from([2, 3, 4, 5, 6, 7])
            .expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");
        actual.retain_range(1, 5).expect("range is within bounds");
        actual.extend(&[6, 7]).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }
}
