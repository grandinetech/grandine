// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// This implementation is optimized for random access. Some of the lists in `BeaconState` are only
// ever appended to or cleared. An implementation specialized for append-only usage could use less
// memory by taking advantage of the fact that intermediate hashes don't need to be retained for
// subtrees that are completely full.

use core::{
    cmp::Ordering,
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator, Peekable},
    marker::PhantomData,
};

use arithmetic::{NonZeroExt as _, U64Ext as _};
use bit_field::BitField as _;
use derivative::Derivative;
use ethereum_types::H256;
use itertools::Itertools as _;
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
    error::{IndexError, PushError, ReadError, WriteError},
    hc::Hc,
    iter::ExactSize,
    list::{SszList, SszListMut},
    merkle_tree::{self, MerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
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
    type IntoIter = ExactSize<Flatten<Leaves<'list, T, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let leaves = match self.root.as_ref() {
            Some(node) => Leaves::new(node.as_ref().as_ref()),
            None => Leaves { stack: vec![] },
        };

        ExactSize::new(leaves.flatten(), self.length)
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
        let mut length: usize = 0;

        let mut nodes_with_heights = elements
            .into_iter()
            .inspect(|_| length = length.saturating_add(1))
            .chunks(B::USIZE)
            .into_iter()
            .map(Box::from_iter)
            .map(Node::leaf)
            .map(Hc::arc)
            .map(|node| (node, 0))
            .collect_vec();

        Self::validate_length(length)?;

        if length == 0 {
            return Ok(Self::default());
        }

        for _ in 0..B::depth_of_length(length) {
            nodes_with_heights = nodes_with_heights
                .into_iter()
                .chunks(2)
                .into_iter()
                .map(|mut chunk| match (chunk.next(), chunk.next()) {
                    (Some((left, left_height)), Some((right, right_height))) => (
                        Hc::arc(Node::Internal {
                            left,
                            right,
                            left_height,
                            right_height,
                        }),
                        left_height.saturating_add(1),
                    ),
                    (Some(left_over), None) => left_over,
                    _ => unreachable!("Itertools::chunks never yields empty chunks"),
                })
                .collect();
        }

        let (node, root_height) = nodes_with_heights
            .into_iter()
            .exactly_one()
            .ok()
            .expect("only the root should be left");

        assert_eq!(root_height, B::depth_of_length(length));

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
            Some(node) => (self.depth()..Self::max_depth())
                .map(B::zero_hash)
                .fold(node.hash_tree_root(), hashing::hash_256_256),
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

    // Returns the bundle containing the element at `index`.
    // Callers must ensure that `index` is within bounds.
    #[expect(clippy::inline_always)]
    #[inline(always)]
    fn bundle_containing(&self, index: usize) -> &[T]
    where
        B: BundleSize<T>,
    {
        Node::bundle_containing(
            self.root
                .as_ref()
                .expect("callers validate index against self.length, so self.root is Some"),
            index,
        )
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
        let bundle = self.bundle_containing(index);

        Ok(&bundle[B::index_in_bundle(index)])
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

        let mut height = self.depth();

        let mut node = self
            .root
            .as_mut()
            .expect("the length check in validate_index ensures that self.root is Some")
            .make_mut()
            .as_mut();

        let bundle = loop {
            match node {
                Node::Internal {
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
                Node::Leaf { bundle, .. } => {
                    assert_eq!(height, 0);
                    break bundle;
                }
            }
        };

        Ok(&mut bundle[B::index_in_bundle(index)])
    }

    fn extend(&mut self, elements: &mut dyn Iterator<Item = T>) -> Result<(), PushError>
    where
        T: Clone,
    {
        let mut elements = elements.fuse().peekable();

        if elements.peek().is_none() {
            return Ok(());
        }

        let maximum = shared::saturating_usize::<N>();

        if self.length < maximum {
            let mut root = self.root.take().unwrap_or_else(|| Hc::arc(Node::leaf([])));

            let (length, height) =
                Node::append(&mut root, self.depth(), self.length, maximum, &mut elements);

            self.root = Some(root);
            self.length = length;

            assert_eq!(height, self.depth());
        }

        if elements.peek().is_some() {
            return Err(PushError::ListFull);
        }

        Ok(())
    }

    // The retained elements are structurally shared with the original list wherever the range
    // lines up with a subtree.
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

        // Retaining an empty range needs no structural sharing at all.
        *self = if new_length == 0 {
            Self::default()
        } else {
            Self {
                root: Some(Node::slice_subtree(
                    start,
                    new_length,
                    &|start, length| {
                        Node::shared_subtree(
                            self.root
                                .as_ref()
                                .expect("a nonzero length means self.root is Some"),
                            self.length,
                            start,
                            length,
                        )
                    },
                    &|index| self.bundle_containing(index),
                )),
                length: new_length,
                phantom: PhantomData,
            }
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
                right_height,
            } => {
                let right_hash = (*right_height..*left_height)
                    .map(B::zero_hash)
                    .fold(right.hash_tree_root(), hashing::hash_256_256);

                hashing::hash_256_256(left.hash_tree_root(), right_hash)
            }
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

impl<T, B: BundleSize<T>> Node<T, B> {
    fn arc_single(element: T) -> Arc<Hc<Self>> {
        Hc::arc(Self::leaf([element]))
    }

    pub(crate) fn leaf(bundle: impl Into<Box<[T]>>) -> Self {
        let bundle = bundle.into();
        let phantom = PhantomData;

        assert!(bundle.len() <= B::USIZE);

        Self::Leaf { bundle, phantom }
    }

    pub(crate) fn shared_subtree(
        root: &Arc<Hc<Self>>,
        root_length: usize,
        start: usize,
        length: usize,
    ) -> Option<Arc<Hc<Self>>> {
        assert!(length > 0);

        let height = B::depth_of_length(length);
        let span = B::USIZE << height;
        let aligned = start.is_multiple_of(span);
        let full = length == span;
        let trailing = start.saturating_add(length) == root_length;

        if start.saturating_add(length) > root_length || !aligned || !(full || trailing) {
            return None;
        }

        let mut remaining = start;
        let mut node_height = B::depth_of_length(root_length);
        let mut node = root;

        while height < node_height {
            let Self::Internal {
                left,
                right,
                left_height,
                right_height,
            } = node.as_ref().as_ref()
            else {
                return None;
            };

            let left_span = B::USIZE << left_height;

            if remaining < left_span {
                node_height = *left_height;
                node = left;
            } else {
                remaining = remaining.saturating_sub(left_span);
                node_height = *right_height;
                node = right;
            }
        }

        (node_height == height && remaining == 0).then(|| node.clone_arc())
    }

    pub(crate) fn bundle_containing(root: &Arc<Hc<Self>>, index: usize) -> &[T] {
        let mut node = root.as_ref().as_ref();
        let mut height = match node {
            Self::Internal { left_height, .. } => left_height.saturating_add(1),
            Self::Leaf { .. } => 0,
        };

        loop {
            match node {
                Self::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                } => {
                    let bit_index = height.saturating_add(B::ilog2()).saturating_sub(1).into();

                    if index.get_bit(bit_index) {
                        height = *right_height;
                        node = right;
                    } else {
                        height = *left_height;
                        node = left;
                    }
                }
                Self::Leaf { bundle, .. } => return bundle,
            }
        }
    }

    pub(crate) fn slice_subtree<'a>(
        start: usize,
        length: usize,
        shared_subtree: &impl Fn(usize, usize) -> Option<Arc<Hc<Self>>>,
        bundle_containing: &impl Fn(usize) -> &'a [T],
    ) -> Arc<Hc<Self>>
    where
        T: Clone + 'a,
    {
        assert!(length > 0);

        let height = B::depth_of_length(length);

        if let Some(node) = shared_subtree(start, length) {
            return node;
        }

        if height == 0 {
            let mut bundle = Vec::with_capacity(length);
            let mut index = start;

            while bundle.len() < length {
                let source = bundle_containing(index);
                let position = B::index_in_bundle(index);
                let count = length
                    .saturating_sub(bundle.len())
                    .min(source.len().saturating_sub(position));

                assert!(count > 0);

                bundle.extend_from_slice(&source[position..position.saturating_add(count)]);
                index = index.saturating_add(count);
            }

            return Hc::arc(Self::leaf(bundle));
        }

        let left_length = B::USIZE << height.saturating_sub(1);
        let right_length = length.saturating_sub(left_length);

        Hc::arc(Self::Internal {
            left: Self::slice_subtree(start, left_length, shared_subtree, bundle_containing),
            right: Self::slice_subtree(
                start.saturating_add(left_length),
                right_length,
                shared_subtree,
                bundle_containing,
            ),
            left_height: height.saturating_sub(1),
            right_height: B::depth_of_length(right_length),
        })
    }

    pub(crate) fn prune(&mut self, mut length: usize)
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

    pub(crate) fn push(&mut self, element: T, current_length_and_new_index: usize)
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
                if Self::pushing_increases_height(current_length_and_new_index) {
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
                    assert!(left_length < current_length_and_new_index);

                    let right_length = current_length_and_new_index.saturating_sub(left_length);
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

    pub(crate) fn append<I: Iterator<Item = T>>(
        node: &mut Arc<Hc<Self>>,
        height: Height,
        length: usize,
        capacity: usize,
        elements: &mut Peekable<I>,
    ) -> (usize, Height)
    where
        T: Clone,
    {
        let length = Self::fill(node, height, length, capacity, elements);

        Self::grow(node, height, length, capacity, elements)
    }

    // Fills the subtree in `node` up without making it any taller, which is only possible if it is
    // not full already. Returns the new length of the subtree.
    #[expect(clippy::inline_always)]
    #[inline(always)]
    fn fill<I: Iterator<Item = T>>(
        node: &mut Arc<Hc<Self>>,
        height: Height,
        length: usize,
        capacity: usize,
        elements: &mut Peekable<I>,
    ) -> usize
    where
        T: Clone,
    {
        if B::USIZE << height <= length || capacity <= length || elements.peek().is_none() {
            return length;
        }

        match node.make_mut().as_mut() {
            // The left child of an internal node is always full, so the elements can only go into
            // the right one. It may hold as many of them as the left one holds, or fewer if the
            // list runs out of room first.
            Self::Internal {
                right,
                left_height,
                right_height,
                ..
            } => {
                let left_length = B::USIZE << *left_height;

                let (right_length, new_right_height) = Self::append(
                    right,
                    *right_height,
                    length.saturating_sub(left_length),
                    left_length.min(capacity.saturating_sub(left_length)),
                    elements,
                );

                *right_height = new_right_height;

                left_length.saturating_add(right_length)
            }
            Self::Leaf { bundle, .. } => {
                let count = B::USIZE.min(capacity).saturating_sub(bundle.len());

                replace_with::replace_with_or_default(bundle, |bundle| {
                    let mut vec = Vec::from(bundle);
                    vec.reserve_exact(count);
                    vec.extend(elements.by_ref().take(count));
                    vec.into_boxed_slice()
                });

                bundle.len()
            }
        }
    }

    // Makes the subtree in `node`, which must be full, the left child of a new node whose right
    // child holds the elements that follow, until the elements or the room in the list run out.
    // Returns the new length and height of the subtree.
    #[expect(clippy::inline_always)]
    #[inline(always)]
    fn grow<I: Iterator<Item = T>>(
        node: &mut Arc<Hc<Self>>,
        mut height: Height,
        mut length: usize,
        capacity: usize,
        elements: &mut Peekable<I>,
    ) -> (usize, Height)
    where
        T: Clone,
    {
        while length < capacity && elements.peek().is_some() {
            assert_eq!(length, B::USIZE << height);

            // The new right child is as tall as its sibling at most, so it holds as many elements.
            let right_capacity = length.min(capacity.saturating_sub(length));
            let count = B::USIZE.min(right_capacity);
            let mut bundle = Vec::with_capacity(count);

            bundle.extend(elements.by_ref().take(count));

            let bundle_length = bundle.len();
            let mut right = Hc::arc(Self::leaf(bundle));

            let (right_length, right_height) =
                Self::append(&mut right, 0, bundle_length, right_capacity, elements);

            // Leaves are normally never empty. See the comment in `Self::push`.
            let make_dummy_leaf = || Hc::arc(Self::leaf([]));

            replace_with::replace_with(node, make_dummy_leaf, |left| {
                Hc::arc(Self::Internal {
                    left,
                    right,
                    left_height: height,
                    right_height,
                })
            });

            height = height.saturating_add(1);
            length = length.saturating_add(right_length);
        }

        (length, height)
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

    fn pushing_increases_height(current_length_and_new_index: usize) -> bool {
        B::index_of_bundle(current_length_and_new_index).is_power_of_two()
            && B::index_in_bundle(current_length_and_new_index) == 0
    }
}

pub struct Leaves<'list, T, B> {
    // This cannot be an array because array sizes cannot depend on generic parameters. Making this
    // a `GenericArray` of size `PersistentList::depth()` would require a huge number of trait
    // bounds which might not even be expressible because of the lifetime in the element type.
    stack: Vec<&'list Node<T, B>>,
}

impl<'list, T, B> Leaves<'list, T, B> {
    pub(crate) fn new(node: &'list Node<T, B>) -> Self {
        Self { stack: vec![node] }
    }
}

impl<'list, T, B> Iterator for Leaves<'list, T, B> {
    type Item = &'list [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| {
            loop {
                match node {
                    Node::Internal { left, right, .. } => {
                        self.stack.push(right);
                        node = left;
                    }
                    Node::Leaf { bundle, .. } => break bundle.as_ref(),
                }
            }
        })
    }
}

impl<T, B> FusedIterator for Leaves<'_, T, B> {}

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
    fn extend_appends_elements_to_empty_list() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut actual = PersistentList::<u64, U8, U4>::default();
        actual
            .extend(&mut [1, 2, 3].into_iter())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_appends_elements_to_nonempty_list() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual
            .extend(&mut [4, 5].into_iter())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_with_no_elements_does_nothing() {
        let expected =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual
            .extend(&mut core::iter::empty())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_fills_the_list_to_capacity() {
        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");

        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual
            .extend(&mut [4, 5, 6, 7, 8].into_iter())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_returns_error_when_list_would_overflow() {
        let mut actual =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        actual
            .extend(&mut [4, 5, 6, 7, 8, 9].into_iter())
            .expect_err("list only has room for 5 more elements");

        let expected = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5, 6, 7, 8])
            .expect("array fits in the list");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_does_not_affect_a_cloned_original() {
        let original =
            PersistentList::<u64, U8, U4>::try_from([1, 2, 3]).expect("array fits in the list");

        let mut extended = original.clone();
        extended
            .extend(&mut [4, 5].into_iter())
            .expect("list is not full");

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

        actual
            .extend(&mut core::iter::once(9))
            .expect_err("list has no room left");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_grows_an_empty_list_across_multiple_levels() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual = PersistentList::<u64, U64, U4>::default();
        actual.extend(&mut (1..=20)).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_appends_elements_to_a_multi_level_list() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual.extend(&mut (4..=20)).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_in_two_steps_matches_extending_at_once() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=20).expect("range fits in the list");

        let mut actual =
            PersistentList::<u64, U64, U4>::try_from([1, 2, 3]).expect("array fits in the list");
        actual.extend(&mut (4..=10)).expect("list is not full");
        actual.extend(&mut (11..=20)).expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }

    #[test]
    fn extend_fills_a_multi_level_list_to_capacity_before_returning_error() {
        let expected =
            PersistentList::<u64, U64, U4>::try_from_iter(1..=64).expect("range fits in the list");

        let mut actual = PersistentList::<u64, U64, U4>::default();

        actual
            .extend(&mut (1..=100))
            .expect_err("list only has room for 64 elements");

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
    #[should_panic(expected = "retain_range start (3) is greater than retain_range end (1)")]
    fn retain_range_with_start_greater_than_end_panics() {
        let mut list = PersistentList::<u64, U8, U4>::try_from([1, 2, 3, 4, 5])
            .expect("array fits in the list");

        drop(list.retain_range(3, 1));
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
        actual
            .extend(&mut [6, 7].into_iter())
            .expect("list is not full");

        assert_eq!(actual, expected);
        assert_eq!(actual.hash_tree_root(), expected.hash_tree_root());
    }
}
