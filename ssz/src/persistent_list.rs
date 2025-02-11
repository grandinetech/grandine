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
};

use arithmetic::{NonZeroExt as _, U64Ext as _};
use bit_field::BitField as _;
use derivative::Derivative;
use ethereum_types::H256;
use itertools::Itertools as _;
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use static_assertions::assert_eq_size;
use std_ext::ArcExt as _;
use triomphe::Arc;
use try_from_iterator::TryFromIterator;
use typenum::{Unsigned, U1, U2, U4};

use crate::{
    bundle_size::BundleSize,
    error::{IndexError, PushError, ReadError, WriteError},
    hc::Hc,
    iter::ExactSize,
    merkle_tree::{self, MerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::{FitsInU64, MerkleElements, MinimumBundleSize},
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
        let mut stack;

        match self.root.as_ref() {
            Some(node) => {
                stack = Vec::with_capacity(self.depth().max(1).into());
                stack.push(node.as_ref().as_ref());
            }
            None => stack = vec![],
        };

        ExactSize::new(Leaves { stack }.flatten(), self.length)
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
        };

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
        let mut length = 0;

        let mut nodes_with_heights = elements
            .into_iter()
            .inspect(|_| length += 1)
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
                        left_height + 1,
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
        let results = shared::read_list(context, bytes)?;
        itertools::process_results(results, |elements| Self::try_from_iter(elements))?
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
        Self::repeat_zero(other.len_usize()).expect("lists have the same maximum length")
    }

    #[must_use]
    pub const fn len_usize(&self) -> usize {
        self.length
    }

    #[must_use]
    pub fn len_u64(&self) -> u64
    where
        N: FitsInU64,
    {
        self.length
            .try_into()
            .expect("the bound on N ensures that self.length fits in u64")
    }

    pub fn get(&self, index: u64) -> Result<&T, IndexError>
    where
        B: BundleSize<T>,
    {
        let index = shared::validate_index(self.length, index)?;

        let mut height = self.depth();

        let mut node = self
            .root
            .as_deref()
            .expect("the length check in validate_index ensures that self.root is Some")
            .as_ref();

        let bundle = loop {
            match node {
                Node::Internal {
                    left,
                    right,
                    left_height,
                    right_height,
                } => {
                    assert_eq!(height, left_height + 1);

                    let bit_index = (height + B::ilog2() - 1).into();

                    if index.get_bit(bit_index) {
                        height = *right_height;
                        node = right;
                    } else {
                        height = *left_height;
                        node = left;
                    }
                }
                Node::Leaf { bundle, .. } => {
                    assert_eq!(height, 0);
                    break bundle;
                }
            }
        };

        Ok(&bundle[B::index_in_bundle(index)])
    }

    pub fn get_mut(&mut self, index: u64) -> Result<&mut T, IndexError>
    where
        T: Clone,
        B: BundleSize<T>,
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
                    assert_eq!(height, *left_height + 1);

                    let bit_index = (height + B::ilog2() - 1).into();

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

    // This clones the elements being visited and checks them for mutations to avoid rebuilding
    // parts of the tree that have not been modified. An `Iterator` that behaves the same way would
    // be more convenient, but items returned by an iterator cannot borrow from the iterator itself.
    // The `streaming-iterator` crate attempts to solve that but falls short because it does not
    // allow mutable borrows.
    pub fn update(&mut self, mut updater: impl FnMut(&mut T))
    where
        T: Clone + PartialEq,
        B: BundleSize<T>,
    {
        if let Some(node) = self.root.as_mut() {
            if let Some(new_node) = node.update(&mut updater) {
                *node = new_node;
            }
        }
    }

    pub fn push(&mut self, element: T) -> Result<(), PushError>
    where
        T: Clone,
        N: Unsigned,
        B: BundleSize<T>,
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

        self.length += 1;

        Ok(())
    }

    fn repeat_zero(length: usize) -> Result<Self, ReadError>
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

type Height = u8;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
enum Node<T, B> {
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

    fn leaf(bundle: impl Into<Box<[T]>>) -> Self {
        let bundle = bundle.into();
        let phantom = PhantomData;

        assert!(bundle.len() <= B::USIZE);

        Self::Leaf { bundle, phantom }
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
                    let right_length = length - left_length;

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

    fn push(&mut self, element: T, current_length_and_new_index: usize)
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
                        left_height: left_height + 1,
                        right_height: 0,
                    }
                } else {
                    let left_length = B::USIZE << left_height;
                    assert!(left_length < current_length_and_new_index);

                    let right_length = current_length_and_new_index - left_length;
                    assert!(right_length < left_length);

                    right.make_mut().push(element, right_length);
                    if Self::pushing_increases_height(right_length) {
                        right_height += 1;
                    };
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

    // Mutably borrowing an `FnMut` closure inside a recursive function causes infinite recursion
    // during monomorphization. Borrowing it outside and passing the reference prevents that.
    fn update(&self, updater: &mut impl FnMut(&mut T)) -> Option<Arc<Hc<Self>>>
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

impl<'list, T, B> Iterator for Leaves<'list, T, B> {
    type Item = &'list [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| loop {
            match node {
                Node::Internal { left, right, .. } => {
                    self.stack.push(right);
                    node = left;
                }
                Node::Leaf { bundle, .. } => break bundle.as_ref(),
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

impl<'list, T: Clone, B> Iterator for LeavesMut<'list, T, B> {
    type Item = &'list mut [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| loop {
            match node {
                Node::Internal { left, right, .. } => {
                    self.stack.push(right.make_mut());
                    node = left.make_mut();
                }
                Node::Leaf { bundle, .. } => break bundle.as_mut(),
            }
        })
    }
}

impl<T: Clone, B> FusedIterator for LeavesMut<'_, T, B> {}
