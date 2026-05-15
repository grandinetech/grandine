// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
    ops::Rem,
};

use arithmetic::{NonZeroExt as _, U64Ext as _, UsizeExt as _};
use bit_field::BitField as _;
use derivative::Derivative;
use ethereum_types::H256;
use generic_array::ArrayLength;
use itertools::Itertools as _;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, SeqAccess, Visitor},
    ser::SerializeTuple as _,
};
use std_ext::ArcExt as _;
use triomphe::Arc;
use try_from_iterator::TryFromIterator;
use typenum::{NonZero, U1, Unsigned};

use crate::{
    bundle_size::BundleSize,
    contiguous_vector::ContiguousVector,
    error::{IndexError, ReadError, WriteError},
    hc::Hc,
    iter::{ExactSize, UpTo3},
    merkle_tree::MerkleTree,
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::{
        IncompletePersistentVectorElements, MerkleElements, MinimumBundleSize, TailElements,
    },
};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
pub struct IncompletePersistentVector<T, N, B: BundleSize<T> = MinimumBundleSize<T>>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    // Execution time is roughly the same without the `Arc` and even without the `Hc`,
    // but memory consumption is slightly lower when the `Arc` is present.
    root: Arc<Hc<Node<T, N, B>>>,
    phantom: PhantomData<N>,
}

#[expect(clippy::into_iter_without_iter)]
impl<'vector, T, N, B> IntoIterator for &'vector IncompletePersistentVector<T, N, B>
where
    N: Unsigned + NonZero + Rem<B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    type Item = &'vector T;
    type IntoIter = ExactSize<Flatten<Leaves<'vector, T, N, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack =
            Vec::with_capacity(IncompletePersistentVector::<T, N, B>::depth().max(1).into());
        stack.push(self.root.as_ref().as_ref());
        ExactSize::new(Leaves { stack }.flatten(), N::USIZE)
    }
}

impl<T, N, B> Default for IncompletePersistentVector<T, N, B>
where
    T: Clone + Default + PartialEq,
    N: IncompletePersistentVectorElements<T, B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn default() -> Self {
        Self::repeat_element(T::default())
    }
}

impl<T: Debug, N: IncompletePersistentVectorElements<T, B>, B: BundleSize<T>> Debug
    for IncompletePersistentVector<T, N, B>
where
    TailElements<N, B>: ArrayLength<T>,
{
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.debug_list().entries(self).finish()
    }
}

impl<T, B, N> TryFromIterator<T> for IncompletePersistentVector<T, N, B>
where
    T: PartialEq,
    N: IncompletePersistentVectorElements<T, B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let mut length = 0usize;
        let elements = elements
            .into_iter()
            .inspect(|_| length = length.saturating_add(1))
            .chunks(B::USIZE);
        let mut chunks = elements.into_iter();

        let mut full_chunks_len: usize = 0;
        // Deduplicating only consecutive nodes saves us from having to use a slower data structure
        // and seems to cover all access patterns used in `consensus-specs`.
        let run_length_encoded_result = itertools::process_results(
            chunks
                .by_ref()
                .take(N::USIZE / B::non_zero_usize())
                .inspect(|_| full_chunks_len = full_chunks_len.saturating_add(1))
                .map(ContiguousVector::try_from_iter),
            |packs| {
                packs
                    .dedup_with_count()
                    .map(|(count, bundle)| {
                        (Hc::arc(Node::Leaf(Box::new(Leaf::Full(bundle)))), count)
                    })
                    .collect_vec()
            },
        );

        let mut run_length_encoded_nodes = match run_length_encoded_result {
            Ok(nodes) if full_chunks_len == N::USIZE / B::non_zero_usize() => nodes,
            _ => {
                chunks.flatten().count();
                return Err(ReadError::VectorSizeMismatch {
                    expected: N::USIZE,
                    actual: length,
                });
            }
        };

        if N::USIZE % B::non_zero_usize() != 0 {
            let Some(last_chunk) = chunks
                .next()
                .map(ContiguousVector::try_from_iter)
                .and_then(Result::ok)
            else {
                chunks.flatten().count();
                return Err(ReadError::VectorSizeMismatch {
                    expected: N::USIZE,
                    actual: length,
                });
            };

            run_length_encoded_nodes
                .push((Hc::arc(Node::Leaf(Box::new(Leaf::Tail(last_chunk)))), 1));
        }

        if chunks.next().is_some() {
            chunks.flatten().count();
            return Err(ReadError::VectorSizeMismatch {
                expected: N::USIZE,
                actual: length,
            });
        }

        for _ in 0..Self::depth() {
            run_length_encoded_nodes = Self::build_parent_level(run_length_encoded_nodes);
        }

        let (root, _) = run_length_encoded_nodes
            .into_iter()
            .exactly_one()
            .ok()
            .expect("only the root should be left");

        Ok(Self {
            root,
            phantom: PhantomData,
        })
    }
}

impl<'de, T, N, B> Deserialize<'de> for IncompletePersistentVector<T, N, B>
where
    T: Deserialize<'de> + PartialEq,
    N: IncompletePersistentVectorElements<T, B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IncompletePersistentVectorVisitor<T, N, B>(PhantomData<(T, N, B)>);

        impl<'de, T, N, B> Visitor<'de> for IncompletePersistentVectorVisitor<T, N, B>
        where
            T: Deserialize<'de> + PartialEq,
            N: IncompletePersistentVectorElements<T, B>,
            B: BundleSize<T>,
            TailElements<N, B>: ArrayLength<T>,
        {
            type Value = IncompletePersistentVector<T, N, B>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "a vector of length {}", N::USIZE)
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                itertools::process_results(
                    core::iter::from_fn(|| seq.next_element().transpose()),
                    |elements| {
                        IncompletePersistentVector::try_from_iter(elements)
                            .map_err(S::Error::custom)
                    },
                )?
            }
        }

        deserializer.deserialize_tuple(N::USIZE, IncompletePersistentVectorVisitor(PhantomData))
    }
}

impl<T, N, B> Serialize for IncompletePersistentVector<T, N, B>
where
    T: Serialize,
    N: Unsigned + NonZero + Rem<B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N::USIZE)?;

        for element in self {
            tuple.serialize_element(element)?;
        }

        tuple.end()
    }
}

impl<T: SszSize, N: Unsigned + NonZero + Rem<B>, B: BundleSize<T>> SszSize
    for IncompletePersistentVector<T, N, B>
where
    TailElements<N, B>: ArrayLength<T>,
{
    const SIZE: Size = T::SIZE.mul(N::USIZE);
}

impl<C, T, N, B> SszRead<C> for IncompletePersistentVector<T, N, B>
where
    T: SszRead<C> + PartialEq,
    N: IncompletePersistentVectorElements<T, B> + Rem<B>,
    B: BundleSize<T> + MerkleElements<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let results = shared::read_vector::<_, _, N>(context, bytes)?;
        itertools::process_results(results, |elements| Self::try_from_iter(elements))?
    }
}

impl<T: SszWrite, N: Unsigned + NonZero + Rem<B>, B: BundleSize<T>> SszWrite
    for IncompletePersistentVector<T, N, B>
where
    TailElements<N, B>: ArrayLength<T>,
{
    fn write_fixed(&self, bytes: &mut [u8]) {
        shared::write_fixed_vector(bytes, self)
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_variable_vector::<N>(bytes, self)
    }
}

impl<T, N, B> SszHash for IncompletePersistentVector<T, N, B>
where
    T: SszHash + SszWrite,
    N: Unsigned + NonZero + Rem<B>,
    B: BundleSize<T> + MerkleElements<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.root.hash_tree_root()
    }
}

impl<T, N, B: BundleSize<T>> IncompletePersistentVector<T, N, B>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    /// Rearranges runs so nodes can be grouped into left/right pairs, then combines each pair
    /// into a parent node for the next tree level.
    #[inline]
    fn build_parent_level(
        run_length_encoded_nodes: RunLengthEncodedNodes<T, N, B>,
    ) -> RunLengthEncodedNodes<T, N, B> {
        let mut aligned = true;
        let mut left_over: Option<Arc<Hc<Node<T, N, B>>>> = None;

        let mut parent_level: RunLengthEncodedNodes<T, N, B> = run_length_encoded_nodes
            .into_iter()
            .flat_map(|(node, count)| {
                let pieces = match count {
                    0 => unreachable!("run-length encoding never produces runs of length 0"),
                    1 => UpTo3::from((node, 1)),
                    2 if aligned => UpTo3::from((node, 2)),
                    2 => UpTo3::from([(node.clone_arc(), 1), (node, 1)]),
                    _ if count.is_odd() => {
                        if aligned {
                            UpTo3::from([(node.clone_arc(), count.saturating_sub(1)), (node, 1)])
                        } else {
                            UpTo3::from([(node.clone_arc(), 1), (node, count.saturating_sub(1))])
                        }
                    }
                    _ => {
                        if aligned {
                            UpTo3::from((node, count))
                        } else {
                            UpTo3::from([
                                (node.clone_arc(), 1),
                                (node.clone_arc(), count.saturating_sub(2)),
                                (node, 1),
                            ])
                        }
                    }
                };

                if count.is_odd() {
                    aligned = !aligned;
                }

                pieces
            })
            .filter_map(|(current, count)| match (left_over.take(), count) {
                (_, 0) => unreachable!("run splitting never produces runs of length 0"),
                (Some(previous), 1) => {
                    let node = Node::Internal {
                        left_height: previous.height(),
                        right_height: current.height(),
                        left: previous,
                        right: current,
                    };
                    Some((Hc::arc(node), 1))
                }
                (Some(_), _) => unreachable!("runs of length 1 occur in pairs after splitting"),
                (None, 1) => {
                    left_over = Some(current);
                    None
                }
                (None, _) => {
                    let node = Node::Internal {
                        left_height: current.height(),
                        right_height: current.height(),
                        left: current.clone_arc(),
                        right: current,
                    };
                    Some((Hc::arc(node), count / 2))
                }
            })
            .collect();

        if let Some(left_over) = left_over {
            parent_level.push((left_over, 1));
        }

        parent_level
    }

    pub fn repeat_element(element: T) -> Self
    where
        T: Clone + PartialEq,
        N: IncompletePersistentVectorElements<T, B>,
    {
        Self::try_from_iter(core::iter::repeat_n(element, N::USIZE))
            .expect("the iterator length should match the type-level length")
    }

    #[must_use]
    pub fn mod_index(&self, index: u64) -> &T
    where
        N: Unsigned + NonZero,
    {
        self.get(index.mod_typenum::<N>())
            .expect("any number below N is a valid index because self contains exactly N elements")
    }

    #[must_use]
    pub fn mod_index_mut(&mut self, index: u64) -> &mut T
    where
        T: Clone,
        N: Unsigned + NonZero,
    {
        self.get_mut(index.mod_typenum::<N>())
            .expect("any number below N is a valid index because self contains exactly N elements")
    }

    pub fn get(&self, index: u64) -> Result<&T, IndexError>
    where
        N: Unsigned + NonZero,
    {
        let index = shared::validate_index(N::USIZE, index)?;
        let mut height = self.root.height();
        let mut node = self.root.as_ref().as_ref();

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
                        node = right;
                    } else {
                        height = *left_height;
                        node = left;
                    }
                }
                Node::Leaf(bundle) => break bundle.as_slice(),
            }
        };
        Ok(&bundle[B::index_in_bundle(index)])
    }

    fn get_mut(&mut self, index: u64) -> Result<&mut T, IndexError>
    where
        T: Clone,
        N: Unsigned + NonZero,
    {
        let index = shared::validate_index(N::USIZE, index)?;
        let mut height = self.root.height();
        let mut node = self.root.make_mut().as_mut();

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
                Node::Leaf(bundle) => {
                    break bundle.as_mut_slice();
                }
            }
        };

        Ok(&mut bundle[B::index_in_bundle(index)])
    }

    const fn actual_leaf_count() -> usize
    where
        N: Unsigned + NonZero,
    {
        N::USIZE.div_ceil(B::USIZE)
    }

    fn depth() -> u8
    where
        N: Unsigned + NonZero,
    {
        Self::actual_leaf_count().ilog2_ceil()
    }
}

type Height = u8;
type RunLengthEncodedNodes<T, N, B> = Vec<(Arc<Hc<Node<T, N, B>>>, usize)>;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
enum Node<T, N, B: BundleSize<T>>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    Internal {
        left: Arc<Hc<Self>>,
        right: Arc<Hc<Self>>,
        left_height: Height,
        right_height: Height,
    },
    // The leaves are big enough that boxing them lowers memory consumption by a small amount.
    // Execution time is roughly the same with or without the `Box`.
    Leaf(Box<Leaf<T, N, B>>),
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
enum Leaf<T, N, B: BundleSize<T>>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    Full(ContiguousVector<T, B>),
    Tail(ContiguousVector<T, TailElements<N, B>>),
}

impl<T, N, B> Leaf<T, N, B>
where
    N: Rem<B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn as_slice(&self) -> &[T] {
        match self {
            Self::Full(bundle) => bundle.as_slice(),
            Self::Tail(bundle) => bundle.as_slice(),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            Self::Full(bundle) => bundle.as_mut_slice(),
            Self::Tail(bundle) => bundle.as_mut_slice(),
        }
    }
}

impl<T, N, B> Node<T, N, B>
where
    N: Rem<B>,
    B: BundleSize<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    fn height(&self) -> Height {
        match self {
            Self::Internal {
                left_height,
                right_height,
                ..
            } => (*left_height).max(*right_height).saturating_add(1),
            Self::Leaf(_) => 0,
        }
    }
}

impl<T, N, B> SszHash for Leaf<T, N, B>
where
    T: SszHash + SszWrite,
    N: Rem<B>,
    B: BundleSize<T> + MerkleElements<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Full(bundle) => bundle.hash_tree_root(),
            Self::Tail(bundle) => {
                if T::PackingFactor::USIZE == 1 {
                    let chunks = bundle.iter().map(SszHash::hash_tree_root);
                    MerkleTree::<<B as MerkleElements<T>>::UnpackedMerkleTreeDepth>::merkleize_chunks(
                        chunks,
                    )
                } else {
                    MerkleTree::<<B as MerkleElements<T>>::PackedMerkleTreeDepth>::merkleize_packed(
                        bundle,
                    )
                }
            }
        }
    }
}

impl<T, N, B> SszHash for Node<T, N, B>
where
    T: SszHash + SszWrite,
    N: Rem<B>,
    B: BundleSize<T> + MerkleElements<T>,
    TailElements<N, B>: ArrayLength<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Internal {
                left_height,
                right_height,
                left,
                right,
            } => {
                // The two branches could be hashed in parallel, but doing it naively with
                // `rayon::join` has too much overhead.
                let right_root = (*right_height..*left_height)
                    .map(B::zero_hash)
                    .fold(right.hash_tree_root(), hashing::hash_256_256);

                hashing::hash_256_256(left.hash_tree_root(), right_root)
            }
            Self::Leaf(bundle) => bundle.hash_tree_root(),
        }
    }
}

pub struct Leaves<'vector, T, N, B: BundleSize<T>>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    // This cannot be an array because array sizes cannot depend on generic parameters. Making this
    // a `GenericArray` of size `PersistentVector::depth()` would require a huge number of trait
    // bounds which might not even be expressible because of the lifetime in the element type.
    stack: Vec<&'vector Node<T, N, B>>,
}

impl<'vector, T, N, B: BundleSize<T>> Iterator for Leaves<'vector, T, N, B>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
    type Item = &'vector [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| {
            loop {
                match node {
                    Node::Internal { left, right, .. } => {
                        self.stack.push(right);
                        node = left;
                    }
                    Node::Leaf(bundle) => break bundle.as_slice(),
                }
            }
        })
    }
}

impl<T, N, B: BundleSize<T>> FusedIterator for Leaves<'_, T, N, B>
where
    N: Rem<B>,
    TailElements<N, B>: ArrayLength<T>,
{
}
