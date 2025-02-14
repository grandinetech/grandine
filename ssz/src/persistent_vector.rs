// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    iter::{Flatten, FusedIterator},
    marker::PhantomData,
};

use arithmetic::{NonZeroExt as _, U64Ext as _, UsizeExt as _};
use bit_field::BitField as _;
use derivative::Derivative;
use ethereum_types::H256;
use itertools::Itertools as _;
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    ser::SerializeTuple as _,
    Deserialize, Deserializer, Serialize, Serializer,
};
use static_assertions::assert_eq_size;
use std_ext::ArcExt as _;
use triomphe::Arc;
use try_from_iterator::TryFromIterator;
use typenum::{NonZero, Unsigned, U1, U2, U4};

use crate::{
    bundle_size::BundleSize,
    contiguous_vector::ContiguousVector,
    error::{IndexError, ReadError, WriteError},
    hc::Hc,
    iter::{ExactSize, UpTo3},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    shared,
    size::Size,
    type_level::{MerkleElements, MinimumBundleSize, PersistentVectorElements},
};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
pub struct PersistentVector<T, N, B: BundleSize<T> = MinimumBundleSize<T>> {
    // Execution time is roughly the same without the `Arc` and even without the `Hc`,
    // but memory consumption is slightly lower when the `Arc` is present.
    root: Arc<Hc<Node<T, B>>>,
    phantom: PhantomData<N>,
}

#[expect(clippy::into_iter_without_iter)]
impl<'vector, T, N, B> IntoIterator for &'vector PersistentVector<T, N, B>
where
    N: Unsigned + NonZero,
    B: BundleSize<T>,
{
    type Item = &'vector T;
    type IntoIter = ExactSize<Flatten<Leaves<'vector, T, B>>>;

    fn into_iter(self) -> Self::IntoIter {
        let mut stack = Vec::with_capacity(PersistentVector::<T, N, B>::depth().max(1).into());
        stack.push(self.root.as_ref().as_ref());
        ExactSize::new(Leaves { stack }.flatten(), N::USIZE)
    }
}

impl<T, N, B> Default for PersistentVector<T, N, B>
where
    T: Clone + Default,
    N: PersistentVectorElements<T, B>,
    B: BundleSize<T>,
{
    fn default() -> Self {
        Self::repeat_element(T::default())
    }
}

impl<T: Debug, N: Unsigned + NonZero, B: BundleSize<T>> Debug for PersistentVector<T, N, B> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.debug_list().entries(self).finish()
    }
}

impl<T, B, N> TryFromIterator<T> for PersistentVector<T, N, B>
where
    T: PartialEq,
    N: PersistentVectorElements<T, B>,
    B: BundleSize<T>,
{
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        let mut length = 0;

        // Deduplicating only consecutive nodes saves us from having to use a slower data structure
        // and seems to cover all access patterns used in `consensus-specs`.
        let run_length_encoded_result = itertools::process_results(
            elements
                .into_iter()
                .inspect(|_| length += 1)
                .chunks(B::USIZE)
                .into_iter()
                .map(ContiguousVector::try_from_iter),
            |packs| {
                packs
                    .dedup_with_count()
                    .map(|(count, bundle)| (Hc::arc(Node::Leaf(Box::new(bundle))), count))
                    .collect_vec()
            },
        );

        let mut run_length_encoded_nodes = match run_length_encoded_result {
            Ok(nodes) if length == N::USIZE => nodes,
            _ => {
                return Err(ReadError::VectorSizeMismatch {
                    expected: N::USIZE,
                    actual: length,
                });
            }
        };

        for _ in 0..Self::depth() {
            let mut aligned = true;
            let mut left_over = None;

            run_length_encoded_nodes = run_length_encoded_nodes
                .into_iter()
                .flat_map(|(node, count)| {
                    let pieces = match count {
                        0 => unreachable!("run-length encoding never produces runs of length 0"),
                        1 => UpTo3::from((node, 1)),
                        2 if aligned => UpTo3::from((node, 2)),
                        2 => UpTo3::from([(node.clone_arc(), 1), (node, 1)]),
                        other if other.is_odd() => {
                            if aligned {
                                UpTo3::from([(node.clone_arc(), count - 1), (node, 1)])
                            } else {
                                UpTo3::from([(node.clone_arc(), 1), (node, count - 1)])
                            }
                        }
                        _ => {
                            if aligned {
                                UpTo3::from((node, count))
                            } else {
                                UpTo3::from([
                                    (node.clone_arc(), 1),
                                    (node.clone_arc(), count - 2),
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
                        let node = Node::Internal(previous, current);
                        Some((Hc::arc(node), 1))
                    }
                    (Some(_), _) => unreachable!("runs of length 1 occur in pairs after splitting"),
                    (None, 1) => {
                        left_over = Some(current);
                        None
                    }
                    (None, _) => {
                        let node = Node::Internal(current.clone_arc(), current);
                        Some((Hc::arc(node), count / 2))
                    }
                })
                .collect();

            assert!(left_over.is_none());
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

impl<'de, T, N, B> Deserialize<'de> for PersistentVector<T, N, B>
where
    T: Deserialize<'de> + PartialEq,
    N: PersistentVectorElements<T, B>,
    B: BundleSize<T>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PersistentVectorVisitor<T, N, B>(PhantomData<(T, N, B)>);

        impl<'de, T, N, B> Visitor<'de> for PersistentVectorVisitor<T, N, B>
        where
            T: Deserialize<'de> + PartialEq,
            N: PersistentVectorElements<T, B>,
            B: BundleSize<T>,
        {
            type Value = PersistentVector<T, N, B>;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "a vector of length {}", N::USIZE)
            }

            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                itertools::process_results(
                    core::iter::from_fn(|| seq.next_element().transpose()),
                    |elements| PersistentVector::try_from_iter(elements).map_err(S::Error::custom),
                )?
            }
        }

        deserializer.deserialize_tuple(N::USIZE, PersistentVectorVisitor(PhantomData))
    }
}

impl<T, N, B> Serialize for PersistentVector<T, N, B>
where
    T: Serialize,
    N: Unsigned + NonZero,
    B: BundleSize<T>,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N::USIZE)?;

        for element in self {
            tuple.serialize_element(element)?;
        }

        tuple.end()
    }
}

impl<T: SszSize, N: Unsigned + NonZero, B: BundleSize<T>> SszSize for PersistentVector<T, N, B> {
    const SIZE: Size = Size::for_vector(T::SIZE, N::USIZE);
}

impl<C, T, N, B> SszRead<C> for PersistentVector<T, N, B>
where
    T: SszRead<C> + PartialEq,
    N: PersistentVectorElements<T, B>,
    B: BundleSize<T> + MerkleElements<T>,
{
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let results = shared::read_vector::<_, _, N>(context, bytes)?;
        itertools::process_results(results, |elements| Self::try_from_iter(elements))?
    }
}

impl<T: SszWrite, N: Unsigned + NonZero, B: BundleSize<T>> SszWrite for PersistentVector<T, N, B> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        shared::write_fixed_vector(bytes, self)
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_variable_vector::<N>(bytes, self)
    }
}

impl<T, N, B> SszHash for PersistentVector<T, N, B>
where
    T: SszHash + SszWrite,
    N: NonZero,
    B: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.root.hash_tree_root()
    }
}

impl<T, N, B: BundleSize<T>> PersistentVector<T, N, B> {
    pub fn repeat_element(element: T) -> Self
    where
        T: Clone,
        N: PersistentVectorElements<T, B>,
    {
        let bundle = ContiguousVector::repeat_element(element);

        let mut node = Node::Leaf(Box::new(bundle));

        for _ in 0..Self::depth() {
            let arc = Hc::arc(node);
            node = Node::Internal(arc.clone_arc(), arc);
        }

        Self {
            root: Hc::arc(node),
            phantom: PhantomData,
        }
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

    fn get(&self, index: u64) -> Result<&T, IndexError>
    where
        N: Unsigned + NonZero,
    {
        let index = shared::validate_index(N::USIZE, index)?;

        let mut bit_index = N::ilog2();
        let mut node = self.root.as_ref().as_ref();

        let bundle = loop {
            match node {
                Node::Internal(left, right) => {
                    bit_index -= 1;
                    let bit = index.get_bit(bit_index.into());
                    node = if bit { right } else { left }
                }
                Node::Leaf(bundle) => {
                    assert_eq!(bit_index, B::ilog2());
                    break bundle;
                }
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

        let mut bit_index = N::ilog2();
        let mut node = self.root.make_mut().as_mut();

        let bundle = loop {
            match node {
                Node::Internal(left, right) => {
                    bit_index -= 1;
                    let bit = index.get_bit(bit_index.into());
                    node = if bit { right } else { left }.make_mut()
                }
                Node::Leaf(bundle) => {
                    assert_eq!(bit_index, B::ilog2());
                    break bundle;
                }
            }
        };

        Ok(&mut bundle[B::index_in_bundle(index)])
    }

    fn depth() -> u8
    where
        N: Unsigned + NonZero,
    {
        N::ilog2() - B::ilog2()
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq")
)]
enum Node<T, B: BundleSize<T>> {
    Internal(Arc<Hc<Self>>, Arc<Hc<Self>>),
    // The leaves are big enough that boxing them lowers memory consumption by a small amount.
    // Execution time is roughly the same with or without the `Box`.
    Leaf(Box<ContiguousVector<T, B>>),
}

// Before Rust 1.65.0 the compiler was not smart enough to fit `Node` in 2 words.
// See <https://github.com/rust-lang/rust/pull/94075/>.
assert_eq_size!(Node<H256, U1>, Node<H256, U2>, Node<H256, U4>, [usize; 2]);

impl<T, B> SszHash for Node<T, B>
where
    T: SszHash + SszWrite,
    B: BundleSize<T> + MerkleElements<T>,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Internal(left, right) => {
                // The two branches could be hashed in parallel, but doing it naively with
                // `rayon::join` has too much overhead.
                hashing::hash_256_256(left.hash_tree_root(), right.hash_tree_root())
            }
            Self::Leaf(bundle) => bundle.hash_tree_root(),
        }
    }
}

pub struct Leaves<'vector, T, B: BundleSize<T>> {
    // This cannot be an array because array sizes cannot depend on generic parameters. Making this
    // a `GenericArray` of size `PersistentVector::depth()` would require a huge number of trait
    // bounds which might not even be expressible because of the lifetime in the element type.
    stack: Vec<&'vector Node<T, B>>,
}

impl<'vector, T, B: BundleSize<T>> Iterator for Leaves<'vector, T, B> {
    type Item = &'vector [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop().map(|mut node| loop {
            match node {
                Node::Internal(left, right) => {
                    self.stack.push(right);
                    node = left;
                }
                Node::Leaf(bundle) => break bundle.as_slice(),
            }
        })
    }
}

impl<T, B: BundleSize<T>> FusedIterator for Leaves<'_, T, B> {}
