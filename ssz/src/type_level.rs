// This is the best we can do until feature `generic_const_exprs` is stabilized.

use core::ops::{Add, Shr, Sub};

use ethereum_types::H256;
use generic_array::ArrayLength;
use typenum::{
    op, Diff, IsGreaterOrEqual, IsLess, Len, Length, Log2, Min, Minimum, NonZero, PowerOfTwo,
    Shleft, Sub1, Sum, True, Unsigned, B1, U1, U3, U31, U5, U64, U7,
};

use crate::porcelain::SszHash;

pub trait FitsInU64: Unsigned {}

impl<N: Unsigned + IsLess<Shleft<U1, U64>, Output = True>> FitsInU64 for N {}

pub trait ContiguousVectorElements<T>: ArrayLength<T> + NonZero {}

impl<T, N: ArrayLength<T> + NonZero> ContiguousVectorElements<T> for N {}

pub trait PersistentVectorElements<T, B>: Unsigned + NonZero {}

impl<T, N, B> PersistentVectorElements<T, B> for N where
    N: Unsigned + NonZero + PowerOfTwo + IsGreaterOrEqual<B, Output = True>
{
}

pub trait MerkleElements<T>: Unsigned {
    // TODO(feature/deneb): The `ArrayLength<H256>` are redundant.
    //                      Consider removing from the bounds and the impl.
    type UnpackedMerkleTreeDepth: ArrayLength<H256> + ProofSize;
    type PackedMerkleTreeDepth: ArrayLength<H256> + ProofSize;
}

impl<T, N> MerkleElements<T> for N
where
    T: SszHash,
    N: Sub<B1> + Unsigned,
    Sub1<Self>: Len,
    ChunksToDepth<Self>: ArrayLength<H256>
        + ProofSize
        + Min<Log2<T::PackingFactor>>
        + Sub<Minimum<ChunksToDepth<Self>, Log2<T::PackingFactor>>>,
    Diff<ChunksToDepth<Self>, Minimum<ChunksToDepth<Self>, Log2<T::PackingFactor>>>:
        ArrayLength<H256> + ProofSize,
{
    type UnpackedMerkleTreeDepth = ChunksToDepth<Self>;
    type PackedMerkleTreeDepth =
        Diff<ChunksToDepth<Self>, Minimum<ChunksToDepth<Self>, Log2<T::PackingFactor>>>;
}

pub trait ByteVectorBytes: ContiguousVectorElements<u8> + ArrayLength<u8, ArrayType: Copy> {}

impl<N: ContiguousVectorElements<u8> + ArrayLength<u8, ArrayType: Copy>> ByteVectorBytes for N {}

pub trait BitVectorBits: Unsigned {
    type Bytes: ArrayLength<u8, ArrayType: Copy>;
}

impl<N> BitVectorBits for N
where
    Self: Add<U7> + Unsigned,
    Sum<Self, U7>: Shr<U3>,
    BitsToBytes<Self>: ArrayLength<u8, ArrayType: Copy>,
{
    type Bytes = BitsToBytes<Self>;
}

pub trait MerkleBits {
    type MerkleTreeDepth: ArrayLength<H256>;
}

impl<N> MerkleBits for N
where
    Self: Add<U7>,
    Sum<Self, U7>: Shr<U3>,
    BitsToBytes<Self>: Add<U31>,
    Sum<BitsToBytes<Self>, U31>: Shr<U5>,
    BitsToChunks<Self>: Sub<B1>,
    Sub1<BitsToChunks<Self>>: Len,
    BitsToDepth<Self>: ArrayLength<H256>,
{
    type MerkleTreeDepth = BitsToDepth<Self>;
}

pub trait ProofSize:
    ArrayLength<H256> + ArrayLength<Box<[H256]>> + Add<B1, Output: ArrayLength<H256>>
{
}

impl<N> ProofSize for N where
    Self: ArrayLength<H256> + ArrayLength<Box<[H256]>> + Add<B1, Output: ArrayLength<H256>>
{
}

type BitsToBytes<N> = op!((N + U7) >> U3);

type BytesToChunks<N> = op!((N + U31) >> U5);

type ChunksToDepth<N> = Length<Sub1<N>>;

type BitsToChunks<N> = BytesToChunks<BitsToBytes<N>>;

type BitsToDepth<N> = ChunksToDepth<BitsToChunks<N>>;

pub type BytesToDepth<N> = ChunksToDepth<BytesToChunks<N>>;

/// Number of elements needed to fill a single chunk without padding.
pub type MinimumBundleSize<T> = <T as SszHash>::PackingFactor;

/// Number of elements needed to fill 2 chunks without padding.
///
/// Types whose chunks are not produced by hashing should be stored in bundles at least this big.
/// Using smaller bundles will waste memory by storing redundant hashes.
///
/// [`MinimumBundleSize`] could be made to handle both cases using another associated type in
/// [`SszHash`] and some more type-level logic, but it's tricky to do in a completely general way
/// and may be needlessly restrictive. See the following for explanations of the technique:
/// - <https://stackoverflow.com/questions/40392524/conflicting-trait-implementations-even-though-associated-types-differ/40408431#40408431>
/// - <https://github.com/rust-lang/rfcs/pull/1672#issuecomment-1405377983>
pub type UnhashedBundleSize<T> = Shleft<<T as SszHash>::PackingFactor, U1>;
