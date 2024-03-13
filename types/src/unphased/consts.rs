use typenum::{Diff, Length, Log2, Prod, Shleft, Sub1, Sum, U1};

/// [`concat_generalized_indices`](https://github.com/ethereum/consensus-specs/blob/0f2d25d919bf19d3421df791533d553af679a54f/ssz/merkle-proofs.md#concat_generalized_indices)
pub type ConcatGeneralizedIndices<A, B> =
    Sum<Prod<A, PrevPowerOfTwo<B>>, Diff<B, PrevPowerOfTwo<B>>>;

/// [`get_generalized_index` specialized for containers](https://github.com/ethereum/consensus-specs/blob/0f2d25d919bf19d3421df791533d553af679a54f/ssz/merkle-proofs.md#ssz-object-to-index)
pub type GeneralizedIndexInContainer<I, N> = Sum<I, NextPowerOfTwo<N>>;

type NextPowerOfTwo<N> = Shleft<U1, Length<Sub1<N>>>;
type PrevPowerOfTwo<N> = Shleft<U1, Log2<N>>;
