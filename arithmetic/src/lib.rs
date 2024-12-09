// Having `#[expect(clippy::wrong_self_convention)]` declared directly on violating attributes
// results in `unfulfilled_lint_expectations` false positive warning.
// Declaring this for the whole module as a temporary workaround.
// TODO(Grandine Team): consider removing this workaround when upgrading from Rust 1.82.0.
#![expect(
    clippy::wrong_self_convention,
    reason = "This is needlessly strict. See <https://github.com/rust-lang/rust-clippy/issues/6727>."
)]

use core::num::{NonZeroU128, NonZeroU64, NonZeroUsize};

use easy_ext::ext;
use typenum::{NonZero, Unsigned};

#[ext(NonZeroExt)]
pub impl<N: Unsigned + NonZero> N {
    #[inline]
    #[must_use]
    fn non_zero() -> NonZeroU64 {
        Self::U64
            .try_into()
            .expect("the bound on N ensures that it is nonzero")
    }

    #[inline]
    #[must_use]
    fn ilog2() -> u8 {
        Self::non_zero()
            .ilog2()
            .try_into()
            .expect("binary logarithm of u64 should fit in u8")
    }
}

#[ext(UsizeExt)]
pub impl usize {
    #[inline]
    #[must_use]
    fn is_odd(self) -> bool {
        self % 2 == 1
    }

    #[inline]
    #[must_use]
    fn is_multiple_of(self, factor: NonZeroUsize) -> bool {
        self % factor == 0
    }

    #[inline]
    #[must_use]
    fn div_typenum<N: Unsigned + NonZero>(self) -> Self {
        self / N::USIZE
    }

    #[inline]
    #[must_use]
    fn ilog2_ceil(self) -> u8 {
        self.checked_next_power_of_two()
            .map_or(Self::BITS, Self::trailing_zeros)
            .try_into()
            .expect("number of bits in usize should fit in u8")
    }
}

#[ext(U64Ext)]
pub impl u64 {
    #[inline]
    #[must_use]
    fn is_multiple_of(self, factor: NonZeroU64) -> bool {
        self % factor == 0
    }

    #[inline]
    #[must_use]
    fn prev_multiple_of(self, factor: NonZeroU64) -> Self {
        self - self % factor
    }

    #[inline]
    #[must_use]
    fn div_typenum<N: Unsigned + NonZero>(self) -> Self {
        self / N::U64
    }

    #[inline]
    #[must_use]
    fn mod_typenum<N: Unsigned + NonZero>(self) -> Self {
        self % N::U64
    }

    #[inline]
    #[must_use]
    fn prev_power_of_two(self) -> Self {
        1 << self.ilog2()
    }
}

#[ext(U128Ext)]
pub impl u128 {
    #[inline]
    #[must_use]
    fn is_multiple_of(self, factor: NonZeroU128) -> bool {
        self % factor == 0
    }
}
