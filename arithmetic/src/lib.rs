// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// Having `#[expect(clippy::wrong_self_convention)]` declared directly on violating attributes
// results in `unfulfilled_lint_expectations` false positive warning.
// Declaring this for the whole module as a temporary workaround.
// TODO(Grandine Team): consider removing this workaround when upgrading from Rust 1.82.0.
#![expect(
    clippy::wrong_self_convention,
    reason = "This is needlessly strict. See <https://github.com/rust-lang/rust-clippy/issues/6727>."
)]
#![expect(
    clippy::return_self_not_must_use,
    reason = "Conflicts with `#[must_use]` has no effect when applied to a provided trait method."
)]

use core::num::NonZeroU64;

use easy_ext::ext;
use typenum::{NonZero, Unsigned};

#[ext(NonZeroExt)]
pub impl<N: Unsigned + NonZero> N {
    #[inline]
    fn non_zero() -> NonZeroU64 {
        Self::U64
            .try_into()
            .expect("the bound on N ensures that it is nonzero")
    }

    #[inline]
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
    fn is_odd(self) -> bool {
        self % 2 == 1
    }

    #[inline]
    fn div_typenum<N: Unsigned + NonZero>(self) -> Self {
        self / N::USIZE
    }

    #[inline]
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
    fn prev_multiple_of(self, factor: NonZeroU64) -> Self {
        self - self % factor
    }

    #[inline]
    fn div_typenum<N: Unsigned + NonZero>(self) -> Self {
        self / N::U64
    }

    #[inline]
    fn mod_typenum<N: Unsigned + NonZero>(self) -> Self {
        self % N::U64
    }

    #[inline]
    fn prev_power_of_two(self) -> Self {
        1 << self.ilog2()
    }

    #[inline]
    fn ilog2_ceil(self) -> u8 {
        self.checked_next_power_of_two()
            .map_or(Self::BITS, Self::trailing_zeros)
            .try_into()
            .expect("number of bits in u64 should fit in u8")
    }
}
