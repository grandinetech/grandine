// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// Having `#[expect(clippy::wrong_self_convention)]` declared directly on violating attributes
// results in `unfulfilled_lint_expectations` false positive warning.
// Declaring this for the whole module as a temporary workaround.
// TODO(Grandine Team): consider removing this workaround when upgrading from Rust 1.95.0.
#![expect(
    clippy::wrong_self_convention,
    reason = "This is needlessly strict. See <https://github.com/rust-lang/rust-clippy/issues/6727>."
)]
#![expect(
    clippy::return_self_not_must_use,
    reason = "Conflicts with `#[must_use]` has no effect when applied to a provided trait method."
)]

use core::num::{NonZeroU64, NonZeroUsize};

use easy_ext::ext;
use primitive_types::U256;
use thiserror::Error;
use typenum::{NonZero, Unsigned};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum ArithmeticError {
    #[error("{lhs} + {rhs} overflows")]
    AdditionOverflow { lhs: u64, rhs: u64 },
    #[error("{lhs} + {rhs} overflows")]
    AdditionOverflowU256 { lhs: U256, rhs: U256 },
    #[error("{lhs} - {rhs} underflows")]
    SubtractionOverflow { lhs: u64, rhs: u64 },
    #[error("{lhs} * {rhs} overflows")]
    MultiplicationOverflow { lhs: u64, rhs: u64 },
    #[error("{lhs} / {rhs} is undefined")]
    DivisionByZero { lhs: u64, rhs: u64 },
}

#[ext(NonZeroExt)]
pub impl<N: Unsigned + NonZero> N {
    #[inline]
    fn non_zero() -> NonZeroU64 {
        Self::U64
            .try_into()
            .expect("the bound on N ensures that it is nonzero")
    }

    #[inline]
    fn non_zero_usize() -> NonZeroUsize {
        Self::USIZE
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
        self / N::non_zero_usize()
    }

    #[inline]
    fn ilog2_ceil(self) -> u8 {
        self.checked_next_power_of_two()
            .map_or(Self::BITS, Self::trailing_zeros)
            .try_into()
            .expect("number of bits in usize should fit in u8")
    }

    #[inline]
    fn try_add(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_add(rhs)
            .ok_or(ArithmeticError::AdditionOverflow {
                lhs: self as u64,
                rhs: rhs as u64,
            })
    }

    #[inline]
    fn try_sub(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_sub(rhs)
            .ok_or(ArithmeticError::SubtractionOverflow {
                lhs: self as u64,
                rhs: rhs as u64,
            })
    }

    #[inline]
    fn try_mul(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_mul(rhs)
            .ok_or(ArithmeticError::MultiplicationOverflow {
                lhs: self as u64,
                rhs: rhs as u64,
            })
    }

    #[inline]
    fn try_div(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_div(rhs)
            .ok_or(ArithmeticError::DivisionByZero {
                lhs: self as u64,
                rhs: rhs as u64,
            })
    }
}

#[ext(NonZeroU64Ext)]
pub impl NonZeroU64 {
    #[inline]
    fn try_mul(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_mul(rhs)
            .ok_or_else(|| ArithmeticError::MultiplicationOverflow {
                lhs: self.get(),
                rhs: rhs.get(),
            })
    }
}

#[ext(U16Ext)]
pub impl u16 {
    #[inline]
    fn try_add(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_add(rhs)
            .ok_or_else(|| ArithmeticError::AdditionOverflow {
                lhs: u64::from(self),
                rhs: u64::from(rhs),
            })
    }

    #[inline]
    fn try_sub(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_sub(rhs)
            .ok_or_else(|| ArithmeticError::SubtractionOverflow {
                lhs: u64::from(self),
                rhs: u64::from(rhs),
            })
    }
}

#[ext(U256Ext)]
pub impl U256 {
    #[inline]
    fn try_add(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_add(rhs)
            .ok_or(ArithmeticError::AdditionOverflowU256 { lhs: self, rhs })
    }
}

#[ext(U64Ext)]
pub impl u64 {
    #[inline]
    fn prev_multiple_of(self, factor: NonZeroU64) -> Self {
        self.saturating_sub(self % factor)
    }

    #[inline]
    fn div_typenum<N: Unsigned + NonZero>(self) -> Self {
        self / N::non_zero()
    }

    #[inline]
    fn mod_typenum<N: Unsigned + NonZero>(self) -> Self {
        self % N::non_zero()
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

    #[inline]
    fn try_add(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_add(rhs)
            .ok_or(ArithmeticError::AdditionOverflow { lhs: self, rhs })
    }

    #[inline]
    fn try_rem(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_rem(rhs)
            .ok_or(ArithmeticError::DivisionByZero { lhs: self, rhs })
    }

    #[inline]
    fn try_sub(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_sub(rhs)
            .ok_or(ArithmeticError::SubtractionOverflow { lhs: self, rhs })
    }

    #[inline]
    fn try_mul(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_mul(rhs)
            .ok_or(ArithmeticError::MultiplicationOverflow { lhs: self, rhs })
    }

    #[inline]
    fn try_div(self, rhs: Self) -> Result<Self, ArithmeticError>
    where
        Self: Sized,
    {
        self.checked_div(rhs)
            .ok_or(ArithmeticError::DivisionByZero { lhs: self, rhs })
    }
}
