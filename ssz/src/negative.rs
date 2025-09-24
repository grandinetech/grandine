use core::{
    cell::{Cell, RefCell, UnsafeCell},
    num::{NonZeroIsize, NonZeroUsize},
    sync::atomic::{
        AtomicBool, AtomicI16, AtomicI32, AtomicI8, AtomicIsize, AtomicPtr, AtomicU16,
        AtomicU32, AtomicU8, AtomicUsize,
    },
};

#[cfg(not(target_arch = "mips"))]
use core::sync::atomic::{AtomicI64, AtomicU64};

use std::sync::{Mutex, RwLock};

use ethereum_types::H256;
use static_assertions::assert_not_impl_any;
use typenum::U0;

use crate::{
    bit_vector::BitVector,
    byte_vector::ByteVector,
    contiguous_vector::ContiguousVector,
    persistent_vector::PersistentVector,
    porcelain::{SszHash, SszReadDefault, SszSize, SszWrite},
};

// > - Empty vector types (`Vector[type, 0]`, `Bitvector[0]`) are illegal.
assert_not_impl_any!(BitVector<U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ByteVector<U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(ContiguousVector<H256, U0>: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(PersistentVector<H256, U0>: SszSize, SszReadDefault, SszWrite, SszHash);

// > - Containers with no fields are illegal.
// > - The `null` type is only legal as the first type in a union subtype
// >   (i.e. with type index zero).
assert_not_impl_any!((): SszHash, SszReadDefault, SszSize, SszWrite);

// There are some problems with implementing SSZ traits for `usize`, not all of them obvious.
// The obvious one is that it does not have a fixed size. This could be solved by serializing
// `usize` as `u64`, which is the "native" type of Ethereum 2.0. Doing so would make it possible to
// represent validator indices and deposit indices with `usize`, which would simplify indexing.
// The less obvious problem is that doing so would force us to either make `SszHash::hash_tree_root`
// fallible or rely on values in `usize` fields never exceeding `u64::MAX`.
assert_not_impl_any!(usize: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(isize: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(NonZeroUsize: SszSize, SszReadDefault, SszWrite, SszHash);
assert_not_impl_any!(NonZeroIsize: SszSize, SszReadDefault, SszWrite, SszHash);

// Internal mutability can be used to bypass automatic cache invalidation in `Hc`.
assert_not_impl_any!(UnsafeCell<H256>: SszHash);
assert_not_impl_any!(Cell<H256>: SszHash);
assert_not_impl_any!(RefCell<H256>: SszHash);
assert_not_impl_any!(AtomicBool: SszHash);
assert_not_impl_any!(AtomicU8: SszHash);
assert_not_impl_any!(AtomicU16: SszHash);
assert_not_impl_any!(AtomicU32: SszHash);
assert_not_impl_any!(AtomicUsize: SszHash);
assert_not_impl_any!(AtomicI8: SszHash);
assert_not_impl_any!(AtomicI16: SszHash);
assert_not_impl_any!(AtomicI32: SszHash);
assert_not_impl_any!(AtomicIsize: SszHash);
assert_not_impl_any!(AtomicPtr<H256>: SszHash);
assert_not_impl_any!(Mutex<H256>: SszHash);
assert_not_impl_any!(RwLock<H256>: SszHash);

#[cfg(not(target_arch = "mips"))]
assert_not_impl_any!(AtomicU64: SszHash);
#[cfg(not(target_arch = "mips"))]
assert_not_impl_any!(AtomicI64: SszHash);