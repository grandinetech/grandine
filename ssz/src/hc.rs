use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::DerefMut,
};

use derive_more::{AsRef, Deref};
use educe::Educe;
use ethereum_types::H256;
use once_cell::race::OnceBox;
use serde::{Deserialize, Serialize};
use static_assertions::assert_eq_size;
use triomphe::Arc;

use crate::{
    error::{ReadError, WriteError},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
};

/// A "Hash Cell". Or a "Hash Cache", if you prefer.
#[derive(Default, Deref, AsRef, Educe, Deserialize, Serialize)]
#[educe(PartialEq(bound), Eq(bound), Debug(bound))]
#[serde(transparent)]
pub struct Hc<T> {
    #[deref]
    #[as_ref]
    value: T,
    // `once_cell::sync::OnceCell` could be used instead of `once_cell::race::OnceBox`.
    // However, `OnceCell<Box<H256>>` needs two words of memory, whereas `OnceBox` fits in one.
    // The drawback is that `OnceBox` may cause multiple threads to redundantly compute the same
    // root, whereas `OnceCell` prevents that by locking.
    #[educe(PartialEq(ignore), Debug(method = "fmt_once_box_as_option"))]
    #[serde(skip)]
    cached_root: OnceBox<H256>,
}

assert_eq_size!(Hc<usize>, (usize, usize));
assert_eq_size!(Hc<H256>, (H256, usize));

// `OnceBox<T>` does not implement `Clone`.
impl<T: Clone> Clone for Hc<T> {
    fn clone(&self) -> Self {
        let Self { value, cached_root } = self;
        let value = value.clone();

        match cached_root.get().copied() {
            Some(root) => Self::with_root_internal(value, root),
            None => Self::from(value),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        let Self { value, cached_root } = source;

        self.value.clone_from(value);

        self.cached_root = cached_root
            .get()
            .copied()
            .map(initialized_once_box)
            .unwrap_or_default();
    }
}

impl<T> DerefMut for Hc<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> AsMut<T> for Hc<T> {
    fn as_mut(&mut self) -> &mut T {
        // Invalidate `cached_root` whenever `value` could potentially be modified.
        // This may be insufficient if `value` is internally mutable.
        self.cached_root = OnceBox::new();
        &mut self.value
    }
}

impl<T> From<T> for Hc<T> {
    fn from(value: T) -> Self {
        let cached_root = OnceBox::new();
        Self { value, cached_root }
    }
}

impl<T: SszSize> SszSize for Hc<T> {
    const SIZE: Size = T::SIZE;
}

impl<C, T: SszRead<C>> SszRead<C> for Hc<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        T::from_ssz_unchecked(context, bytes).map(Self::from)
    }
}

impl<T: SszWrite> SszWrite for Hc<T> {
    fn write_fixed(&self, bytes: &mut [u8]) {
        self.value.write_fixed(bytes);
    }

    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.value.write_variable(bytes)
    }
}

impl<T: SszHash> SszHash for Hc<T> {
    type PackingFactor = T::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        *self
            .cached_root
            .get_or_init(|| Box::new(self.value.hash_tree_root()))
    }
}

impl<T> Hc<T> {
    pub fn set_cached_root(&self, root: H256) {
        if let Err(old_root) = self.cached_root.set(Box::new(root)) {
            panic!("cached_root already set (old_root: {old_root:?}, root: {root:?})");
        }
    }

    // The bound on `T` could be made optional with `#[cfg(debug_assertions)]`,
    // but types that don't implement `SszHash` shouldn't be wrapped in `Hc` anyway.
    pub(crate) fn with_root(value: T, root: H256) -> Self
    where
        T: SszHash,
    {
        debug_assert_eq!(value.hash_tree_root(), root);
        Self::with_root_internal(value, root)
    }

    pub(crate) fn arc(value: T) -> Arc<Self> {
        Arc::new(Self::from(value))
    }

    fn with_root_internal(value: T, root: H256) -> Self {
        let cached_root = initialized_once_box(root);
        Self { value, cached_root }
    }
}

// `OnceBox<T>` does not implement `From<T>`.
fn initialized_once_box<T: Debug>(value: T) -> OnceBox<T> {
    let once_box = OnceBox::new();

    once_box
        .set(Box::new(value))
        .expect("once_box is empty because OnceBox::new returns an empty cell");

    once_box
}

// The `Debug` impl for `OnceBox` formats it as a raw pointer and even includes a `PhantomData` in
// older versions.
fn fmt_once_box_as_option(once_box: &OnceBox<impl Debug>, formatter: &mut Formatter) -> FmtResult {
    once_box.get().fmt(formatter)
}
