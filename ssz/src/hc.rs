use core::{
    fmt::{Debug, Formatter, Result as FmtResult},
    ops::DerefMut,
};

use derivative::Derivative;
use derive_more::{AsRef, Deref};
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
#[derive(Default, Deref, AsRef, Derivative, Deserialize, Serialize)]
#[derivative(PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct Hc<T> {
    #[deref]
    #[as_ref]
    value: T,
    // `once_cell::sync::OnceCell` could be used instead of `once_cell::race::OnceBox`.
    // However, `OnceCell<Box<H256>>` needs two words of memory, whereas `OnceBox` fits in one.
    // The drawback is that `OnceBox` may cause multiple threads to redundantly compute the same
    // root, whereas `OnceCell` prevents that by locking.
    #[derivative(PartialEq = "ignore", Debug(format_with = "fmt_once_box_as_option"))]
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
    pub fn new(value: T) -> Self {
        value.into()
    }

    pub fn into_inner(self) -> T {
        self.value
    }

    /// Caches `root` as the hash tree root of this value.
    ///
    /// Setting the same root twice is allowed: a state read back from the delta store may already
    /// carry the root cached by whoever wrote it. A *conflicting* root means the value and the
    /// root disagree, so it is rejected rather than silently ignored.
    pub fn set_cached_root(&self, root: H256) {
        if let Err(new_root) = self.cached_root.set(Box::new(root)) {
            assert_eq!(
                self.cached_root.get(),
                Some(&*new_root),
                "cached_root was already set to a different root",
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cached_root_serves_the_root_without_hashing_the_value() {
        let hc = Hc::new(1_u64);
        let root = H256::repeat_byte(1);

        hc.set_cached_root(root);

        assert_eq!(hc.hash_tree_root(), root);
    }

    #[test]
    fn set_cached_root_is_idempotent() {
        // A state read back from the delta store may already carry the root cached by whoever
        // wrote it, so setting the same root again has to be allowed.
        let hc = Hc::new(1_u64);
        let root = H256::repeat_byte(1);

        hc.set_cached_root(root);
        hc.set_cached_root(root);

        assert_eq!(hc.hash_tree_root(), root);
    }

    #[test]
    #[should_panic(expected = "cached_root was already set to a different root")]
    fn set_cached_root_rejects_a_conflicting_root() {
        let hc = Hc::new(1_u64);

        hc.set_cached_root(H256::repeat_byte(1));
        hc.set_cached_root(H256::repeat_byte(2));
    }
}
