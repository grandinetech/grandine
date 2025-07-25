#![expect(
    clippy::return_self_not_must_use,
    reason = "Conflicts with `#[must_use]` has no effect when applied to a provided trait method."
)]
use std::sync::Arc as StdArc;

use easy_ext::ext;
use triomphe::Arc as TriompheArc;

// TODO(Grandine Team): Remove the impl for `StdArc` and revert to `#[ext(ArcExt)]` when the switch to
//                      `triomphe` is complete.
pub trait ArcExt<T: ?Sized> {
    #[must_use]
    fn clone_arc(&self) -> Self
    where
        Self: Clone,
    {
        Self::clone(self)
    }

    #[must_use]
    fn make_mut(&mut self) -> &mut T
    where
        T: Clone;
}

impl<T: ?Sized> ArcExt<T> for StdArc<T> {
    fn make_mut(&mut self) -> &mut T
    where
        T: Clone,
    {
        Self::make_mut(self)
    }
}

impl<T: ?Sized> ArcExt<T> for TriompheArc<T> {
    fn make_mut(&mut self) -> &mut T
    where
        T: Clone,
    {
        Self::make_mut(self)
    }
}

#[ext(CopyExt)]
pub impl<T: Copy> T {
    fn copy(&self) -> Self {
        *self
    }
}

#[ext(DefaultExt)]
pub impl<T: PartialEq + Default> T {
    fn is_default(&self) -> bool {
        *self == T::default()
    }
}
