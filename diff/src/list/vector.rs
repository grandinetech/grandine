use ssz::{
    BundleSize, ContiguousList, IncompletePersistentVector, IncompletePersistentVectorElements,
    PersistentVector, PersistentVectorElements, Ssz, SszRead, SszSize, SszWrite,
};

use crate::{
    error::Error,
    list::{PositionalPatch, Unlimited, positional::PositionalEdit},
    patch::{Patch, PatchConfig},
};

#[derive(Ssz, Debug, Clone)]
#[ssz(
    derive_hash = false,
    bound = "T: SszWrite",
    bound_for_read = "T: SszRead<C> + SszWrite"
)]
pub struct VectorPatch<T> {
    edits: ContiguousList<PositionalEdit<T>, Unlimited>,
}

impl<T, N, B> Patch<PersistentVector<T, N, B>> for VectorPatch<T>
where
    T: Clone + Eq + SszSize,
    N: PersistentVectorElements<T, B>,
    B: BundleSize<T>,
{
    fn diff(
        _config: PatchConfig,
        base: &PersistentVector<T, N, B>,
        changed: &PersistentVector<T, N, B>,
    ) -> Result<Self, Error> {
        Ok(Self {
            edits: PositionalPatch::diff_edits(base, changed),
        })
    }

    fn apply(self, base: &mut PersistentVector<T, N, B>) -> Result<(), Error> {
        PositionalPatch::apply_edits(self.edits, |i, value| {
            base.get_mut(i)
                .map(|item| *item = value)
                .map_err(|_| Error::PatchIndexOutOfBounds)
        })
    }
}

impl<T, N, B> Patch<IncompletePersistentVector<T, N, B>> for VectorPatch<T>
where
    T: Clone + Eq + SszSize,
    N: IncompletePersistentVectorElements<T, B>,
    B: BundleSize<T>,
{
    fn diff(
        _config: PatchConfig,
        base: &IncompletePersistentVector<T, N, B>,
        changed: &IncompletePersistentVector<T, N, B>,
    ) -> Result<Self, Error> {
        Ok(Self {
            edits: PositionalPatch::diff_edits(base, changed),
        })
    }

    fn apply(self, base: &mut IncompletePersistentVector<T, N, B>) -> Result<(), Error> {
        PositionalPatch::apply_edits(self.edits, |i, value| {
            base.get_mut(i)
                .map(|item| *item = value)
                .map_err(|_| Error::PatchIndexOutOfBounds)
        })
    }
}
