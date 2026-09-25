use ssz::{ContiguousList, Ssz, SszListMut};
use try_from_iterator::TryFromIterator;
use types::altair::primitives::ParticipationFlags;

use crate::{
    error::Error,
    list::{Unlimited, position_set::PositionSet},
    patch::{Patch, PatchConfig},
};

#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct ParticipationPatch {
    base_len: u32,
    positions: PositionSet,
    edits: ContiguousList<ParticipationFlags, Unlimited>,
    appended: ContiguousList<ParticipationFlags, Unlimited>,
}

impl<C: SszListMut<ParticipationFlags> + ?Sized> Patch<C> for ParticipationPatch {
    fn diff(_config: PatchConfig, base: &C, changed: &C) -> Result<Self, Error> {
        if changed.len_usize() < base.len_usize() {
            return Err(Error::UnsupportedDiff);
        }

        let mut positions = PositionSet::builder(base.len_usize());

        let mut edits = Vec::new();

        for (index, (before, after)) in base.iter().zip(changed.iter()).enumerate() {
            if before == after {
                continue;
            }

            positions.record(index);
            edits.push(before ^ after);
        }

        Ok(Self {
            base_len: u32::try_from(base.len_usize()).map_err(|_| Error::PatchListLimitExceeded)?,
            positions: positions.finish(),
            edits: ContiguousList::try_from(edits)
                .expect("participation edits should fit in the SSZ list"),
            appended: ContiguousList::try_from_iter(changed.iter().skip(base.len_usize()).copied())
                .expect("appended participation flags should fit in the SSZ list"),
        })
    }

    fn apply(self, base: &mut C) -> Result<(), Error> {
        let Self {
            base_len,
            positions,
            edits,
            appended,
        } = self;

        if base.len_usize() != usize::try_from(base_len).map_err(|_| Error::InvalidPatchEncoding)? {
            return Err(Error::PatchBaseLengthMismatch);
        }

        let mut edits = edits.into_iter();

        positions.apply(base, |flags| {
            edits
                .next()
                .map(|edit| *flags ^= edit)
                .ok_or(Error::InvalidPatchEncoding)
        })?;

        if edits.next().is_some() {
            return Err(Error::InvalidPatchEncoding);
        }

        base.extend(&mut appended.into_iter())
            .map_err(|_| Error::PatchListLimitExceeded)
    }
}

#[cfg(test)]
mod tests {
    use ssz::PersistentProgressiveList;

    use super::*;

    #[test]
    fn round_trips_over_persistent_progressive_list() {
        type List = PersistentProgressiveList<ParticipationFlags>;

        let base = List::try_from_iter((0..20).map(|index| index % 8))
            .expect("length is below the maximum");

        for changed in [
            List::try_from_iter((0..20).map(|index| index % 8)),
            List::try_from_iter((0..20).map(|index| (index + 3) % 8)),
            List::try_from_iter((0..30).map(|index| index % 8)),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = ParticipationPatch::diff(PatchConfig::default(), &base, &changed)
                .expect("participation patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn a_base_of_the_wrong_length_is_rejected() {
        type List = PersistentProgressiveList<ParticipationFlags>;

        let base = List::try_from_iter((0..20).map(|index| index % 8))
            .expect("length is below the maximum");

        let changed = List::try_from_iter((0..20).map(|index| (index + 3) % 8))
            .expect("length is below the maximum");

        let patch = ParticipationPatch::diff(PatchConfig::default(), &base, &changed)
            .expect("participation patch should represent the change");

        let mut shorter = List::try_from_iter((0..10).map(|index| index % 8))
            .expect("length is below the maximum");

        let error = patch
            .apply(&mut shorter)
            .expect_err("the patch was diffed against a twenty-element list");

        assert!(matches!(error, Error::PatchBaseLengthMismatch));
    }
}
