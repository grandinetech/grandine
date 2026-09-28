use ssz::{ContiguousList, Ssz, SszListMut, SszRead, SszWrite};
use try_from_iterator::TryFromIterator as _;

use crate::{
    error::Error,
    list::Unlimited,
    patch::{Patch, PatchConfig},
};

/// Patch kind that efficiently tracks list changes, by interpreting underlying
/// container as a FIFO-queue.
///
/// It supports two operations: deleting items from the beginning, and appending
/// items to the end. Thus, theoretically, it supports *any* kind of change in
/// underlying list. However, for random changes this patch is suboptimal, as
/// it will just pop out all items from queue, and push them back. For generic
/// lists, see [`PositionalPatch`](PositionalPatch).
#[derive(Ssz, Debug, Clone)]
#[ssz(
    derive_hash = false,
    bound = "T: SszWrite",
    bound_for_read = "T: SszRead<C> + SszWrite"
)]
pub struct QueuePatch<T> {
    base_len: u32,
    delete: u32,
    appended: ContiguousList<T, Unlimited>,
}

impl<T, C> Patch<C> for QueuePatch<T>
where
    T: Clone + Eq,
    C: SszListMut<T> + ?Sized,
{
    fn diff(_config: PatchConfig, base: &C, changed: &C) -> Result<Self, Error> {
        let mut changed_iter = changed.iter().peekable();
        let mut to_delete = 0u32;
        let mut matching = false;
        let mut rebuild = false;

        for base_item in base.iter() {
            match changed_iter.peek() {
                Some(changed_item) if *changed_item == base_item => {
                    matching = true;
                    let _ = changed_iter.next();
                }
                _ if matching => {
                    rebuild = true;
                    break;
                }
                _ => to_delete = to_delete.saturating_add(1),
            }
        }

        let appended = if rebuild {
            to_delete = u32::try_from(base.len_usize())
                .expect("queue patch delete count should fit in u32");

            ContiguousList::try_from_iter(changed.iter().cloned())
        } else {
            ContiguousList::try_from_iter(changed_iter.cloned())
        }
        .expect("queue patch appended items should fit in the SSZ list");

        Ok(Self {
            base_len: u32::try_from(base.len_usize()).map_err(|_| Error::PatchListLimitExceeded)?,
            delete: to_delete,
            appended,
        })
    }

    fn apply(self, base: &mut C) -> Result<(), Error> {
        if base.len_usize()
            != usize::try_from(self.base_len).map_err(|_| Error::InvalidPatchEncoding)?
        {
            return Err(Error::PatchBaseLengthMismatch);
        }

        let delete = u64::from(self.delete);
        let length = base.len_u64();

        if delete > length {
            return Err(Error::PatchIndexOutOfBounds);
        }

        base.retain_range(delete, length)
            .map_err(|_| Error::PatchIndexOutOfBounds)?;

        base.extend(&mut self.appended.into_iter())
            .map_err(|_| Error::PatchListLimitExceeded)
    }
}

#[cfg(test)]
mod tests {
    use ssz::{PersistentList, PersistentProgressiveList};
    use typenum::U64;

    use super::*;

    #[test]
    fn round_trips_over_persistent_list() {
        type List = PersistentList<u64, U64>;

        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        for changed in [
            List::try_from_iter(0..20),
            List::try_from_iter(0..30),
            List::try_from_iter(5..20),
            List::try_from_iter(5..30),
            List::try_from_iter(0..0),
            List::try_from_iter(100..110),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = QueuePatch::diff(PatchConfig::default(), &base, &changed)
                .expect("queue patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn round_trips_over_persistent_progressive_list() {
        type List = PersistentProgressiveList<u64>;

        let base = List::try_from_iter(0..20).expect("length is below the maximum");

        for changed in [
            List::try_from_iter(0..20),
            List::try_from_iter(0..30),
            List::try_from_iter(5..20),
            List::try_from_iter(5..30),
            List::try_from_iter(0..0),
            List::try_from_iter(100..110),
        ] {
            let changed = changed.expect("length is below the maximum");

            let patch = QueuePatch::diff(PatchConfig::default(), &base, &changed)
                .expect("queue patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn a_base_of_the_wrong_length_is_rejected() {
        type List = PersistentList<u64, U64>;

        // Both the deletion count and the appended tail assume the base the patch was diffed
        // against, so a shorter base would otherwise apply cleanly into a wrong queue.
        let base = List::try_from_iter(0..5).expect("length is below the maximum");
        let changed = List::try_from_iter(2..6).expect("length is below the maximum");

        let patch = QueuePatch::diff(PatchConfig::default(), &base, &changed)
            .expect("queue patch should represent the change");

        let mut shorter = List::try_from_iter(0..3).expect("length is below the maximum");

        let error = patch
            .apply(&mut shorter)
            .expect_err("the patch was diffed against a five-element list");

        assert!(matches!(error, Error::PatchBaseLengthMismatch));
    }
}
