#[cfg(target_os = "zkvm")]
pub use std::vec::Vec as Vector;

#[cfg(not(target_os = "zkvm"))]
pub use im::Vector;

#[cfg(not(target_os = "zkvm"))]
pub fn vector_bundles<T: Clone>(vector: &Vector<T>) -> impl Iterator<Item = &[T]> {
    vector.leaves()
}

#[cfg(target_os = "zkvm")]
pub fn vector_bundles<T>(vector: &Vector<T>) -> impl Iterator<Item = &[T]> {
    core::iter::once(vector.as_slice())
}

pub fn zip_unshared<'list, T: 'list>(
    mut base: impl Iterator<Item = &'list [T]>,
    mut changed: impl Iterator<Item = &'list [T]>,
) -> impl Iterator<Item = (usize, &'list T, &'list T)> {
    let mut base_rest: &'list [T] = &[];
    let mut changed_rest: &'list [T] = &[];
    let mut index = 0_usize;

    core::iter::from_fn(move || {
        loop {
            if base_rest.is_empty() {
                base_rest = base.next()?;
            }

            if changed_rest.is_empty() {
                changed_rest = changed.next()?;
            }

            let length = base_rest.len().min(changed_rest.len());
            let start = index;

            let (base_run, base_tail) = base_rest.split_at(length);
            let (changed_run, changed_tail) = changed_rest.split_at(length);

            base_rest = base_tail;
            changed_rest = changed_tail;
            index = index.saturating_add(length);

            if !core::ptr::eq(base_run, changed_run) {
                return Some((start, base_run, changed_run));
            }
        }
    })
    .flat_map(|(start, base_run, changed_run)| {
        (start..)
            .zip(base_run)
            .zip(changed_run)
            .map(|((index, base), changed)| (index, base, changed))
    })
}

#[cfg(test)]
mod tests {
    use ssz::{PersistentList, SszList as _, SszListMut as _};
    use try_from_iterator::TryFromIterator as _;
    use typenum::{U8, U4096};

    use super::*;

    type List = PersistentList<u64, U4096, U8>;

    #[test]
    fn only_the_bundles_that_were_written_to_are_yielded() {
        let base = List::try_from_iter(0..20).expect("length is below the maximum");
        let mut changed = base.clone();

        *changed.get_mut(9).expect("index is within bounds") = 90;

        let pairs = zip_unshared(base.bundles(), changed.bundles()).collect::<Vec<_>>();

        assert_eq!(
            pairs.iter().map(|(index, _, _)| *index).collect::<Vec<_>>(),
            (8..16).collect::<Vec<_>>(),
        );
        assert_eq!(pairs[1], (9, &9, &90));
    }

    #[test]
    fn bundles_of_different_sizes_are_paired_by_index() {
        let base = [[1_u64, 2].as_slice(), &[3, 4, 5]];
        let changed = [[1_u64].as_slice(), &[2, 7], &[4, 5, 6]];

        assert_eq!(
            zip_unshared(base.into_iter(), changed.into_iter()).collect::<Vec<_>>(),
            [
                (0, &1, &1),
                (1, &2, &2),
                (2, &3, &7),
                (3, &4, &4),
                (4, &5, &5)
            ],
        );
    }
}
