use core::cmp::Reverse;

use ssz::{ContiguousList, Ssz};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{Ptc, PtcWindow, preset::Preset};

use crate::{
    error::Error,
    list::{PositionalPatch, Unlimited, positional::PositionalEdit},
    patch::{Patch, PatchConfig},
};

/// Patch kind for `ptc_window`, which drops whole epochs of committees off the
/// front and takes on new ones at the back. Only whole-epoch shifts exist, so
/// the one carrying over the most committees is found in a linear scan.
#[derive(Ssz, Debug, Clone)]
#[ssz(derive_hash = false)]
pub struct PtcPatch<P: Preset> {
    shift: u32,
    edits: ContiguousList<PositionalEdit<Ptc<P>>, Unlimited>,
    tail: ContiguousList<Ptc<P>, Unlimited>,
}

impl<P: Preset> Patch<PtcWindow<P>> for PtcPatch<P> {
    fn diff(
        _config: PatchConfig,
        base: &PtcWindow<P>,
        changed: &PtcWindow<P>,
    ) -> Result<Self, Error> {
        let base_items = base.into_iter().collect::<Vec<_>>();
        let changed_items = changed.into_iter().collect::<Vec<_>>();

        let shift = (0..base_items.len())
            .step_by(P::SlotsPerEpoch::USIZE)
            .map(|shift| {
                let carried = base_items[shift..]
                    .iter()
                    .zip(&changed_items)
                    .filter(|(base_item, changed_item)| base_item == changed_item)
                    .count();

                (carried, Reverse(shift))
            })
            .max()
            .map_or(0, |(_, Reverse(shift))| shift);

        Ok(Self {
            shift: u32::try_from(shift).expect("window length should fit in u32"),
            edits: PositionalPatch::diff_edits(
                base_items[shift..].iter().copied(),
                changed_items.iter().copied(),
            ),
            tail: ContiguousList::try_from_iter(
                changed_items[changed_items.len().saturating_sub(shift)..]
                    .iter()
                    .copied()
                    .cloned(),
            )
            .expect("shifted in committees should fit in the SSZ list"),
        })
    }

    fn apply(self, base: &mut PtcWindow<P>) -> Result<(), Error> {
        let Self { shift, edits, tail } = self;

        let shift = usize::try_from(shift).map_err(|_| Error::InvalidPatchEncoding)?;

        if tail.len() != shift {
            return Err(Error::InvalidPatchEncoding);
        }

        if shift > 0 {
            let carried = base.into_iter().skip(shift).cloned().collect::<Vec<_>>();

            for (index, value) in carried.into_iter().chain(tail).enumerate() {
                let index = u64::try_from(index).map_err(|_| Error::InvalidPatchEncoding)?;

                *base
                    .get_mut(index)
                    .map_err(|_| Error::PatchIndexOutOfBounds)? = value;
            }
        }

        PositionalPatch::apply_edits(edits, |index, value| {
            base.get_mut(index)
                .map(|item| *item = value)
                .map_err(|_| Error::PatchIndexOutOfBounds)
        })
    }
}

#[cfg(test)]
mod tests {
    use ssz::SszWrite as _;
    use types::preset::Minimal;

    use crate::list::VectorPatch;

    use super::*;

    type Window = PtcWindow<Minimal>;

    fn committee(seed: u64) -> Ptc<Minimal> {
        Ptc::<Minimal>::try_from_iter((seed.saturating_mul(100)..).take(16)).expect("length")
    }

    fn window(seeds: impl IntoIterator<Item = u64>) -> Window {
        Window::try_from_iter(seeds.into_iter().map(committee)).expect("length matches")
    }

    #[test]
    fn round_trips_a_shifted_window() {
        let base = window(0..24);

        for changed in [
            window(8..32),
            window(16..40),
            window(0..24),
            window(100..124),
            window((8..31).chain([7])),
        ] {
            let patch = PtcPatch::<Minimal>::diff(PatchConfig::default(), &base, &changed)
                .expect("ptc patch should represent the change");

            let mut applied = base.clone();
            patch.apply(&mut applied).expect("patch should apply");

            assert_eq!(applied, changed);
        }
    }

    #[test]
    fn shifts_by_whole_epochs_only() {
        let base = window(0..24);

        assert_eq!(
            PtcPatch::<Minimal>::diff(PatchConfig::default(), &base, &window(8..32))
                .expect("ptc patch should represent the change")
                .shift,
            8,
        );

        assert_eq!(
            PtcPatch::<Minimal>::diff(PatchConfig::default(), &base, &window(3..27))
                .expect("ptc patch should represent the change")
                .shift,
            0,
        );
    }

    #[test]
    fn a_shifted_window_encodes_smaller_than_positional_edits() {
        let base = window(0..24);
        let changed = window(8..32);

        let shifted = PtcPatch::<Minimal>::diff(PatchConfig::default(), &base, &changed)
            .expect("ptc patch should represent the change")
            .to_ssz()
            .expect("patch should serialize");

        let positional = VectorPatch::<Ptc<Minimal>>::diff(PatchConfig::default(), &base, &changed)
            .expect("positional patch should represent the change")
            .to_ssz()
            .expect("patch should serialize");

        assert!(
            shifted.len() < positional.len(),
            "shifted {} should beat positional {}",
            shifted.len(),
            positional.len(),
        );
    }

    #[test]
    fn a_tail_that_does_not_match_the_shift_is_rejected() {
        let mut base = window(0..24);
        let changed = window(8..32);

        let patch = PtcPatch::<Minimal>::diff(PatchConfig::default(), &base, &changed)
            .expect("ptc patch should represent the change");

        let truncated = PtcPatch::<Minimal> {
            tail: ContiguousList::try_from_iter([committee(24)])
                .expect("length is below the maximum"),
            ..patch
        };

        let error = truncated
            .apply(&mut base)
            .expect_err("a shift of eight needs eight tail committees");

        assert!(matches!(error, Error::InvalidPatchEncoding));
    }
}
