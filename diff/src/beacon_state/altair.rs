use std::sync::Arc;

use ssz::{Hc, Ssz};
use types::{
    altair::{beacon_state::BeaconState as AltairBeaconState, containers::SyncCommittee},
    preset::Preset,
    traits::PostAltairBeaconState,
};

use crate::{
    beacon_state::phase0::Phase0Patch,
    compress::Compressed,
    error::Error,
    list::{ParticipationPatch, PositionalPatch},
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct AltairStatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,
    altair: AltairPatch<P>,
}

impl<P: Preset> Patch<AltairBeaconState<P>> for AltairStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &AltairBeaconState<P>,
        changed: &AltairBeaconState<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            phase0: Patch::diff(config, base, changed)?,
            altair: Patch::diff(config, base, changed)?,
        })
    }

    fn apply(self, base: &mut AltairBeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.altair.apply(base)
    }
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct AltairPatch<P: Preset> {
    previous_epoch_participation: Compressed<ParticipationPatch>,
    current_epoch_participation: Compressed<ParticipationPatch>,
    inactivity_scores: Compressed<PositionalPatch<u64>>,
    current_sync_committee: ReplacePatch<Arc<Hc<SyncCommittee<P>>>>,
    next_sync_committee: ReplacePatch<Arc<Hc<SyncCommittee<P>>>>,
}

impl<P: Preset, S: PostAltairBeaconState<P>> Patch<S> for AltairPatch<P> {
    fn diff(config: PatchConfig, base: &S, changed: &S) -> Result<Self, Error> {
        Ok(Self {
            previous_epoch_participation: Patch::diff(
                config,
                base.previous_epoch_participation(),
                changed.previous_epoch_participation(),
            )?,
            current_epoch_participation: Patch::diff(
                config,
                base.current_epoch_participation(),
                changed.current_epoch_participation(),
            )?,
            inactivity_scores: Patch::diff(
                config,
                base.inactivity_scores(),
                changed.inactivity_scores(),
            )?,
            current_sync_committee: Patch::diff(
                config,
                base.current_sync_committee(),
                changed.current_sync_committee(),
            )?,
            next_sync_committee: Patch::diff(
                config,
                base.next_sync_committee(),
                changed.next_sync_committee(),
            )?,
        })
    }

    fn apply(self, base: &mut S) -> Result<(), Error> {
        self.previous_epoch_participation
            .apply(base.previous_epoch_participation_mut())?;
        self.current_epoch_participation
            .apply(base.current_epoch_participation_mut())?;
        self.inactivity_scores.apply(base.inactivity_scores_mut())?;
        self.current_sync_committee
            .apply(base.current_sync_committee_mut())?;
        self.next_sync_committee
            .apply(base.next_sync_committee_mut())
    }
}
