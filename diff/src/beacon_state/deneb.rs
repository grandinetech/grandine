use ssz::Ssz;
use types::{
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::ExecutionPayloadHeader as DenebExecutionPayloadHeader,
    },
    preset::Preset,
};

use crate::{
    beacon_state::{altair::AltairPatch, capella::CapellaPatch, phase0::Phase0Patch},
    error::Error,
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct DenebStatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,
    altair: AltairPatch<P>,
    capella: CapellaPatch<P>,

    latest_execution_payload_header: ReplacePatch<DenebExecutionPayloadHeader<P>>,
}

impl<P: Preset> Patch<DenebBeaconState<P>> for DenebStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &DenebBeaconState<P>,
        changed: &DenebBeaconState<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            phase0: Patch::diff(config, base, changed)?,
            altair: Patch::diff(config, base, changed)?,
            capella: Patch::diff(config, base, changed)?,
            latest_execution_payload_header: Patch::diff(
                config,
                &base.latest_execution_payload_header,
                &changed.latest_execution_payload_header,
            )?,
        })
    }

    fn apply(self, base: &mut DenebBeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.altair.apply(base)?;
        self.capella.apply(base)?;

        self.latest_execution_payload_header
            .apply(&mut base.latest_execution_payload_header)
    }
}
