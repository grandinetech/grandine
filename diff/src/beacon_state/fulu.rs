use core::marker::PhantomData;

use ssz::Ssz;
use types::{
    deneb::containers::ExecutionPayloadHeader as DenebExecutionPayloadHeader,
    fulu::beacon_state::BeaconState as FuluBeaconState, phase0::primitives::ValidatorIndex,
    preset::Preset, traits::PostFuluBeaconState,
};

use crate::{
    beacon_state::{
        altair::AltairPatch, capella::CapellaPatch, electra::ElectraPatch, phase0::Phase0Patch,
    },
    compress::Compressed,
    error::Error,
    list::VectorPatch,
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct FuluStatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,
    altair: AltairPatch<P>,
    capella: CapellaPatch<P>,
    electra: ElectraPatch<P>,
    fulu: FuluPatch<P>,

    latest_execution_payload_header: ReplacePatch<DenebExecutionPayloadHeader<P>>,
}

impl<P: Preset> Patch<FuluBeaconState<P>> for FuluStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &FuluBeaconState<P>,
        changed: &FuluBeaconState<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            phase0: Patch::diff(config, base, changed)?,
            altair: Patch::diff(config, base, changed)?,
            capella: Patch::diff(config, base, changed)?,
            electra: Patch::diff(config, base, changed)?,
            fulu: Patch::diff(config, base, changed)?,

            latest_execution_payload_header: Patch::diff(
                config,
                &base.latest_execution_payload_header,
                &changed.latest_execution_payload_header,
            )?,
        })
    }

    fn apply(self, base: &mut FuluBeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.altair.apply(base)?;
        self.capella.apply(base)?;
        self.electra.apply(base)?;
        self.fulu.apply(base)?;

        self.latest_execution_payload_header
            .apply(&mut base.latest_execution_payload_header)
    }
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct FuluPatch<P: Preset> {
    proposer_lookahead: Compressed<VectorPatch<ValidatorIndex>>,

    #[ssz(skip)]
    phantom: PhantomData<P>,
}

impl<P: Preset, S: PostFuluBeaconState<P>> Patch<S> for FuluPatch<P> {
    fn diff(config: PatchConfig, base: &S, changed: &S) -> Result<Self, Error> {
        Ok(Self {
            proposer_lookahead: Patch::diff(
                config,
                base.proposer_lookahead(),
                changed.proposer_lookahead(),
            )?,
            phantom: PhantomData,
        })
    }

    fn apply(self, base: &mut S) -> Result<(), Error> {
        self.proposer_lookahead.apply(base.proposer_lookahead_mut())
    }
}
