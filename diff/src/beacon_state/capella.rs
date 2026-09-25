use core::marker::PhantomData;

use ssz::Ssz;
use types::{
    capella::{
        beacon_state::BeaconState as CapellaBeaconState,
        containers::{ExecutionPayloadHeader as CapellaExecutionPayloadHeader, HistoricalSummary},
        primitives::WithdrawalIndex,
    },
    phase0::primitives::ValidatorIndex,
    preset::Preset,
    traits::PostCapellaBeaconState,
};

use crate::{
    beacon_state::{altair::AltairPatch, phase0::Phase0Patch},
    error::Error,
    list::PositionalPatch,
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct CapellaStatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,
    altair: AltairPatch<P>,
    capella: CapellaPatch<P>,

    latest_execution_payload_header: ReplacePatch<CapellaExecutionPayloadHeader<P>>,
}

impl<P: Preset> Patch<CapellaBeaconState<P>> for CapellaStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &CapellaBeaconState<P>,
        changed: &CapellaBeaconState<P>,
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

    fn apply(self, base: &mut CapellaBeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.altair.apply(base)?;
        self.capella.apply(base)?;

        self.latest_execution_payload_header
            .apply(&mut base.latest_execution_payload_header)
    }
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct CapellaPatch<P: Preset> {
    next_withdrawal_index: ReplacePatch<WithdrawalIndex>,
    next_withdrawal_validator_index: ReplacePatch<ValidatorIndex>,
    historical_summaries: PositionalPatch<HistoricalSummary>,

    #[ssz(skip)]
    phantom: PhantomData<P>,
}

impl<P: Preset, S: PostCapellaBeaconState<P>> Patch<S> for CapellaPatch<P> {
    fn diff(config: PatchConfig, base: &S, changed: &S) -> Result<Self, Error> {
        Ok(Self {
            next_withdrawal_index: Patch::diff(
                config,
                &base.next_withdrawal_index(),
                &changed.next_withdrawal_index(),
            )?,
            next_withdrawal_validator_index: Patch::diff(
                config,
                &base.next_withdrawal_validator_index(),
                &changed.next_withdrawal_validator_index(),
            )?,
            historical_summaries: Patch::diff(
                config,
                base.historical_summaries(),
                changed.historical_summaries(),
            )?,
            phantom: PhantomData,
        })
    }

    fn apply(self, base: &mut S) -> Result<(), Error> {
        self.next_withdrawal_index
            .apply(base.next_withdrawal_index_mut())?;
        self.next_withdrawal_validator_index
            .apply(base.next_withdrawal_validator_index_mut())?;
        self.historical_summaries
            .apply(base.historical_summaries_mut())
    }
}
