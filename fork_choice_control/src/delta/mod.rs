use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use ssz::Hc;
use std::sync::Arc;
use types::{combined::BeaconState, nonstandard::Phase, phase0::primitives::Slot, preset::Preset};

mod altair;
mod bellatrix;
mod capella;
mod deneb;
mod electra;
mod fulu;
mod phase0;

pub use altair::{
    BeaconStateDelta as AltairBeaconStateDelta, apply_delta as apply_altair_delta,
    delta as altair_delta,
};
pub use bellatrix::{
    BeaconStateDelta as BellatrixBeaconStateDelta, apply_delta as apply_bellatrix_delta,
    delta as bellatrix_delta,
};
pub use capella::{
    BeaconStateDelta as CapellaBeaconStateDelta, apply_delta as apply_capella_delta,
    delta as capella_delta,
};
pub use deneb::{
    BeaconStateDelta as DenebBeaconStateDelta, apply_delta as apply_deneb_delta,
    delta as deneb_delta,
};
pub use electra::{
    BeaconStateDelta as ElectraBeaconStateDelta, apply_delta as apply_electra_delta,
    delta as electra_delta,
};
pub use fulu::{
    BeaconStateDelta as FuluBeaconStateDelta, apply_delta as apply_fulu_delta, delta as fulu_delta,
};
pub use phase0::{
    BeaconStateDelta as Phase0BeaconStateDelta, apply_delta as apply_phase0_delta,
    delta as phase0_delta,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub enum BeaconStateDelta<P: Preset> {
    Phase0(Phase0BeaconStateDelta<P>),
    Altair(AltairBeaconStateDelta<P>),
    Bellatrix(BellatrixBeaconStateDelta<P>),
    Capella(CapellaBeaconStateDelta<P>),
    Deneb(DenebBeaconStateDelta<P>),
    Electra(ElectraBeaconStateDelta<P>),
    Fulu(FuluBeaconStateDelta<P>),
}

impl<P: Preset> BeaconStateDelta<P> {
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(phase0_delta) => phase0_delta.slot,
            Self::Altair(altair_delta) => altair_delta.slot,
            Self::Bellatrix(bellatrix_delta) => bellatrix_delta.slot,
            Self::Capella(capella_delta) => capella_delta.slot,
            Self::Deneb(deneb_delta) => deneb_delta.slot,
            Self::Electra(electra_delta) => electra_delta.slot,
            Self::Fulu(fulu_delta) => fulu_delta.slot,
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
            Self::Fulu(_) => Phase::Fulu,
        }
    }
}

pub fn delta<P: Preset>(
    base: &Arc<BeaconState<P>>,
    target: &Arc<BeaconState<P>>,
) -> Result<BeaconStateDelta<P>> {
    match (base.as_ref(), &target.as_ref()) {
        (BeaconState::Phase0(base), BeaconState::Phase0(target)) => Ok(BeaconStateDelta::Phase0(
            phase0_delta(base, (**target).clone()),
        )),
        (BeaconState::Altair(base), BeaconState::Altair(target)) => Ok(BeaconStateDelta::Altair(
            altair_delta(base, (**target).clone()),
        )),
        (BeaconState::Bellatrix(base), BeaconState::Bellatrix(target)) => Ok(
            BeaconStateDelta::Bellatrix(bellatrix_delta(base, (**target).clone())),
        ),
        (BeaconState::Capella(base), BeaconState::Capella(target)) => Ok(
            BeaconStateDelta::Capella(capella_delta(base, (**target).clone())),
        ),
        (BeaconState::Deneb(base), BeaconState::Deneb(target)) => Ok(BeaconStateDelta::Deneb(
            deneb_delta(base, (**target).clone()),
        )),
        (BeaconState::Electra(base), BeaconState::Electra(target)) => Ok(
            BeaconStateDelta::Electra(electra_delta(base, (**target).clone())),
        ),
        (BeaconState::Fulu(base), BeaconState::Fulu(target)) => {
            Ok(BeaconStateDelta::Fulu(fulu_delta(base, (**target).clone())))
        }
        _ => bail!(
            "Cannot create delta across different phases: base is {:?}, target is {:?}",
            base.phase(),
            target.phase()
        ),
    }
}

pub fn apply_delta<P: Preset>(
    base: &BeaconState<P>,
    delta: BeaconStateDelta<P>,
) -> Result<BeaconState<P>> {
    let delta_phase = delta.phase();
    match (&base, delta) {
        (BeaconState::Phase0(base), BeaconStateDelta::Phase0(delta)) => Ok(BeaconState::Phase0(
            Hc::from(apply_phase0_delta((**base).clone(), delta)),
        )),
        (BeaconState::Altair(base), BeaconStateDelta::Altair(delta)) => Ok(BeaconState::Altair(
            Hc::from(apply_altair_delta((**base).clone(), delta)),
        )),
        (BeaconState::Bellatrix(base), BeaconStateDelta::Bellatrix(delta)) => Ok(
            BeaconState::Bellatrix(Hc::from(apply_bellatrix_delta((**base).clone(), delta))),
        ),
        (BeaconState::Capella(base), BeaconStateDelta::Capella(delta)) => Ok(BeaconState::Capella(
            Hc::from(apply_capella_delta((**base).clone(), delta)),
        )),
        (BeaconState::Deneb(base), BeaconStateDelta::Deneb(delta)) => Ok(BeaconState::Deneb(
            Hc::from(apply_deneb_delta((**base).clone(), delta)),
        )),
        (BeaconState::Electra(base), BeaconStateDelta::Electra(delta)) => Ok(BeaconState::Electra(
            Hc::from(apply_electra_delta((**base).clone(), delta)),
        )),
        (BeaconState::Fulu(base), BeaconStateDelta::Fulu(delta)) => Ok(BeaconState::Fulu(
            Hc::from(apply_fulu_delta((**base).clone(), delta)),
        )),
        _ => bail!(
            "Cannot apply delta from different phase: base is {:?}, delta is {:?}",
            base.phase(),
            delta_phase
        ),
    }
}
