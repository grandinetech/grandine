use serde::{Deserialize, Serialize};
use ssz::Hc;
use std::sync::Arc;
use types::{combined::BeaconState, phase0::primitives::Slot, preset::Preset};

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
}

pub fn delta<P: Preset>(
    base: &Arc<BeaconState<P>>,
    target: &Arc<BeaconState<P>>,
) -> BeaconStateDelta<P> {
    match (base.as_ref(), &target.as_ref()) {
        (BeaconState::Phase0(base), BeaconState::Phase0(target)) => {
            BeaconStateDelta::Phase0(phase0_delta(base, (**target).clone()))
        }
        (BeaconState::Altair(base), BeaconState::Altair(target)) => {
            BeaconStateDelta::Altair(altair_delta(base, (**target).clone()))
        }
        (BeaconState::Bellatrix(base), BeaconState::Bellatrix(target)) => {
            BeaconStateDelta::Bellatrix(bellatrix_delta(base, (**target).clone()))
        }
        (BeaconState::Capella(base), BeaconState::Capella(target)) => {
            BeaconStateDelta::Capella(capella_delta(base, (**target).clone()))
        }
        (BeaconState::Deneb(base), BeaconState::Deneb(target)) => {
            BeaconStateDelta::Deneb(deneb_delta(base, (**target).clone()))
        }
        (BeaconState::Electra(base), BeaconState::Electra(target)) => {
            BeaconStateDelta::Electra(electra_delta(base, (**target).clone()))
        }
        (BeaconState::Fulu(base), BeaconState::Fulu(target)) => {
            BeaconStateDelta::Fulu(fulu_delta(base, (**target).clone()))
        }
        _ => panic!("Cannot create delta across different phases"),
    }
}

pub fn apply_delta<P: Preset>(base: &BeaconState<P>, delta: BeaconStateDelta<P>) -> BeaconState<P> {
    match (&base, delta) {
        (BeaconState::Phase0(base), BeaconStateDelta::Phase0(delta)) => {
            BeaconState::Phase0(Hc::from(apply_phase0_delta((**base).clone(), delta)))
        }
        (BeaconState::Altair(base), BeaconStateDelta::Altair(delta)) => {
            BeaconState::Altair(Hc::from(apply_altair_delta((**base).clone(), delta)))
        }
        (BeaconState::Bellatrix(base), BeaconStateDelta::Bellatrix(delta)) => {
            BeaconState::Bellatrix(Hc::from(apply_bellatrix_delta((**base).clone(), delta)))
        }
        (BeaconState::Capella(base), BeaconStateDelta::Capella(delta)) => {
            BeaconState::Capella(Hc::from(apply_capella_delta((**base).clone(), delta)))
        }
        (BeaconState::Deneb(base), BeaconStateDelta::Deneb(delta)) => {
            BeaconState::Deneb(Hc::from(apply_deneb_delta((**base).clone(), delta)))
        }

        (BeaconState::Electra(base), BeaconStateDelta::Electra(delta)) => {
            BeaconState::Electra(Hc::from(apply_electra_delta((**base).clone(), delta)))
        }
        (BeaconState::Fulu(base), BeaconStateDelta::Fulu(delta)) => {
            BeaconState::Fulu(Hc::from(apply_fulu_delta((**base).clone(), delta)))
        }
        _ => panic!("Cannot apply delta from different phase"),
    }
}
