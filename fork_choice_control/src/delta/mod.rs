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
    apply_delta as apply_altair_delta, delta as altair_delta,
    BeaconStateDelta as AltairBeaconStateDelta,
};
pub use bellatrix::{
    apply_delta as apply_bellatrix_delta, delta as bellatrix_delta,
    BeaconStateDelta as BellatrixBeaconStateDelta,
};
pub use capella::{
    apply_delta as apply_capella_delta, delta as capella_delta,
    BeaconStateDelta as CapellaBeaconStateDelta,
};
pub use deneb::{
    apply_delta as apply_deneb_delta, delta as deneb_delta,
    BeaconStateDelta as DenebBeaconStateDelta,
};
pub use electra::{
    apply_delta as apply_electra_delta, delta as electra_delta,
    BeaconStateDelta as ElectraBeaconStateDelta,
};
pub use fulu::{
    apply_delta as apply_fulu_delta, delta as fulu_delta, BeaconStateDelta as FuluBeaconStateDelta,
};
pub use phase0::{
    apply_delta as apply_phase0_delta, delta as phase0_delta,
    BeaconStateDelta as Phase0BeaconStateDelta,
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
    pub fn slot(&self) -> Slot {
        match self {
            BeaconStateDelta::Phase0(phase0_delta) => phase0_delta.slot,
            BeaconStateDelta::Altair(altair_delta) => altair_delta.slot,
            BeaconStateDelta::Bellatrix(bellatrix_delta) => bellatrix_delta.slot,
            BeaconStateDelta::Capella(capella_delta) => capella_delta.slot,
            BeaconStateDelta::Deneb(deneb_delta) => deneb_delta.slot,
            BeaconStateDelta::Electra(electra_delta) => electra_delta.slot,
            BeaconStateDelta::Fulu(fulu_delta) => fulu_delta.slot,
        }
    }
}

pub fn delta<P: Preset>(
    base: Arc<BeaconState<P>>,
    target: Arc<BeaconState<P>>,
) -> BeaconStateDelta<P> {
    match (base.as_ref(), &target.as_ref()) {
        (BeaconState::Phase0(base), BeaconState::Phase0(target)) => {
            BeaconStateDelta::Phase0(phase0_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Altair(base), BeaconState::Altair(target)) => {
            BeaconStateDelta::Altair(altair_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Bellatrix(base), BeaconState::Bellatrix(target)) => {
            BeaconStateDelta::Bellatrix(bellatrix_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Capella(base), BeaconState::Capella(target)) => {
            BeaconStateDelta::Capella(capella_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Deneb(base), BeaconState::Deneb(target)) => {
            BeaconStateDelta::Deneb(deneb_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Electra(base), BeaconState::Electra(target)) => {
            BeaconStateDelta::Electra(electra_delta((**base).clone(), (**target).clone()))
        }
        (BeaconState::Fulu(base), BeaconState::Fulu(target)) => {
            BeaconStateDelta::Fulu(fulu_delta((**base).clone(), (**target).clone()))
        }
        _ => panic!("Cannot create delta across different phases"),
    }
}

pub fn apply_delta<P: Preset>(base: BeaconState<P>, delta: BeaconStateDelta<P>) -> BeaconState<P> {
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
