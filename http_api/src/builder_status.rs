use bls::PublicKeyBytes;
use helper_functions::predicates::is_active_builder;
use parse_display::FromStr;
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_with::DeserializeFromStr;
use types::{
    combined::BeaconState, gloas::containers::Builder, gloas::primitives::BuilderIndex,
    phase0::consts::FAR_FUTURE_EPOCH, preset::Preset, traits::BeaconState as _,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromStr, DeserializeFromStr)]
#[cfg_attr(test, derive(Debug))]
pub enum BuilderId {
    #[display("{0}")]
    BuilderIndex(BuilderIndex),
    #[display("{0:?}")]
    PublicKey(PublicKeyBytes),
}

#[derive(Deserialize)]
pub struct BuilderIdsAndStatusesBody {
    #[serde(default)]
    ids: Vec<BuilderId>,
    #[serde(default)]
    statuses: Vec<BuilderStatus>,
}

impl BuilderIdsAndStatusesBody {
    pub fn ids(&self) -> &[BuilderId] {
        self.ids.as_slice()
    }

    pub fn statuses(&self) -> &[BuilderStatus] {
        self.statuses.as_slice()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[cfg_attr(test, derive(Debug))]
#[repr(u8)]
pub enum BuilderStatus {
    Pending = 0,
    Active = 1,
    Exited = 2,
}

impl BuilderStatus {
    pub fn new<P: Preset>(builder: &Builder, state: &BeaconState<P>) -> Self {
        let finalized_epoch = state.finalized_checkpoint().epoch;

        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
            return Self::Exited;
        }

        if is_active_builder(builder, finalized_epoch) {
            return Self::Active;
        }

        Self::Pending
    }

    pub fn matches(self, other: Self) -> bool {
        self == other
    }
}
