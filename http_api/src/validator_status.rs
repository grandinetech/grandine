use bls::PublicKeyBytes;
use helper_functions::{accessors, misc};
use parse_display::{Display, FromStr};
use serde::Deserialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use types::{
    combined::BeaconState,
    phase0::{consts::FAR_FUTURE_EPOCH, containers::Validator, primitives::ValidatorIndex},
    preset::Preset,
    traits::BeaconState as _,
};

pub trait ValidatorIdsAndStatuses {
    fn ids(&self) -> &[ValidatorId];
    fn statuses(&self) -> &[ValidatorStatus];
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorIdQuery {
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_vec_from_string_or_vec"
    )]
    pub id: Vec<ValidatorId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct ValidatorIdsAndStatusesQuery {
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_vec_from_string_or_vec"
    )]
    pub id: Vec<ValidatorId>,
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_vec_from_string_or_vec"
    )]
    pub status: Vec<ValidatorStatus>,
}

impl ValidatorIdsAndStatuses for ValidatorIdsAndStatusesQuery {
    fn ids(&self) -> &[ValidatorId] {
        self.id.as_slice()
    }

    fn statuses(&self) -> &[ValidatorStatus] {
        self.status.as_slice()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorIdsAndStatusesBody {
    #[serde(default)]
    ids: Vec<ValidatorId>,
    #[serde(default)]
    statuses: Vec<ValidatorStatus>,
}

impl ValidatorIdsAndStatuses for ValidatorIdsAndStatusesBody {
    fn ids(&self) -> &[ValidatorId] {
        self.ids.as_slice()
    }

    fn statuses(&self) -> &[ValidatorStatus] {
        self.statuses.as_slice()
    }
}

#[derive(Clone, Copy, FromStr, DeserializeFromStr)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug, Display))]
pub enum ValidatorId {
    #[display("{0}")]
    ValidatorIndex(ValidatorIndex),
    #[display("{0:?}")]
    PublicKey(PublicKeyBytes),
}

impl ValidatorId {
    pub fn validator_index<P: Preset>(self, state: &BeaconState<P>) -> Option<ValidatorIndex> {
        match self {
            Self::ValidatorIndex(validator_index) => Some(validator_index),
            Self::PublicKey(pubkey) => accessors::index_of_public_key(state, pubkey),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Display, FromStr, DeserializeFromStr, SerializeDisplay)]
#[display(style = "snake_case")]
#[cfg_attr(test, derive(Debug))]
pub enum ValidatorStatus {
    Active,
    ActiveExiting,
    ActiveOngoing,
    ActiveSlashed,
    Exited,
    ExitedUnslashed,
    ExitedSlashed,
    Pending,
    PendingInitialized,
    PendingQueued,
    Withdrawal,
    WithdrawalDone,
    WithdrawalPossible,
}

impl ValidatorStatus {
    pub fn new<P: Preset>(validator: &Validator, state: &BeaconState<P>) -> Self {
        let current_epoch = misc::compute_epoch_at_slot::<P>(state.slot());

        if validator.activation_epoch > current_epoch {
            if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH {
                return Self::PendingInitialized;
            }

            return Self::PendingQueued;
        }

        if validator.activation_epoch <= current_epoch && current_epoch < validator.exit_epoch {
            if validator.exit_epoch == FAR_FUTURE_EPOCH {
                return Self::ActiveOngoing;
            }

            if validator.slashed {
                return Self::ActiveSlashed;
            }

            return Self::ActiveExiting;
        }

        if validator.exit_epoch <= current_epoch && current_epoch < validator.withdrawable_epoch {
            if validator.slashed {
                return Self::ExitedSlashed;
            }

            return Self::ExitedUnslashed;
        }

        if validator.withdrawable_epoch <= current_epoch {
            if validator.effective_balance == 0 {
                return Self::WithdrawalDone;
            }

            return Self::WithdrawalPossible;
        }

        Self::Active
    }

    pub fn matches(self, other: Self) -> bool {
        match self {
            Self::Active => matches!(
                other,
                Self::Active | Self::ActiveExiting | Self::ActiveOngoing | Self::ActiveSlashed,
            ),
            Self::Exited => matches!(
                other,
                Self::Exited | Self::ExitedSlashed | Self::ExitedUnslashed,
            ),
            Self::Pending => matches!(
                other,
                Self::Pending | Self::PendingInitialized | Self::PendingQueued,
            ),
            Self::Withdrawal => matches!(
                other,
                Self::Withdrawal | Self::WithdrawalDone | Self::WithdrawalPossible,
            ),
            _ => self == other,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;

    #[test_case("12", ValidatorId::ValidatorIndex(12))]
    #[test_case(
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ValidatorId::PublicKey(PublicKeyBytes::zero())
    )]
    #[test_case(
        "0x286a9f59df6017029975682ba803d67efbb9daec7a012c193025a8e6e1e8f22ff123f4562aa123f0a9ff412231231231",
        ValidatorId::PublicKey(hex!("286a9f59df6017029975682ba803d67efbb9daec7a012c193025a8e6e1e8f22ff123f4562aa123f0a9ff412231231231").into())
    )]
    fn validator_id_string_round_trip(string: &str, validator_id: ValidatorId) {
        assert_eq!(string.parse(), Ok(validator_id));
        assert_eq!(validator_id.to_string(), string);
    }

    #[test_case(ValidatorStatus::Active,        ValidatorStatus::ActiveExiting => true)]
    #[test_case(ValidatorStatus::Active,        ValidatorStatus::Active        => true)]
    #[test_case(ValidatorStatus::ActiveExiting, ValidatorStatus::ActiveExiting => true)]
    #[test_case(ValidatorStatus::ActiveExiting, ValidatorStatus::ActiveOngoing => false)]
    fn validator_status_matches(status: ValidatorStatus, other: ValidatorStatus) -> bool {
        status.matches(other)
    }

    #[test_case("active_ongoing", ValidatorStatus::ActiveOngoing)]
    fn validator_status_round_trip(string: &str, validator_status: ValidatorStatus) {
        assert_eq!(string.parse(), Ok(validator_status));
        assert_eq!(validator_status.to_string(), string);
    }
}
