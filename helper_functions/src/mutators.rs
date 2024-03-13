use core::cmp::Ordering;

use anyhow::Result;
use types::{
    config::Config,
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{Gwei, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState,
};

use crate::{
    accessors::{get_current_epoch, get_validator_churn_limit},
    error::Error,
    misc::compute_activation_exit_epoch,
};

pub fn balance<P: Preset>(
    state: &mut impl BeaconState<P>,
    validator_index: ValidatorIndex,
) -> Result<&mut Gwei> {
    state
        .balances_mut()
        .get_mut(validator_index)
        .map_err(Into::into)
}

#[inline]
pub fn increase_balance(balance: &mut Gwei, delta: Gwei) {
    *balance += delta;
}

#[inline]
pub fn decrease_balance(balance: &mut Gwei, delta: Gwei) {
    *balance = balance.saturating_sub(delta);
}

pub fn clamp_balance<P: Preset>(balance: &mut Gwei) {
    *balance = P::EFFECTIVE_BALANCE_INCREMENT.get().max(*balance);
}

pub fn initiate_validator_exit<P: Preset>(
    config: &Config,
    state: &mut impl BeaconState<P>,
    validator_index: ValidatorIndex,
) -> Result<()> {
    // > Return if validator already initiated exit
    if state.validators().get(validator_index)?.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    // > Compute exit queue epoch
    //
    // Possible optimization: cache `exit_queue_epoch` and `exit_queue_churn`.
    // `exit_queue_epoch` must not fall behind `compute_activation_exit_epoch`.
    // We had implemented this, but the implementation did not update `exit_queue_epoch` correctly,
    // which led to state transitions failing when syncing Goerli. We were able to find the bug, but
    // the optimization didn't have much of an effect anyway, so we reverted it as a precaution.
    let mut exit_queue_epoch = compute_activation_exit_epoch::<P>(get_current_epoch(state));
    let mut exit_queue_churn = 0;

    for validator in state.validators() {
        let exit_epoch = validator.exit_epoch;

        if exit_epoch == FAR_FUTURE_EPOCH {
            continue;
        }

        match exit_epoch.cmp(&exit_queue_epoch) {
            Ordering::Less => {}
            Ordering::Equal => exit_queue_churn += 1,
            Ordering::Greater => {
                exit_queue_epoch = exit_epoch;
                exit_queue_churn = 1;
            }
        }
    }

    if exit_queue_churn >= get_validator_churn_limit(config, state) {
        exit_queue_epoch += 1;
    }

    // > Set validator exit epoch and withdrawable epoch
    let validator = state.validators_mut().get_mut(validator_index)?;

    validator.exit_epoch = exit_queue_epoch;

    validator.withdrawable_epoch = exit_queue_epoch
        .checked_add(config.min_validator_withdrawability_delay)
        .ok_or(Error::EpochOverflow)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use types::{
        phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Validator},
        preset::Minimal,
    };

    use super::*;

    #[test]
    fn test_validator_exit_init() -> Result<()> {
        let config = Config::minimal();

        let validator_1 = Validator {
            effective_balance: 24,
            activation_eligibility_epoch: 2,
            activation_epoch: 3,
            exit_epoch: 4,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        };

        let validator_2 = Validator {
            effective_balance: 24,
            activation_eligibility_epoch: 2,
            activation_epoch: 3,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        };

        let mut state = Phase0BeaconState::<Minimal> {
            validators: [validator_1, validator_2].try_into()?,
            ..Phase0BeaconState::default()
        };

        // `exit_epoch` is already set and should remain the same.
        initiate_validator_exit(&config, &mut state, 0)?;

        // `exit_epoch` is `FAR_FUTURE_EPOCH` and should be set to the lowest possible value.
        initiate_validator_exit(&config, &mut state, 1)?;

        assert_eq!(state.validators.get(0)?.exit_epoch, 4);
        assert_eq!(state.validators.get(1)?.exit_epoch, 5);

        Ok(())
    }

    #[test]
    fn test_increase_balance() {
        let mut balance = 5;

        increase_balance(&mut balance, 10);

        assert_eq!(balance, 15);
    }

    #[test]
    fn test_decrease_balance() {
        let mut low_balance = 5;
        let mut high_balance = 10;

        decrease_balance(&mut low_balance, 10);
        decrease_balance(&mut high_balance, 5);

        assert_eq!(low_balance, 0);
        assert_eq!(high_balance, 5);
    }
}
