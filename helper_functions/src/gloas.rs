use anyhow::Result;
use typenum::Unsigned as _;
use types::{
    altair::consts::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    config::Config,
    nonstandard::SlashingKind,
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{Epoch, Gwei, ValidatorIndex},
    },
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::{
    accessors::{get_activation_exit_churn_limit, get_beacon_proposer_index, get_current_epoch},
    error::Error,
    misc::compute_activation_exit_epoch,
    mutators::{balance, decrease_balance, increase_balance},
    slot_report::SlotReport,
};

// TODO(gloas): remove this function
pub fn compute_exit_epoch_and_update_churn<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    exit_balance: Gwei,
) -> Epoch {
    let mut earliest_exit_epoch = state
        .earliest_exit_epoch()
        .max(compute_activation_exit_epoch::<P>(get_current_epoch(state)));

    let per_epoch_churn = get_activation_exit_churn_limit(config, state);

    // > New epoch for exits.
    let mut exit_balance_to_consume = if state.earliest_exit_epoch() < earliest_exit_epoch {
        per_epoch_churn
    } else {
        state.exit_balance_to_consume()
    };

    // > Exit doesn't fit in the current earliest epoch.
    if exit_balance > exit_balance_to_consume {
        let balance_to_process = exit_balance - exit_balance_to_consume;
        let additional_epochs = (balance_to_process - 1) / per_epoch_churn + 1;

        earliest_exit_epoch += additional_epochs;
        exit_balance_to_consume += additional_epochs * per_epoch_churn;
    }

    // > Consume the balance and update state variables.
    *state.exit_balance_to_consume_mut() = exit_balance_to_consume - exit_balance;
    *state.earliest_exit_epoch_mut() = earliest_exit_epoch;

    state.earliest_exit_epoch()
}

// TODO(gloas): remove this function
pub fn initiate_validator_exit<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    validator_index: ValidatorIndex,
) -> Result<()> {
    let validator = state.validators().get(validator_index)?;

    // > Return if validator already initiated exit
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    // > Compute exit queue epoch
    let exit_queue_epoch =
        compute_exit_epoch_and_update_churn(config, state, validator.effective_balance);

    // > Set validator exit epoch and withdrawable epoch
    let validator = state.validators_mut().get_mut(validator_index)?;

    validator.exit_epoch = exit_queue_epoch;

    validator.withdrawable_epoch = exit_queue_epoch
        .checked_add(config.min_validator_withdrawability_delay)
        .ok_or(Error::EpochOverflow)?;

    Ok(())
}

// TODO(gloas): remove this function
pub fn slash_validator<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
    kind: SlashingKind,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    initiate_validator_exit(config, state, slashed_index)?;

    let epoch = get_current_epoch(state);
    let validator = state.validators_mut().get_mut(slashed_index)?;
    let effective_balance = validator.effective_balance;
    let slashing_penalty = effective_balance / P::MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA;

    validator.slashed = true;
    validator.withdrawable_epoch = validator
        .withdrawable_epoch
        .max(epoch + P::EpochsPerSlashingsVector::U64);

    *state.slashings_mut().mod_index_mut(epoch) += effective_balance;

    decrease_balance(balance(state, slashed_index)?, slashing_penalty);

    // > Apply proposer and whistleblower rewards
    let proposer_index = get_beacon_proposer_index(config, state)?;
    let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = effective_balance / P::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA;
    let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
    let remaining_reward = whistleblower_reward - proposer_reward;

    increase_balance(balance(state, proposer_index)?, proposer_reward);
    increase_balance(balance(state, whistleblower_index)?, remaining_reward);

    slot_report.set_slashing_penalty(slashed_index, slashing_penalty);
    slot_report.add_slashing_reward(kind, proposer_reward);
    slot_report.add_whistleblowing_reward(whistleblower_index, remaining_reward);

    Ok(())
}
