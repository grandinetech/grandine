use anyhow::Result;
use typenum::Unsigned as _;
use types::{
    altair::consts::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    config::Config,
    nonstandard::SlashingKind,
    phase0::primitives::ValidatorIndex,
    preset::Preset,
    traits::PostBellatrixBeaconState,
};

use crate::{
    accessors::{get_beacon_proposer_index, get_current_epoch},
    mutators::{balance, decrease_balance, increase_balance, initiate_validator_exit},
    slot_report::SlotReport,
};

pub fn slash_validator<P: Preset>(
    config: &Config,
    state: &mut impl PostBellatrixBeaconState<P>,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
    kind: SlashingKind,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    initiate_validator_exit(config, state, slashed_index)?;

    let epoch = get_current_epoch(state);
    let validator = state.validators_mut().get_mut(slashed_index)?;
    let effective_balance = validator.effective_balance;
    let slashing_penalty = effective_balance / P::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX;

    validator.slashed = true;
    validator.withdrawable_epoch = validator
        .withdrawable_epoch
        .max(epoch + P::EpochsPerSlashingsVector::U64);

    *state.slashings_mut().mod_index_mut(epoch) += effective_balance;

    decrease_balance(balance(state, slashed_index)?, slashing_penalty);

    // > Apply proposer and whistleblower rewards
    let proposer_index = get_beacon_proposer_index(state)?;
    let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = effective_balance / P::WHISTLEBLOWER_REWARD_QUOTIENT;
    let proposer_reward = whistleblower_reward * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR;
    let remaining_reward = whistleblower_reward - proposer_reward;

    increase_balance(balance(state, proposer_index)?, proposer_reward);
    increase_balance(balance(state, whistleblower_index)?, remaining_reward);

    slot_report.set_slashing_penalty(slashed_index, slashing_penalty);
    slot_report.add_slashing_reward(kind, proposer_reward);
    slot_report.add_whistleblowing_reward(whistleblower_index, remaining_reward);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use enum_map::enum_map;
    use types::{
        bellatrix::beacon_state::BeaconState as BellatrixBeaconState,
        nonstandard::smallvec,
        phase0::{consts::FAR_FUTURE_EPOCH, containers::Validator},
        preset::Mainnet,
    };

    use crate::slot_report::RealSlotReport;

    use super::*;

    #[test]
    fn test_slash_validator() -> Result<()> {
        let validator = Validator {
            effective_balance: Mainnet::MAX_EFFECTIVE_BALANCE,
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        };

        let mut state = BellatrixBeaconState::<Mainnet> {
            slot: <Mainnet as Preset>::SlotsPerEpoch::U64 * 3,
            validators: [validator].try_into()?,
            balances: [Mainnet::MAX_EFFECTIVE_BALANCE].try_into()?,
            ..BellatrixBeaconState::default()
        };

        let mut slot_report = RealSlotReport::default();

        slash_validator(
            &Config::mainnet(),
            &mut state,
            0,
            None,
            SlashingKind::Attester,
            &mut slot_report,
        )?;

        let validator = state.validators.get(0)?;

        assert_eq!(validator.exit_epoch, 3 + 1 + 4);
        assert_eq!(validator.withdrawable_epoch, 3 + 8192);
        assert_eq!(
            slot_report,
            RealSlotReport {
                slashing_rewards: enum_map! {
                    SlashingKind::Proposer => smallvec![],
                    SlashingKind::Attester => smallvec![7_812_500],
                },
                slashing_penalties: HashMap::from([(0, 1_000_000_000)]),
                whistleblowing_rewards: HashMap::from([(0, smallvec![54_687_500])]),
                ..RealSlotReport::default()
            },
        );

        Ok(())
    }
}
