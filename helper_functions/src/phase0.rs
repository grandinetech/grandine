use anyhow::{ensure, Result};
use ssz::{BitList, ContiguousList};
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    config::Config,
    nonstandard::SlashingKind,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::FAR_FUTURE_EPOCH,
        containers::{Attestation, AttestationData, IndexedAttestation, Validator},
        primitives::ValidatorIndex,
    },
    preset::Preset,
    traits::BeaconState,
};

use crate::{
    accessors::{beacon_committee, get_beacon_proposer_index, get_current_epoch},
    error::Error,
    mutators::{balance, decrease_balance, increase_balance, initiate_validator_exit},
    slot_report::SlotReport,
};

pub fn get_indexed_attestation<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<IndexedAttestation<P>> {
    let attesting_indices_iter =
        get_attesting_indices(state, attestation.data, &attestation.aggregation_bits)?;

    let mut attesting_indices = ContiguousList::try_from_iter(attesting_indices_iter).expect(
        "Attestation.aggregation_bits and IndexedAttestation.attesting_indices \
         have the same maximum length",
    );

    // Sorting a slice is faster than building a `BTreeMap`.
    attesting_indices.sort_unstable();

    Ok(IndexedAttestation {
        attesting_indices,
        data: attestation.data,
        signature: attestation.signature,
    })
}

pub fn get_attesting_indices<'all, P: Preset>(
    state: &'all impl BeaconState<P>,
    attestation_data: AttestationData,
    aggregation_bits: &'all BitList<P::MaxValidatorsPerCommittee>,
) -> Result<impl Iterator<Item = ValidatorIndex> + 'all> {
    let committee = beacon_committee(state, attestation_data.slot, attestation_data.index)?;

    ensure!(
        committee.len() == aggregation_bits.len(),
        Error::CommitteeLengthMismatch {
            aggregation_bitlist_length: aggregation_bits.len(),
            committee_length: committee.len(),
        },
    );

    // `Itertools::zip_eq` is slower than `Iterator::zip` when iterating over packed indices.
    // That may be due to the internal traits `core::iter::Zip` implements.
    // `bitvec::slice::BitSlice::iter_ones` with `Iterator::filter_map` is even slower.
    aggregation_bits
        .iter()
        .by_vals()
        .zip(committee)
        .filter_map(|(present, validator_index)| present.then_some(validator_index))
        .pipe(Ok)
}

// > Check if ``validator`` is eligible to be placed into the activation queue.
#[must_use]
pub const fn is_eligible_for_activation_queue<P: Preset>(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance == P::MAX_EFFECTIVE_BALANCE
}

pub fn slash_validator<P: Preset>(
    config: &Config,
    state: &mut Phase0BeaconState<P>,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
    kind: SlashingKind,
    mut slot_report: impl SlotReport,
) -> Result<()> {
    initiate_validator_exit(config, state, slashed_index)?;

    let epoch = get_current_epoch(state);
    let validator = state.validators.get_mut(slashed_index)?;
    let effective_balance = validator.effective_balance;
    let slashing_penalty = effective_balance / P::MIN_SLASHING_PENALTY_QUOTIENT;

    validator.slashed = true;
    validator.withdrawable_epoch = validator
        .withdrawable_epoch
        .max(epoch + P::EpochsPerSlashingsVector::U64);

    *state.slashings.mod_index_mut(epoch) += effective_balance;

    decrease_balance(balance(state, slashed_index)?, slashing_penalty);

    // > Apply proposer and whistleblower rewards
    let proposer_index = get_beacon_proposer_index(config, state)?;
    let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = effective_balance / P::WHISTLEBLOWER_REWARD_QUOTIENT;
    let proposer_reward = whistleblower_reward / P::PROPOSER_REWARD_QUOTIENT;
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

        let mut state = Phase0BeaconState::<Mainnet> {
            slot: <Mainnet as Preset>::SlotsPerEpoch::U64 * 3,
            validators: [validator].try_into()?,
            balances: [Mainnet::MAX_EFFECTIVE_BALANCE].try_into()?,
            ..Phase0BeaconState::default()
        };

        let mut slot_report = RealSlotReport::default();

        slash_validator(
            &Config::mainnet(),
            &mut state,
            0,
            None,
            SlashingKind::Proposer,
            &mut slot_report,
        )?;

        let validator = state.validators.get(0)?;

        assert_eq!(validator.exit_epoch, 3 + 1 + 4);
        assert_eq!(validator.withdrawable_epoch, 3 + 8192);
        assert_eq!(
            slot_report,
            RealSlotReport {
                slashing_rewards: enum_map! {
                    SlashingKind::Proposer => smallvec![7_812_500],
                    SlashingKind::Attester => smallvec![],
                },
                slashing_penalties: HashMap::from([(0, 250_000_000)]),
                whistleblowing_rewards: HashMap::from([(0, smallvec![54_687_500])]),
                ..RealSlotReport::default()
            },
        );

        Ok(())
    }
}
