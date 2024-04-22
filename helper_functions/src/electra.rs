use std::collections::HashSet;

use anyhow::{ensure, Result};
use ssz::ContiguousList;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::consts::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR},
    config::Config,
    electra::containers::{Attestation, IndexedAttestation},
    nonstandard::SlashingKind,
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::Validator,
        primitives::{Epoch, Gwei, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconState, PostElectraBeaconState},
};

use crate::{
    accessors::{beacon_committee, get_beacon_proposer_index, get_current_epoch},
    error::Error,
    misc::{get_committee_indices, get_validator_max_effective_balance},
    mutators::{balance, compute_exit_epoch_and_update_churn, decrease_balance, increase_balance},
    predicates::has_execution_withdrawal_credential,
    slot_report::SlotReport,
};

// > Check if ``validator`` is eligible to be placed into the activation queue.
#[must_use]
pub const fn is_eligible_for_activation_queue<P: Preset>(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance >= P::MIN_ACTIVATION_BALANCE
}

// > Check if ``validator`` is fully withdrawable.
#[must_use]
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_execution_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

// > Check if ``validator`` is partially withdrawable.
#[must_use]
pub fn is_partially_withdrawable_validator<P: Preset>(
    validator: &Validator,
    balance: Gwei,
) -> bool {
    let max_effective_balance = get_validator_max_effective_balance::<P>(validator);
    let has_max_effective_balance = validator.effective_balance == max_effective_balance;
    let has_excess_balance = balance > max_effective_balance;

    has_execution_withdrawal_credential(validator)
        && has_max_effective_balance
        && has_excess_balance
}

pub fn get_indexed_attestation<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<IndexedAttestation<P>> {
    let attesting_indices = get_attesting_indices(state, attestation)?;

    let mut attesting_indices = ContiguousList::try_from_iter(attesting_indices).expect(
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

// > Return the set of attesting indices corresponding to ``aggregation_bits`` and ``committee_bits``.
#[must_use]
pub fn get_attesting_indices<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<HashSet<ValidatorIndex>> {
    let mut output = HashSet::new();
    let committee_indices = get_committee_indices::<P>(attestation.committee_bits);
    let mut committee_offset = 0;

    for index in committee_indices {
        let committee = beacon_committee(state, attestation.data.slot, index)?;

        let committee_attesters = committee.into_iter().enumerate().filter_map(|(i, index)| {
            (*attestation.aggregation_bits.get(committee_offset + i)?).then_some(index)
        });

        output.extend(committee_attesters);

        committee_offset += committee.len();
    }

    // This works the same as `assert len(attestation.aggregation_bits) == participants_count`
    ensure!(
        committee_offset == attestation.aggregation_bits.len(),
        Error::ParticipantsCountMismatch,
    );

    Ok(output)
}

// > Initiate the exit of the validator with index ``index``.
pub fn initiate_validator_exit<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
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

// > Slash the validator with index ``slashed_index``.
pub fn slash_validator<P: Preset>(
    config: &Config,
    state: &mut impl PostElectraBeaconState<P>,
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
    let proposer_index = get_beacon_proposer_index(state)?;
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
