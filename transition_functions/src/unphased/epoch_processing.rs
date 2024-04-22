use std::collections::HashMap;

use anyhow::Result;
use arithmetic::{NonZeroExt as _, U64Ext as _};
use helper_functions::{
    accessors::{
        absolute_epoch, get_block_root, get_current_epoch, get_next_epoch, get_randao_mix,
        get_validator_churn_limit,
    },
    misc::compute_activation_exit_epoch,
    mutators::{decrease_balance, increase_balance, initiate_validator_exit},
    phase0::is_eligible_for_activation_queue,
    predicates::{is_active_validator, is_eligible_for_activation},
};
use itertools::Itertools as _;
use ssz::{PersistentList, SszHash as _};
use types::{
    config::Config,
    nonstandard::AttestationEpoch,
    phase0::{
        consts::GENESIS_EPOCH,
        containers::{Checkpoint, HistoricalBatch},
        primitives::{Gwei, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState,
};
use unwrap_none::UnwrapNone as _;

use crate::unphased::{EpochDeltas, ValidatorSummary};

// Unlike `EpochDeltas` (and other items in `transition_functions::*::epoch_intermediates`), this is
// only used to avoid the overhead of storing penalties when doing ordinary state transitions.
pub trait SlashingPenalties: Default {
    fn add(&mut self, validator_index: ValidatorIndex, slashing_penalty: Gwei);
}

impl SlashingPenalties for () {
    fn add(&mut self, _validator_index: ValidatorIndex, _slashing_penalty: Gwei) {}
}

impl SlashingPenalties for HashMap<ValidatorIndex, Gwei> {
    fn add(&mut self, validator_index: ValidatorIndex, slashing_penalty: Gwei) {
        self.insert(validator_index, slashing_penalty).unwrap_none();
    }
}

pub fn process_rewards_and_penalties<P: Preset>(
    state: &mut impl BeaconState<P>,
    deltas: impl IntoIterator<Item = impl EpochDeltas>,
) {
    if !should_process_rewards_and_penalties(state) {
        return;
    }

    let mut deltas = deltas.into_iter();

    state.balances_mut().update(|balance| {
        let deltas = deltas
            .next()
            .expect("deltas should have as many elements as there are validators");

        increase_balance(balance, deltas.combined_reward());
        decrease_balance(balance, deltas.combined_penalty());
    });
}

pub fn process_registry_updates<P: Preset>(
    config: &Config,
    state: &mut impl BeaconState<P>,
    summaries: &mut [impl ValidatorSummary],
) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let next_epoch = get_next_epoch(state);

    // The indices collected in these do not overlap.
    // See <https://github.com/protolambda/eth2-docs/tree/de65f38857f1e27ffb6f25107d61e795cf1a5ad7#registry-updates>
    //
    // These could be computed in `epoch_intermediates::statistics`, but doing so causes a slowdown.
    let mut eligible_for_activation_queue = vec![];
    let mut ejections = vec![];
    let mut activation_queue = vec![];

    for (validator, validator_index) in state.validators().into_iter().zip(0..) {
        if is_eligible_for_activation_queue::<P>(validator) {
            eligible_for_activation_queue.push(validator_index);
        }

        if is_active_validator(validator, current_epoch)
            && validator.effective_balance <= config.ejection_balance
        {
            ejections.push(validator_index);
        }

        if is_eligible_for_activation(state, validator) {
            activation_queue.push((validator_index, validator.activation_eligibility_epoch));
        }
    }

    // > Process activation eligibility and ejections
    for validator_index in eligible_for_activation_queue {
        state
            .validators_mut()
            .get_mut(validator_index)?
            .activation_eligibility_epoch = next_epoch;
    }

    for validator_index in ejections {
        let index = usize::try_from(validator_index)?;

        initiate_validator_exit(config, state, validator_index)?;

        // `process_slashings` depends on `Validator.withdrawable_epoch`,
        // which may have been modified by `initiate_validator_exit`.
        // However, no test cases in `consensus-spec-tests` fail if this is absent.
        summaries[index].update_from(state.validators().get(validator_index)?);
    }

    // > Queue validators eligible for activation and not yet dequeued for activation
    let activation_queue = activation_queue
        .into_iter()
        .enumerate()
        .sorted_unstable_by_key(|&(position_in_queue, (_, activation_eligibility_epoch))| {
            // > Order by the sequence of activation_eligibility_epoch setting and then index
            (activation_eligibility_epoch, position_in_queue)
        })
        .map(|(_, (validator_index, _))| validator_index);

    // > Dequeued validators for activation up to churn limit
    let churn_limit = get_validator_churn_limit(config, state).try_into()?;
    let activation_exit_epoch = compute_activation_exit_epoch::<P>(current_epoch);

    for validator_index in activation_queue.into_iter().take(churn_limit) {
        state
            .validators_mut()
            .get_mut(validator_index)?
            .activation_epoch = activation_exit_epoch;
    }

    Ok(())
}

pub fn process_eth1_data_reset<P: Preset>(state: &mut impl BeaconState<P>) {
    let next_epoch = get_next_epoch(state);

    // > Reset eth1 data votes
    if next_epoch.is_multiple_of(P::EpochsPerEth1VotingPeriod::non_zero()) {
        *state.eth1_data_votes_mut() = PersistentList::default();
    }
}

pub fn process_effective_balance_updates<P: Preset>(state: &mut impl BeaconState<P>) {
    let hysteresis_increment = P::EFFECTIVE_BALANCE_INCREMENT.get() / P::HYSTERESIS_QUOTIENT;
    let downward_threshold = hysteresis_increment * P::HYSTERESIS_DOWNWARD_MULTIPLIER;
    let upward_threshold = hysteresis_increment * P::HYSTERESIS_UPWARD_MULTIPLIER;

    let (validators, balances) = state.validators_mut_with_balances();

    // These could be collected into a vector in `process_slashings`. Doing so speeds up this
    // function by around ~160 μs in Goerli, but may result in a slowdown in `process_slashings`.
    // The reason why the speedup is so small is likely because values in the balance tree are
    // packed into bundles of 8.
    let mut balances = balances.into_iter().copied();

    // > Update effective balances with hysteresis
    validators.update(|validator| {
        let balance = balances
            .next()
            .expect("list of validators and list of balances should have the same length");

        let below = balance + downward_threshold < validator.effective_balance;
        let above = validator.effective_balance + upward_threshold < balance;

        if below || above {
            validator.effective_balance = balance
                .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
                .min(P::MAX_EFFECTIVE_BALANCE);
        }
    });
}

pub fn process_slashings_reset<P: Preset>(state: &mut impl BeaconState<P>) {
    let next_epoch = get_next_epoch(state);

    // > Reset slashings
    *state.slashings_mut().mod_index_mut(next_epoch) = 0;
}

pub fn process_randao_mixes_reset<P: Preset>(state: &mut impl BeaconState<P>) {
    let current_epoch = get_current_epoch(state);
    let next_epoch = get_next_epoch(state);

    // > Set randao mix
    *state.randao_mixes_mut().mod_index_mut(next_epoch) = get_randao_mix(state, current_epoch);
}

pub fn process_historical_roots_update<P: Preset>(state: &mut impl BeaconState<P>) -> Result<()> {
    let next_epoch = get_next_epoch(state);

    // > Set historical root accumulator
    if next_epoch.is_multiple_of(P::EpochsPerHistoricalRoot::non_zero()) {
        let historical_batch = HistoricalBatch::<P> {
            block_roots: state.block_roots().clone(),
            state_roots: state.state_roots().clone(),
        };

        state
            .historical_roots_mut()
            .push(historical_batch.hash_tree_root())?;
    }

    Ok(())
}

pub fn weigh_justification_and_finalization<P: Preset>(
    state: &mut impl BeaconState<P>,
    current_epoch_active_balance: Gwei,
    previous_epoch_target_balance: Gwei,
    current_epoch_target_balance: Gwei,
) {
    let old_previous_justified_checkpoint = state.previous_justified_checkpoint();
    let old_current_justified_checkpoint = state.current_justified_checkpoint();

    // > Process justifications
    *state.previous_justified_checkpoint_mut() = state.current_justified_checkpoint();
    state.justification_bits_mut().shift_up_by_1();

    let mut justify_if_supermajority = |attestation_epoch, bit, target_balance| {
        if target_balance * 3 >= current_epoch_active_balance * 2 {
            let root = get_block_root(state, attestation_epoch).expect(
                "get_block_root can fail during the first slot of an epoch but \
                 process_justification_and_finalization is only called at the end of an epoch",
            );

            *state.current_justified_checkpoint_mut() = Checkpoint {
                epoch: absolute_epoch(state, attestation_epoch.into()),
                root,
            };

            state.justification_bits_mut().set(bit, true);
        }
    };

    justify_if_supermajority(AttestationEpoch::Previous, 1, previous_epoch_target_balance);
    justify_if_supermajority(AttestationEpoch::Current, 0, current_epoch_target_balance);

    // > Process finalizations
    let bits = state.justification_bits();
    let current_epoch = get_current_epoch(state);

    // > The 2nd/3rd/4th most recent epochs are justified, the 2nd using the 4th as source
    if bits[1..4] && old_previous_justified_checkpoint.epoch + 3 == current_epoch {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint
    }

    // > The 2nd/3rd most recent epochs are justified, the 2nd using the 3rd as source
    if bits[1..3] && old_previous_justified_checkpoint.epoch + 2 == current_epoch {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint
    }

    // > The 1st/2nd/3rd most recent epochs are justified, the 1st using the 3rd as source
    if bits[0..3] && old_current_justified_checkpoint.epoch + 2 == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }

    // > The 1st/2nd most recent epochs are justified, the 1st using the 2nd as source
    if bits[0..2] && old_current_justified_checkpoint.epoch + 1 == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }
}

pub fn should_process_justification_and_finalization<P: Preset>(
    state: &impl BeaconState<P>,
) -> bool {
    // > Initial FFG checkpoint values have a `0x00` stub for `root`.
    // > Skip FFG updates in the first two epochs to avoid
    // > corner cases that might result in modifying this stub.
    GENESIS_EPOCH + 1 < get_current_epoch(state)
}

pub fn should_process_rewards_and_penalties<P: Preset>(state: &impl BeaconState<P>) -> bool {
    // > No rewards are applied at the end of `GENESIS_EPOCH`
    // > because rewards are for work done in the previous epoch
    GENESIS_EPOCH < get_current_epoch(state)
}
