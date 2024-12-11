#![expect(clippy::module_name_repetitions)]

use core::{
    num::{NonZeroU64, TryFromIntError},
    ops::{Add, AddAssign, Neg as _},
};
use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use enum_map::EnumMap;
use serde::Serialize;
use types::{
    nonstandard::{AttestationEpoch, AttestationOutcome, GweiVec, Outcome as _, SlashingKind},
    phase0::{
        containers::AttestationData,
        primitives::{Gwei, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::BeaconState,
};
use unwrap_none::UnwrapNone as _;

use crate::accessors;

// Unlike `EpochDeltas` (and other items in `transition_functions::*::epoch_intermediates`), this is
// only used to avoid the overhead of filling reports when doing ordinary state transitions.
//
// Methods for deltas are in the order that the deltas are applied in.
//
// Methods that don't have a `ValidatorIndex` parameter are for rewards given to the proposer.
//
// Methods whose names begin with `set_` are for deltas that are only given once per slot.
// The impl for `RealSlotReport` makes assertions about that.
pub trait SlotReport {
    fn set_slashing_penalty(&mut self, slashed_index: ValidatorIndex, penalty: Gwei);
    fn add_slashing_reward(&mut self, kind: SlashingKind, reward: Gwei);
    fn add_whistleblowing_reward(&mut self, whistleblower_index: ValidatorIndex, reward: Gwei);
    fn add_attestation_reward(&mut self, reward: Gwei);
    fn add_deposit(&mut self, validator_index: ValidatorIndex, amount: Gwei);
    fn set_sync_committee_delta(&mut self, participant_index: ValidatorIndex, delta: Delta);
    fn set_sync_aggregate_rewards(&mut self, rewards: SyncAggregateRewards);

    fn update_performance<P: Preset>(
        &mut self,
        state: &impl BeaconState<P>,
        data: AttestationData,
        attesting_indices: impl IntoIterator<Item = ValidatorIndex>,
    ) -> Result<()>;
}

impl<D: SlotReport> SlotReport for &mut D {
    #[inline]
    fn set_slashing_penalty(&mut self, slashed_index: ValidatorIndex, penalty: Gwei) {
        (*self).set_slashing_penalty(slashed_index, penalty);
    }

    #[inline]
    fn add_slashing_reward(&mut self, kind: SlashingKind, reward: Gwei) {
        (*self).add_slashing_reward(kind, reward);
    }

    #[inline]
    fn add_whistleblowing_reward(&mut self, whistleblower_index: ValidatorIndex, reward: Gwei) {
        (*self).add_whistleblowing_reward(whistleblower_index, reward);
    }

    #[inline]
    fn add_attestation_reward(&mut self, reward: Gwei) {
        (*self).add_attestation_reward(reward);
    }

    #[inline]
    fn add_deposit(&mut self, validator_index: ValidatorIndex, amount: Gwei) {
        (*self).add_deposit(validator_index, amount);
    }

    #[inline]
    fn set_sync_committee_delta(&mut self, participant_index: ValidatorIndex, delta: Delta) {
        (*self).set_sync_committee_delta(participant_index, delta);
    }

    #[inline]
    fn set_sync_aggregate_rewards(&mut self, rewards: SyncAggregateRewards) {
        (*self).set_sync_aggregate_rewards(rewards);
    }

    #[inline]
    fn update_performance<P: Preset>(
        &mut self,
        state: &impl BeaconState<P>,
        data: AttestationData,
        attesting_indices: impl IntoIterator<Item = ValidatorIndex>,
    ) -> Result<()> {
        (*self).update_performance(state, data, attesting_indices)
    }
}

pub struct NullSlotReport;

impl SlotReport for NullSlotReport {
    #[inline]
    fn set_slashing_penalty(&mut self, _slashed_index: ValidatorIndex, _value: Gwei) {}

    #[inline]
    fn add_slashing_reward(&mut self, _kind: SlashingKind, _value: Gwei) {}

    #[inline]
    fn add_whistleblowing_reward(&mut self, _whistleblower_index: ValidatorIndex, _value: Gwei) {}

    #[inline]
    fn add_attestation_reward(&mut self, _value: Gwei) {}

    #[inline]
    fn add_deposit(&mut self, _validator_index: ValidatorIndex, _value: Gwei) {}

    #[inline]
    fn set_sync_committee_delta(&mut self, _participant_index: ValidatorIndex, _delta: Delta) {}

    #[inline]
    fn set_sync_aggregate_rewards(&mut self, _rewards: SyncAggregateRewards) {}

    #[inline]
    fn update_performance<P: Preset>(
        &mut self,
        _state: &impl BeaconState<P>,
        _data: AttestationData,
        _attesting_indices: impl IntoIterator<Item = ValidatorIndex>,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct RealSlotReport {
    pub slashing_penalties: HashMap<ValidatorIndex, Gwei>,
    pub slashing_rewards: EnumMap<SlashingKind, GweiVec>,
    pub whistleblowing_rewards: HashMap<ValidatorIndex, GweiVec>,
    pub attestation_rewards: GweiVec,
    pub deposits: HashMap<ValidatorIndex, GweiVec>,
    pub sync_committee_deltas: BTreeMap<ValidatorIndex, Delta>,
    pub sync_aggregate_rewards: Option<SyncAggregateRewards>,

    pub sources: HashMap<Assignment, H256>,
    pub targets: HashMap<Assignment, AttestationOutcome>,
    pub heads: HashMap<Assignment, AttestationOutcome>,
    pub inclusion_delays: HashMap<Assignment, NonZeroU64>,
}

impl SlotReport for RealSlotReport {
    #[inline]
    fn set_slashing_penalty(&mut self, slashed_index: ValidatorIndex, penalty: Gwei) {
        self.slashing_penalties
            .insert(slashed_index, penalty)
            .unwrap_none();
    }

    #[inline]
    fn add_slashing_reward(&mut self, kind: SlashingKind, reward: Gwei) {
        self.slashing_rewards[kind].push(reward)
    }

    #[inline]
    fn add_whistleblowing_reward(&mut self, whistleblower_index: ValidatorIndex, reward: Gwei) {
        self.whistleblowing_rewards
            .entry(whistleblower_index)
            .or_default()
            .push(reward);
    }

    #[inline]
    fn add_attestation_reward(&mut self, reward: Gwei) {
        self.attestation_rewards.push(reward);
    }

    #[inline]
    fn add_deposit(&mut self, validator_index: ValidatorIndex, amount: Gwei) {
        self.deposits
            .entry(validator_index)
            .or_default()
            .push(amount);
    }

    #[inline]
    fn set_sync_committee_delta(&mut self, participant_index: ValidatorIndex, delta: Delta) {
        self.sync_committee_deltas
            .entry(participant_index)
            .and_modify(|existing| *existing += delta)
            .or_insert(delta);
    }

    #[inline]
    fn set_sync_aggregate_rewards(&mut self, rewards: SyncAggregateRewards) {
        self.sync_aggregate_rewards.replace(rewards).unwrap_none();
    }

    fn update_performance<P: Preset>(
        &mut self,
        state: &impl BeaconState<P>,
        data: AttestationData,
        attesting_indices: impl IntoIterator<Item = ValidatorIndex>,
    ) -> Result<()> {
        let attestation_epoch = accessors::attestation_epoch(state, data.target.epoch)?;

        let expected_target = accessors::get_block_root(state, attestation_epoch)?;
        let expected_head = accessors::get_block_root_at_slot(state, data.slot)?;

        let actual_source = data.source.root;
        let actual_target = data.target.root;
        let actual_head = data.beacon_block_root;

        let target_outcome = AttestationOutcome::compare(actual_target, expected_target);
        let head_outcome = AttestationOutcome::compare(actual_head, expected_head);

        let inclusion_delay = (state.slot() - data.slot)
            .try_into()
            .expect("MIN_ATTESTATION_INCLUSION_DELAY is at least 1 in all presets");

        for validator_index in attesting_indices {
            let assignment = (validator_index, attestation_epoch);

            self.sources.insert(assignment, actual_source);

            let current_target_outcome = self.targets.entry(assignment).or_insert(target_outcome);
            let current_head_outcome = self.heads.entry(assignment).or_insert(head_outcome);

            if !current_target_outcome.is_match() {
                *current_target_outcome = target_outcome;
            }

            if !current_head_outcome.is_match() {
                *current_head_outcome = head_outcome;
            }

            // There is no need to check if the new inclusion delay is lower because attestations by
            // the same validator for the same epoch in the same block cannot have different delays.
            self.inclusion_delays.insert(assignment, inclusion_delay);
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Delta {
    Reward(Gwei),
    Penalty(Gwei),
}

impl TryFrom<Delta> for i64 {
    type Error = TryFromIntError;

    fn try_from(delta: Delta) -> Result<Self, Self::Error> {
        match delta {
            Delta::Reward(reward) => reward.try_into(),
            Delta::Penalty(penalty) => penalty.try_into().map(Self::neg),
        }
    }
}

impl Delta {
    #[inline]
    #[must_use]
    pub const fn reward(self) -> Option<Gwei> {
        match self {
            Self::Reward(reward) => Some(reward),
            Self::Penalty(_) => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn penalty(self) -> Option<Gwei> {
        match self {
            Self::Reward(_) => None,
            Self::Penalty(penalty) => Some(penalty),
        }
    }
}

impl Add for Delta {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Self::Penalty(penalty), Self::Penalty(other)) => {
                Self::Penalty(penalty.saturating_add(other))
            }
            (Self::Penalty(penalty), Self::Reward(reward))
            | (Self::Reward(reward), Self::Penalty(penalty)) => {
                if penalty > reward {
                    Self::Penalty(penalty - reward)
                } else {
                    Self::Reward(reward - penalty)
                }
            }
            (Self::Reward(reward), Self::Reward(other)) => {
                Self::Reward(reward.saturating_add(other))
            }
        }
    }
}

impl AddAssign for Delta {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SyncAggregateRewards {
    pub singular_reward: Gwei,
    pub participation: u64,
}

impl SyncAggregateRewards {
    #[inline]
    #[must_use]
    pub const fn total(self) -> Gwei {
        self.singular_reward * self.participation
    }
}

pub type Assignment = (ValidatorIndex, AttestationEpoch);

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(Delta::Reward(2), Delta::Reward(3) => Delta::Reward(5))]
    #[test_case(Delta::Reward(2), Delta::Penalty(3) => Delta::Penalty(1))]
    #[test_case(Delta::Penalty(2), Delta::Reward(3) => Delta::Reward(1))]
    #[test_case(Delta::Penalty(2), Delta::Penalty(3) => Delta::Penalty(5))]
    #[test_case(Delta::Reward(2), Delta::Penalty(2) => Delta::Reward(0))]
    #[test_case(Delta::Reward(Gwei::MAX), Delta::Reward(2) => Delta::Reward(Gwei::MAX))]
    fn test_addition_of_deltas(first: Delta, second: Delta) -> Delta {
        first + second
    }
}
