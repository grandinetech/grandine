// Attestation rewards as defined by the `/eth/v1/beacon/rewards/attestations/{epoch}` endpoint.
//
// Rewards for epoch N are applied during the transition from epoch N + 1 to N + 2.
// Only the parts of epoch processing that rewards depend on are run here:
// - participation statistics,
// - justification and finalization (changes whether the chain is in an inactivity leak),
// - inactivity score updates (the inactivity penalty uses the updated scores).
// Everything else in `process_epoch` is skipped.

use core::{iter::Copied, marker::PhantomData, slice};

use anyhow::{Result, ensure};
use arithmetic::U64Ext as _;
use helper_functions::{
    accessors::{
        compute_base_reward, get_base_reward_per_increment, get_current_epoch, total_active_balance,
    },
    misc,
    predicates::is_in_inactivity_leak,
};
use itertools::izip;
use num_integer::Roots as _;
use pubkey_cache::PubkeyCache;
use types::{
    altair::consts::{
        TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
    },
    combined::BeaconState,
    config::Config,
    nonstandard::Participation,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::BASE_REWARDS_PER_EPOCH,
        primitives::{Epoch, Gwei},
    },
    preset::Preset,
    traits::{BeaconState as _, PostAltairBeaconState},
};

use crate::{
    altair::{self, EpochDeltasForReport as AltairEpochDeltasForReport, Statistics},
    bellatrix, capella, combined, deneb, electra, fulu, gloas,
    phase0::{
        self, EpochDeltasForReport as Phase0EpochDeltasForReport, Statistics as _,
        StatisticsForTransition,
    },
};

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct AttestationReward {
    pub head: i64,
    pub target: i64,
    pub source: i64,
    // Phase 0 only.
    pub inclusion_delay: Option<Gwei>,
    pub inactivity: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct ValidatorAttestationReward {
    pub effective_balance: Gwei,
    // Ineligible validators get no rewards or penalties.
    pub eligible: bool,
    pub reward: AttestationReward,
}

pub struct AttestationRewards<P: Preset> {
    validators: Vec<ValidatorAttestationReward>,
    ideal: IdealRewardParameters,
    phantom: PhantomData<P>,
}

impl<P: Preset> AttestationRewards<P> {
    // Indexed by validator index.
    #[must_use]
    pub fn validators(&self) -> &[ValidatorAttestationReward] {
        &self.validators
    }

    // The reward a validator with `effective_balance` would get for perfect participation.
    pub fn ideal_reward(&self, effective_balance: Gwei) -> Result<AttestationReward> {
        self.ideal.ideal_reward::<P>(effective_balance)
    }
}

#[derive(Clone, Copy)]
enum IdealRewardParameters {
    Phase0 {
        in_inactivity_leak: bool,
        active_balance: Gwei,
        source_balance: Gwei,
        target_balance: Gwei,
        head_balance: Gwei,
    },
    PostAltair {
        in_inactivity_leak: bool,
        base_reward_per_increment: Gwei,
        active_increments: u64,
        source_increments: u64,
        target_increments: u64,
        head_increments: u64,
    },
}

impl IdealRewardParameters {
    // These mirror the reward branches of the `epoch_deltas` functions.
    fn ideal_reward<P: Preset>(self, effective_balance: Gwei) -> Result<AttestationReward> {
        match self {
            Self::Phase0 {
                in_inactivity_leak,
                active_balance,
                source_balance,
                target_balance,
                head_balance,
            } => {
                let base_reward = effective_balance
                    .try_mul(P::BASE_REWARD_FACTOR)?
                    .try_div(active_balance.sqrt())?
                    / BASE_REWARDS_PER_EPOCH;

                let proposer_reward = base_reward / P::PROPOSER_REWARD_QUOTIENT;

                let component_reward = |attesting_balance: Gwei| -> Result<i64> {
                    let reward = if in_inactivity_leak {
                        base_reward
                    } else {
                        let increment = P::EFFECTIVE_BALANCE_INCREMENT;
                        base_reward
                            .try_mul(attesting_balance / increment)?
                            .try_div(active_balance / increment)?
                    };

                    Ok(reward.try_into()?)
                };

                // During a leak, even a perfect validator pays the canceling penalty.
                let inactivity = if in_inactivity_leak {
                    let canceling_penalty = BASE_REWARDS_PER_EPOCH
                        .get()
                        .try_mul(base_reward)?
                        .try_sub(proposer_reward)?;

                    signed(0, canceling_penalty)?
                } else {
                    0
                };

                Ok(AttestationReward {
                    head: component_reward(head_balance)?,
                    target: component_reward(target_balance)?,
                    source: component_reward(source_balance)?,
                    inclusion_delay: Some(base_reward.try_sub(proposer_reward)?),
                    inactivity,
                })
            }
            Self::PostAltair {
                in_inactivity_leak,
                base_reward_per_increment,
                active_increments,
                source_increments,
                target_increments,
                head_increments,
            } => {
                // No participation rewards during a leak.
                if in_inactivity_leak {
                    return Ok(AttestationReward::default());
                }

                let base_reward =
                    compute_base_reward::<P>(effective_balance, base_reward_per_increment)?;

                let reward_denominator = active_increments.try_mul(WEIGHT_DENOMINATOR.get())?;

                let component_reward = |weight: u64, increments: u64| -> Result<i64> {
                    Ok(base_reward
                        .try_mul(weight)?
                        .try_mul(increments)?
                        .try_div(reward_denominator)?
                        .try_into()?)
                };

                Ok(AttestationReward {
                    head: component_reward(TIMELY_HEAD_WEIGHT, head_increments)?,
                    target: component_reward(TIMELY_TARGET_WEIGHT, target_increments)?,
                    source: component_reward(TIMELY_SOURCE_WEIGHT, source_increments)?,
                    inclusion_delay: None,
                    inactivity: 0,
                })
            }
        }
    }
}

// Calculates rewards for attestations made in `epoch`.
//
// `state` must be in epoch `epoch + 1` and contain all of its blocks.
//
// Pass a scratch copy. `state` is left invalid.
// It is advanced to the last slot of the epoch.
// Justification, finalization and inactivity scores are then updated.
// Slot and balances stay from before the epoch transition.
// Transitioning it further would apply those updates twice.
pub fn attestation_rewards<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut BeaconState<P>,
    epoch: Epoch,
) -> Result<AttestationRewards<P>> {
    let rewarding_epoch = epoch.try_add(1)?;

    ensure!(
        get_current_epoch(state) == rewarding_epoch,
        "state must be in epoch {rewarding_epoch} to compute attestation rewards for epoch {epoch}",
    );

    // Empty slots at the end of the epoch do not change rewards,
    // but some accessors expect the state to be in the last slot.
    let last_slot =
        misc::compute_start_slot_at_epoch::<P>(rewarding_epoch.try_add(1)?).try_sub(1)?;

    if state.slot() < last_slot {
        combined::process_slots(config, pubkey_cache, state, last_slot)?;
    }

    match state {
        BeaconState::Phase0(state) => phase0_rewards(state),
        BeaconState::Altair(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                altair::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Bellatrix(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                bellatrix::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Capella(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                capella::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Deneb(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                deneb::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Electra(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                electra::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Fulu(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                fulu::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
        BeaconState::Gloas(state) => post_altair_rewards(
            config,
            state,
            |state, statistics, summaries, participation| {
                gloas::epoch_deltas(config, state, statistics, summaries, participation)
            },
        ),
    }
}

fn phase0_rewards<P: Preset>(state: &mut Phase0BeaconState<P>) -> Result<AttestationRewards<P>> {
    let (statistics, summaries, performance) =
        phase0::statistics_and_summaries::<P, StatisticsForTransition>(state)?;

    phase0::process_justification_and_finalization(state, statistics)?;

    let in_inactivity_leak = is_in_inactivity_leak(state)?;

    let deltas: Vec<Phase0EpochDeltasForReport> =
        phase0::epoch_deltas(state, statistics, summaries.iter().copied(), performance)?;

    let validators = izip!(summaries, deltas)
        .map(|(summary, deltas)| {
            Ok(ValidatorAttestationReward {
                effective_balance: summary.effective_balance,
                eligible: summary.eligible_for_penalties,
                reward: AttestationReward {
                    head: signed(deltas.head_reward, deltas.head_penalty)?,
                    target: signed(deltas.target_reward, deltas.target_penalty)?,
                    source: signed(deltas.source_reward, deltas.source_penalty)?,
                    inclusion_delay: Some(deltas.inclusion_delay_reward),
                    inactivity: signed(
                        0,
                        deltas
                            .canceling_penalty
                            .try_add(deltas.inactivity_penalty)?,
                    )?,
                },
            })
        })
        .collect::<Result<_>>()?;

    let ideal = IdealRewardParameters::Phase0 {
        in_inactivity_leak,
        active_balance: statistics.current_epoch_active_balance(),
        source_balance: statistics.previous_epoch_source_attesting_balance(),
        target_balance: statistics.previous_epoch_target_attesting_balance(),
        head_balance: statistics.previous_epoch_head_attesting_balance(),
    };

    Ok(AttestationRewards {
        validators,
        ideal,
        phantom: PhantomData,
    })
}

fn post_altair_rewards<P: Preset, S: PostAltairBeaconState<P>>(
    config: &Config,
    state: &mut S,
    epoch_deltas: impl FnOnce(
        &S,
        Statistics,
        Copied<slice::Iter<'_, altair::ValidatorSummary>>,
        Vec<Participation>,
    ) -> Result<Vec<AltairEpochDeltasForReport>>,
) -> Result<AttestationRewards<P>> {
    let (statistics, summaries, participation) = altair::statistics_and_summaries(state)?;

    altair::process_justification_and_finalization(state, statistics)?;

    altair::process_inactivity_updates(
        config,
        state,
        summaries.iter().copied(),
        participation.iter().copied(),
    )?;

    let in_inactivity_leak = is_in_inactivity_leak(state)?;

    let deltas = epoch_deltas(state, statistics, summaries.iter().copied(), participation)?;

    let validators = izip!(summaries, deltas)
        .map(|(summary, deltas)| {
            Ok(ValidatorAttestationReward {
                effective_balance: summary.effective_balance,
                eligible: summary.eligible_for_penalties,
                reward: AttestationReward {
                    head: signed(deltas.head_reward, 0)?,
                    target: signed(deltas.target_reward, deltas.target_penalty)?,
                    source: signed(deltas.source_reward, deltas.source_penalty)?,
                    inclusion_delay: None,
                    inactivity: signed(0, deltas.inactivity_penalty)?,
                },
            })
        })
        .collect::<Result<_>>()?;

    let increment = P::EFFECTIVE_BALANCE_INCREMENT;

    let ideal = IdealRewardParameters::PostAltair {
        in_inactivity_leak,
        base_reward_per_increment: get_base_reward_per_increment(state)?,
        active_increments: total_active_balance(state) / increment,
        source_increments: statistics.previous_epoch_source_participating_balance / increment,
        target_increments: statistics.previous_epoch_target_participating_balance / increment,
        head_increments: statistics.previous_epoch_head_participating_balance / increment,
    };

    Ok(AttestationRewards {
        validators,
        ideal,
        phantom: PhantomData,
    })
}

fn signed(reward: Gwei, penalty: Gwei) -> Result<i64> {
    let reward = i64::try_from(reward)?;
    let penalty = i64::try_from(penalty)?;

    // Both are non-negative, so this cannot saturate.
    Ok(reward.saturating_sub(penalty))
}

#[cfg(test)]
mod spec_tests {
    use std::collections::HashSet;

    use duplicate::duplicate_item;
    use helper_functions::accessors::get_previous_epoch;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        combined::SignedBeaconBlock,
        nonstandard::Phase,
        phase0::{consts::GENESIS_EPOCH, primitives::Slot},
        preset::{Mainnet, Minimal},
        traits::SignedBeaconBlock as _,
    };

    use super::*;

    // Replays each case and checks the rewards for every completed epoch against the balance
    // changes that `process_epoch` makes. This is independent of how the rewards are computed.
    #[duplicate_item(
        glob                                                            function_name                preset    phase;
        ["consensus-spec-tests/tests/mainnet/phase0/finality/*/*/*"]    [phase0_mainnet_finality]    [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/finality/*/*/*"]    [phase0_minimal_finality]    [Minimal] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/random/*/*/*"]      [phase0_minimal_random]      [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/altair/finality/*/*/*"]    [altair_mainnet_finality]    [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/finality/*/*/*"]    [altair_minimal_finality]    [Minimal] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/random/*/*/*"]      [altair_minimal_random]      [Minimal] [Altair];
        ["consensus-spec-tests/tests/minimal/bellatrix/finality/*/*/*"] [bellatrix_minimal_finality] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/random/*/*/*"]   [bellatrix_minimal_random]   [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/capella/finality/*/*/*"]   [capella_minimal_finality]   [Minimal] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/random/*/*/*"]     [capella_minimal_random]     [Minimal] [Capella];
        ["consensus-spec-tests/tests/minimal/deneb/finality/*/*/*"]     [deneb_minimal_finality]     [Minimal] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/random/*/*/*"]       [deneb_minimal_random]       [Minimal] [Deneb];
        ["consensus-spec-tests/tests/minimal/electra/finality/*/*/*"]   [electra_minimal_finality]   [Minimal] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/random/*/*/*"]     [electra_minimal_random]     [Minimal] [Electra];
        ["consensus-spec-tests/tests/minimal/fulu/finality/*/*/*"]      [fulu_minimal_finality]      [Minimal] [Fulu];
        ["consensus-spec-tests/tests/minimal/fulu/random/*/*/*"]        [fulu_minimal_random]        [Minimal] [Fulu];
        ["consensus-spec-tests/tests/minimal/gloas/finality/*/*/*"]     [gloas_minimal_finality]     [Minimal] [Gloas];
        ["consensus-spec-tests/tests/minimal/gloas/random/*/*/*"]       [gloas_minimal_random]       [Minimal] [Gloas];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let config = preset::default_config().start_and_stay_in(Phase::phase);
        run_case::<preset>(&config, case).expect("attestation rewards should match balances");
    }

    fn run_case<P: Preset>(config: &Config, case: Case) -> Result<()> {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz::<_, BeaconState<P>>(config, "pre");
        let blocks_count = case.meta().blocks_count;
        let blocks = case.numbered::<_, SignedBeaconBlock<P>>(config, "blocks", 0..blocks_count);

        for block in blocks {
            let block_slot = block.message().slot();
            check_epochs_before(config, &pubkey_cache, &mut state, block_slot)?;
            combined::trusted_state_transition(config, &pubkey_cache, &mut state, &block)?;
        }

        Ok(())
    }

    // Checks every epoch transition up to `slot`.
    // `state` is left before the last one so that a block in `slot` can still be applied.
    fn check_epochs_before<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &mut BeaconState<P>,
        slot: Slot,
    ) -> Result<()> {
        loop {
            let next_epoch_start =
                misc::compute_start_slot_at_epoch::<P>(get_current_epoch(state).try_add(1)?);

            if next_epoch_start > slot {
                return Ok(());
            }

            let last_slot = next_epoch_start.try_sub(1)?;

            if state.slot() < last_slot {
                combined::process_slots(config, pubkey_cache, state, last_slot)?;
            }

            let mut post_state = state.clone();
            combined::process_slots(config, pubkey_cache, &mut post_state, next_epoch_start)?;

            if get_current_epoch(state) > GENESIS_EPOCH {
                check_epoch(config, pubkey_cache, state, &post_state)?;
            }

            if next_epoch_start == slot {
                return Ok(());
            }

            *state = post_state;
        }
    }

    fn check_epoch<P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        pre_state: &BeaconState<P>,
        post_state: &BeaconState<P>,
    ) -> Result<()> {
        let epoch = get_previous_epoch(pre_state);
        let rewards = attestation_rewards(config, pubkey_cache, &mut pre_state.clone(), epoch)?;

        // These validators have balance changes other than attestation rewards:
        // - Phase 0 proposers get rewards for including attestations.
        // - Electra applies pending deposits and consolidations during epoch processing.
        let mut excluded = HashSet::new();

        if let BeaconState::Phase0(state) = pre_state {
            excluded.extend(
                state
                    .previous_epoch_attestations
                    .into_iter()
                    .map(|attestation| attestation.proposer_index),
            );
        }

        if let Some(state) = pre_state.post_electra() {
            let pending_pubkeys = state
                .pending_deposits()
                .into_iter()
                .map(|deposit| deposit.pubkey)
                .collect::<HashSet<_>>();

            excluded.extend(
                izip!(0.., state.validators().pubkeys())
                    .filter(|(_, pubkey)| pending_pubkeys.contains(pubkey))
                    .map(|(validator_index, _)| validator_index),
            );

            for consolidation in state.pending_consolidations() {
                excluded.insert(consolidation.source_index);
                excluded.insert(consolidation.target_index);
            }
        }

        let mut checked = false;

        for (validator_index, validator, pre_balance, post_balance, rewarded) in izip!(
            0..,
            pre_state.validators().partial_validators(),
            pre_state.balances().into_iter().copied(),
            post_state.balances().into_iter().copied(),
            rewards.validators(),
        ) {
            let ValidatorAttestationReward {
                effective_balance,
                eligible,
                reward,
            } = *rewarded;

            let ideal = rewards.ideal_reward(effective_balance)?;

            // Any component that is a reward must be the full reward for it.
            // Zero is ambiguous: a missed head vote gets no penalty after Phase 0.
            for (actual, ideal) in [
                (reward.head, ideal.head),
                (reward.target, ideal.target),
                (reward.source, ideal.source),
            ] {
                if eligible && actual > 0 {
                    assert_eq!(
                        actual, ideal,
                        "validator {validator_index} in epoch {epoch}"
                    );
                }
            }

            assert!(reward.inclusion_delay <= ideal.inclusion_delay);

            // Slashed validators get slashing penalties. Balances saturate at 0.
            if validator.slashed || excluded.contains(&validator_index) || post_balance == 0 {
                continue;
            }

            let expected = signed(post_balance, 0)?.saturating_sub(signed(pre_balance, 0)?);

            let actual = [
                reward.head,
                reward.target,
                reward.source,
                signed(reward.inclusion_delay.unwrap_or_default(), 0)?,
                reward.inactivity,
            ]
            .into_iter()
            .sum::<i64>();

            assert_eq!(
                actual, expected,
                "validator {validator_index} in epoch {epoch}"
            );

            checked = true;
        }

        assert!(checked);

        Ok(())
    }
}
