use anyhow::{bail, ensure, Result};
use derive_more::From;
use enum_iterator::Sequence as _;
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use helper_functions::{
    accessors, fork, misc,
    slot_report::{NullSlotReport, RealSlotReport, SlotReport},
    verifier::{MultiVerifier, NullVerifier, Verifier, VerifierOption},
};
use prometheus_metrics::METRICS;
use static_assertions::const_assert_eq;
use thiserror::Error;
use types::{
    combined::{BeaconBlock, BeaconState, BlindedBeaconBlock, SignedBeaconBlock},
    config::Config,
    nonstandard::{Phase, Toption},
    phase0::{
        containers::DepositData,
        primitives::{Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    altair::{self, EpochReport as AltairEpochReport, Statistics as AltairStatistics},
    bellatrix, capella, deneb, electra,
    phase0::{
        self, EpochReport as Phase0EpochReport, StatisticsForReport, StatisticsForTransition,
    },
    unphased::{self, Error, ProcessSlots, StateRootPolicy},
};

#[derive(From)]
pub enum EpochReport {
    Phase0(Phase0EpochReport),
    PostAltair(AltairEpochReport),
}

#[derive(From)]
pub enum Statistics {
    Phase0(StatisticsForReport),
    Altair(AltairStatistics),
}

pub fn untrusted_state_transition<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    signed_block: &SignedBeaconBlock<P>,
) -> Result<()> {
    custom_state_transition(
        config,
        state,
        signed_block,
        ProcessSlots::Always,
        StateRootPolicy::Verify,
        NullExecutionEngine,
        MultiVerifier::default(),
        NullSlotReport,
    )
}

pub fn trusted_state_transition<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    signed_block: &SignedBeaconBlock<P>,
) -> Result<()> {
    custom_state_transition(
        config,
        state,
        signed_block,
        ProcessSlots::Always,
        StateRootPolicy::Trust,
        NullExecutionEngine,
        NullVerifier,
        NullSlotReport,
    )
}

pub fn state_transition_for_report<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    signed_block: &SignedBeaconBlock<P>,
) -> Result<RealSlotReport> {
    let mut slot_report = RealSlotReport::default();

    custom_state_transition(
        config,
        state,
        signed_block,
        ProcessSlots::IfNeeded,
        StateRootPolicy::Trust,
        NullExecutionEngine,
        NullVerifier,
        &mut slot_report,
    )?;

    Ok(slot_report)
}

#[allow(clippy::too_many_arguments)]
pub fn custom_state_transition<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &SignedBeaconBlock<P>,
    process_slots: ProcessSlots,
    state_root_policy: StateRootPolicy,
    execution_engine: impl ExecutionEngine<P> + Send,
    verifier: impl Verifier + Send,
    slot_report: impl SlotReport + Send,
) -> Result<()> {
    // > Process slots (including those with no blocks) since block
    if process_slots.should_process(state, block.message()) {
        self::process_slots(config, state, block.message().slot())?;
    }

    let process_slots = ProcessSlots::Never;

    match (state, block) {
        (BeaconState::Phase0(state), SignedBeaconBlock::Phase0(block)) => phase0::state_transition(
            config,
            state,
            block,
            process_slots,
            state_root_policy,
            verifier,
            slot_report,
        ),
        (BeaconState::Altair(state), SignedBeaconBlock::Altair(block)) => altair::state_transition(
            config,
            state,
            block,
            process_slots,
            state_root_policy,
            verifier,
            slot_report,
        ),
        (BeaconState::Bellatrix(state), SignedBeaconBlock::Bellatrix(block)) => {
            bellatrix::state_transition(
                config,
                state,
                block,
                process_slots,
                state_root_policy,
                execution_engine,
                verifier,
                slot_report,
            )
        }
        (BeaconState::Capella(state), SignedBeaconBlock::Capella(block)) => {
            capella::state_transition(
                config,
                state,
                block,
                process_slots,
                state_root_policy,
                execution_engine,
                verifier,
                slot_report,
            )
        }
        (BeaconState::Deneb(state), SignedBeaconBlock::Deneb(block)) => deneb::state_transition(
            config,
            state,
            block,
            process_slots,
            state_root_policy,
            execution_engine,
            verifier,
            slot_report,
        ),
        (BeaconState::Electra(state), SignedBeaconBlock::Electra(block)) => {
            electra::state_transition(
                config,
                state,
                block,
                process_slots,
                state_root_policy,
                execution_engine,
                verifier,
                slot_report,
            )
        }
        _ => {
            // This match arm will silently match any new phases.
            // Cause a compilation error if a new phase is added.
            const_assert_eq!(Phase::CARDINALITY, 6);

            unreachable!("successful slot processing ensures that phases match")
        }
    }
}

pub fn verify_signatures<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    block: &SignedBeaconBlock<P>,
    verifier: impl Verifier,
) -> Result<()> {
    match (state, block) {
        (BeaconState::Phase0(state), SignedBeaconBlock::Phase0(block)) => {
            phase0::verify_signatures(config, state, block, verifier)
        }
        (BeaconState::Altair(state), SignedBeaconBlock::Altair(block)) => {
            altair::verify_signatures(config, state, block, verifier)
        }
        (BeaconState::Bellatrix(state), SignedBeaconBlock::Bellatrix(block)) => {
            bellatrix::verify_signatures(config, state, block, verifier)
        }
        (BeaconState::Capella(state), SignedBeaconBlock::Capella(block)) => {
            capella::verify_signatures(config, state, block, verifier)
        }
        (BeaconState::Deneb(state), SignedBeaconBlock::Deneb(block)) => {
            deneb::verify_signatures(config, state, block, verifier)
        }
        (BeaconState::Electra(state), SignedBeaconBlock::Electra(block)) => {
            electra::verify_signatures(config, state, block, verifier)
        }
        _ => {
            // This match arm will silently match any new phases.
            // Cause a compilation error if a new phase is added.
            const_assert_eq!(Phase::CARDINALITY, 6);

            bail!(PhaseError {
                state_phase: state.phase(),
                block_phase: block.phase(),
            });
        }
    }
}

pub fn process_slots<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    slot: Slot,
) -> Result<()> {
    // This validation is not required to pass `consensus-spec-tests`.
    // `process_block_header` already prevents multiple blocks from being applied in the same slot
    // (see <https://github.com/ethereum/consensus-specs/releases/tag/v0.11.3>).
    // However, without this `process_slots` and `process_slots_internal` become idempotent.
    // As a result, transitions with preprocessed states succeed even with `ProcessSlots::Always`.
    ensure!(
        state.slot() < slot,
        Error::<P>::SlotNotLater {
            current: state.slot(),
            target: slot,
        },
    );

    let _timer = METRICS
        .get()
        .map(|metrics| metrics.process_slot_times.start_timer());

    // If multiple phases have the same fork slots,
    // the state may need to be upgraded multiple times in the same slot.
    let final_phase = config.phase_at_slot::<P>(slot);

    while state.slot() < slot || state.phase() < final_phase {
        let mut made_progress = false;

        // The cloning below could be avoided using `replace_with`,
        // but the added complexity is probably not worth it.
        match state {
            BeaconState::Phase0(phase0_state) => {
                let altair_fork_slot = config.fork_slot::<P>(Phase::Altair);

                let last_slot_in_phase = Toption::Some(slot)
                    .min(altair_fork_slot)
                    .expect("result of min should always be Some because slot is always Some");

                if phase0_state.slot < last_slot_in_phase {
                    phase0::process_slots(config, phase0_state, last_slot_in_phase)?;

                    made_progress = true;
                }

                if Toption::Some(last_slot_in_phase) == altair_fork_slot {
                    *state = fork::upgrade_to_altair(config, phase0_state.as_ref().clone())?.into();

                    made_progress = true;
                }
            }
            BeaconState::Altair(altair_state) => {
                let bellatrix_fork_slot = config.fork_slot::<P>(Phase::Bellatrix);

                let last_slot_in_phase = Toption::Some(slot)
                    .min(bellatrix_fork_slot)
                    .expect("result of min should always be Some because slot is always Some");

                if altair_state.slot < last_slot_in_phase {
                    altair::process_slots(config, altair_state, last_slot_in_phase)?;

                    made_progress = true;
                }

                if Toption::Some(last_slot_in_phase) == bellatrix_fork_slot {
                    *state =
                        fork::upgrade_to_bellatrix(config, altair_state.as_ref().clone()).into();

                    made_progress = true;
                }
            }
            BeaconState::Bellatrix(bellatrix_state) => {
                let capella_fork_slot = config.fork_slot::<P>(Phase::Capella);

                let last_slot_in_phase = Toption::Some(slot)
                    .min(capella_fork_slot)
                    .expect("result of min should always be Some because slot is always Some");

                if bellatrix_state.slot < last_slot_in_phase {
                    bellatrix::process_slots(config, bellatrix_state, last_slot_in_phase)?;

                    made_progress = true;
                }

                if Toption::Some(last_slot_in_phase) == capella_fork_slot {
                    *state =
                        fork::upgrade_to_capella(config, bellatrix_state.as_ref().clone()).into();

                    made_progress = true;
                }
            }
            BeaconState::Capella(capella_state) => {
                let deneb_fork_slot = config.fork_slot::<P>(Phase::Deneb);

                let last_slot_in_phase = Toption::Some(slot)
                    .min(deneb_fork_slot)
                    .expect("result of min should always be Some because slot is always Some");

                if capella_state.slot < last_slot_in_phase {
                    capella::process_slots(config, capella_state, last_slot_in_phase)?;

                    made_progress = true;
                }

                if Toption::Some(last_slot_in_phase) == deneb_fork_slot {
                    *state = fork::upgrade_to_deneb(config, capella_state.as_ref().clone()).into();

                    made_progress = true;
                }
            }
            BeaconState::Deneb(deneb_state) => {
                let electra_fork_slot = config.fork_slot::<P>(Phase::Electra);

                let last_slot_in_phase = Toption::Some(slot)
                    .min(electra_fork_slot)
                    .expect("result of min should always be Some because slot is always Some");

                if deneb_state.slot < last_slot_in_phase {
                    deneb::process_slots(config, deneb_state, last_slot_in_phase)?;

                    made_progress = true;
                }

                if Toption::Some(last_slot_in_phase) == electra_fork_slot {
                    *state = fork::upgrade_to_electra(config, deneb_state.as_ref().clone())?.into();

                    made_progress = true;
                }
            }
            BeaconState::Electra(electra_state) => {
                electra::process_slots(config, electra_state, slot)?;

                made_progress = true;
            }
        }

        assert!(made_progress);
    }

    Ok(())
}

// `process_justification_and_finalization` is used in the fork choice rule starting with
// `consensus-specs` version 1.3.0-rc.4.
pub fn process_justification_and_finalization(state: &mut BeaconState<impl Preset>) -> Result<()> {
    match state {
        BeaconState::Phase0(state) => {
            let (statistics, _, _) = phase0::statistics::<_, StatisticsForTransition>(state)?;
            phase0::process_justification_and_finalization(state, statistics);
        }
        BeaconState::Altair(state) => {
            let (statistics, _, _) = altair::statistics(state);
            altair::process_justification_and_finalization(state, statistics);
        }
        BeaconState::Bellatrix(state) => {
            let (statistics, _, _) = altair::statistics(state);
            altair::process_justification_and_finalization(state, statistics);
        }
        BeaconState::Capella(state) => {
            let (statistics, _, _) = altair::statistics(state);
            altair::process_justification_and_finalization(state, statistics);
        }
        BeaconState::Deneb(state) => {
            let (statistics, _, _) = altair::statistics(state);
            altair::process_justification_and_finalization(state, statistics);
        }
        BeaconState::Electra(state) => {
            let (statistics, _, _) = altair::statistics(state);
            altair::process_justification_and_finalization(state, statistics);
        }
    }

    Ok(())
}

pub fn process_epoch(config: &Config, state: &mut BeaconState<impl Preset>) -> Result<()> {
    match state {
        BeaconState::Phase0(state) => phase0::process_epoch(config, state),
        BeaconState::Altair(state) => altair::process_epoch(config, state),
        BeaconState::Bellatrix(state) => bellatrix::process_epoch(config, state),
        BeaconState::Capella(state) => capella::process_epoch(config, state),
        BeaconState::Deneb(state) => deneb::process_epoch(config, state),
        BeaconState::Electra(state) => electra::process_epoch(config, state),
    }
}

pub fn epoch_report(config: &Config, state: &mut BeaconState<impl Preset>) -> Result<EpochReport> {
    process_slots_for_epoch_report(config, state)?;

    let report = match state {
        BeaconState::Phase0(state) => phase0::epoch_report(config, state)?.into(),
        BeaconState::Altair(state) => altair::epoch_report(config, state)?.into(),
        BeaconState::Bellatrix(state) => bellatrix::epoch_report(config, state)?.into(),
        BeaconState::Capella(state) => capella::epoch_report(config, state)?.into(),
        BeaconState::Deneb(state) => deneb::epoch_report(config, state)?.into(),
        BeaconState::Electra(state) => electra::epoch_report(config, state)?.into(),
    };

    post_process_slots_for_epoch_report(config, state)?;

    Ok(report)
}

fn process_slots_for_epoch_report<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
) -> Result<()> {
    let next_epoch = accessors::get_next_epoch(state);
    let last_slot = misc::compute_start_slot_at_epoch::<P>(next_epoch) - 1;

    if state.slot() < last_slot {
        process_slots(config, state, last_slot)?;
    }

    unphased::process_slot(state);

    assert!(misc::is_epoch_start::<P>(state.slot() + 1));

    Ok(())
}

fn post_process_slots_for_epoch_report<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
) -> Result<()> {
    let post_slot = state.slot() + 1;

    // If multiple phases have the same fork slots,
    // the state may need to be upgraded multiple times in the same slot.
    let final_phase = config.phase_at_slot::<P>(post_slot);

    *state.slot_mut() = post_slot;

    while state.phase() < final_phase {
        // The cloning below could be avoided using `replace_with`,
        // but the added complexity is probably not worth it.
        match state {
            BeaconState::Phase0(phase0_state) => {
                let altair_fork_slot = config.fork_slot::<P>(Phase::Altair);

                if Toption::Some(post_slot) == altair_fork_slot {
                    *state = fork::upgrade_to_altair(config, phase0_state.as_ref().clone())?.into();
                }
            }
            BeaconState::Altair(altair_state) => {
                let bellatrix_fork_slot = config.fork_slot::<P>(Phase::Bellatrix);

                if Toption::Some(post_slot) == bellatrix_fork_slot {
                    *state =
                        fork::upgrade_to_bellatrix(config, altair_state.as_ref().clone()).into();
                }
            }
            BeaconState::Bellatrix(bellatrix_state) => {
                let capella_fork_slot = config.fork_slot::<P>(Phase::Capella);

                if Toption::Some(post_slot) == capella_fork_slot {
                    *state =
                        fork::upgrade_to_capella(config, bellatrix_state.as_ref().clone()).into();
                }
            }
            BeaconState::Capella(capella_state) => {
                let deneb_fork_slot = config.fork_slot::<P>(Phase::Deneb);

                if Toption::Some(post_slot) == deneb_fork_slot {
                    *state = fork::upgrade_to_deneb(config, capella_state.as_ref().clone()).into();
                }
            }
            BeaconState::Deneb(deneb_state) => {
                let electra_fork_slot = config.fork_slot::<P>(Phase::Electra);

                if Toption::Some(post_slot) == electra_fork_slot {
                    *state = fork::upgrade_to_electra(config, deneb_state.as_ref().clone())?.into();
                }
            }
            BeaconState::Electra(_) => {}
        }
    }

    Ok(())
}

pub fn process_untrusted_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BeaconBlock<P>,
    slot_report: impl SlotReport,
    skip_randao_verification: bool,
) -> Result<()> {
    let verifier = if skip_randao_verification {
        MultiVerifier::new([VerifierOption::SkipRandaoVerification])
    } else {
        MultiVerifier::default()
    };

    process_block(config, state, block, verifier, slot_report)
}

pub fn process_trusted_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BeaconBlock<P>,
    slot_report: impl SlotReport,
) -> Result<()> {
    process_block(config, state, block, NullVerifier, slot_report)
}

fn process_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BeaconBlock<P>,
    verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    match (state, block) {
        (BeaconState::Phase0(state), BeaconBlock::Phase0(block)) => {
            phase0::process_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Altair(state), BeaconBlock::Altair(block)) => {
            altair::process_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Bellatrix(state), BeaconBlock::Bellatrix(block)) => {
            bellatrix::process_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Capella(state), BeaconBlock::Capella(block)) => {
            capella::process_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Deneb(state), BeaconBlock::Deneb(block)) => {
            deneb::process_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Electra(state), BeaconBlock::Electra(block)) => {
            electra::process_block(config, state, block, verifier)
        }
        (state, _) => {
            // This match arm will silently match any new phases.
            // Cause a compilation error if a new phase is added.
            const_assert_eq!(Phase::CARDINALITY, 6);

            bail!(PhaseError {
                state_phase: state.phase(),
                block_phase: block.phase(),
            });
        }
    }
}

pub fn process_untrusted_blinded_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BlindedBeaconBlock<P>,
    slot_report: impl SlotReport,
    skip_randao_verification: bool,
) -> Result<()> {
    let verifier = if skip_randao_verification {
        MultiVerifier::new([VerifierOption::SkipRandaoVerification])
    } else {
        MultiVerifier::default()
    };

    process_blinded_block(config, state, block, verifier, slot_report)
}

pub fn process_trusted_blinded_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BlindedBeaconBlock<P>,
    slot_report: impl SlotReport,
) -> Result<()> {
    process_blinded_block(config, state, block, NullVerifier, slot_report)
}

fn process_blinded_block<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    block: &BlindedBeaconBlock<P>,
    verifier: impl Verifier,
    slot_report: impl SlotReport,
) -> Result<()> {
    match (state, block) {
        (BeaconState::Bellatrix(state), BlindedBeaconBlock::Bellatrix(block)) => {
            bellatrix::custom_process_blinded_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Capella(state), BlindedBeaconBlock::Capella(block)) => {
            capella::custom_process_blinded_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Deneb(state), BlindedBeaconBlock::Deneb(block)) => {
            deneb::custom_process_blinded_block(config, state, block, verifier, slot_report)
        }
        (BeaconState::Electra(state), BlindedBeaconBlock::Electra(block)) => {
            electra::custom_process_blinded_block(config, state, block, verifier, slot_report)
        }
        (state, _) => {
            // This match arm will silently match any new phases.
            // Cause a compilation error if a new phase is added.
            const_assert_eq!(Phase::CARDINALITY, 6);

            bail!(PhaseError {
                state_phase: state.phase(),
                block_phase: block.phase(),
            });
        }
    }
}

pub fn process_deposit_data(
    config: &Config,
    state: &mut BeaconState<impl Preset>,
    deposit_data: DepositData,
) -> Result<Option<ValidatorIndex>> {
    match state {
        BeaconState::Phase0(state) => phase0::process_deposit_data(config, state, deposit_data),
        BeaconState::Altair(state) => altair::process_deposit_data(config, state, deposit_data),
        BeaconState::Bellatrix(state) => {
            // The use of `altair::process_deposit_data` is intentional.
            // Bellatrix does not modify `process_deposit_data`.
            altair::process_deposit_data(config, state, deposit_data)
        }
        BeaconState::Capella(state) => {
            // The use of `altair::process_deposit_data` is intentional.
            // Capella does not modify `process_deposit_data`.
            altair::process_deposit_data(config, state, deposit_data)
        }
        BeaconState::Deneb(state) => {
            // The use of `altair::process_deposit_data` is intentional.
            // Deneb does not modify `process_deposit_data`.
            altair::process_deposit_data(config, state, deposit_data)
        }
        BeaconState::Electra(state) => electra::process_deposit_data(config, state, deposit_data),
    }
}

pub fn statistics<P: Preset>(state: &BeaconState<P>) -> Result<Statistics> {
    let statistics = match state {
        BeaconState::Phase0(state) => {
            let (statistics, _, _) = phase0::statistics::<P, StatisticsForReport>(state)?;
            statistics.into()
        }
        BeaconState::Altair(state) => {
            let (statistics, _, _) = altair::statistics(state);
            statistics.into()
        }
        BeaconState::Bellatrix(state) => {
            let (statistics, _, _) = altair::statistics(state);
            statistics.into()
        }
        BeaconState::Capella(state) => {
            let (statistics, _, _) = altair::statistics(state);
            statistics.into()
        }
        BeaconState::Deneb(state) => {
            let (statistics, _, _) = altair::statistics(state);
            statistics.into()
        }
        BeaconState::Electra(state) => {
            let (statistics, _, _) = altair::statistics(state);
            statistics.into()
        }
    };

    Ok(statistics)
}

// Slots would provide more information, but they're not the direct cause of this error.
// The purpose of this error is to reveal bugs, so phases are more appropriate.
#[derive(Debug, Error)]
#[error("state and block phases do not match (state: {state_phase}, block: {block_phase})")]
pub struct PhaseError {
    state_phase: Phase,
    block_phase: Phase,
}

#[cfg(test)]
mod spec_tests {
    use duplicate::duplicate_item;
    use helper_functions::predicates;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        preset::{Mainnet, Minimal},
        traits::BeaconBlock as _,
    };

    use super::*;

    // We do not honor `bls_setting` in the tests here because none of them customize it.

    #[duplicate_item(
        glob                                                              function_name             preset    phase;
        ["consensus-spec-tests/tests/mainnet/phase0/sanity/slots/*/*"]    [phase0_mainnet_slots]    [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/sanity/slots/*/*"]    [phase0_minimal_slots]    [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/altair/sanity/slots/*/*"]    [altair_mainnet_slots]    [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/sanity/slots/*/*"]    [altair_minimal_slots]    [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/sanity/slots/*/*"] [bellatrix_mainnet_slots] [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/sanity/slots/*/*"] [bellatrix_minimal_slots] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/capella/sanity/slots/*/*"]   [capella_mainnet_slots]   [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/sanity/slots/*/*"]   [capella_minimal_slots]   [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/deneb/sanity/slots/*/*"]     [deneb_mainnet_slots]     [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/sanity/slots/*/*"]     [deneb_minimal_slots]     [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/electra/sanity/slots/*/*"]   [electra_mainnet_slots]   [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/sanity/slots/*/*"]   [electra_minimal_slots]   [Minimal] [Electra];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let config = preset::default_config().start_and_stay_in(Phase::phase);
        run_slots_case::<preset>(&config, case);
    }

    #[duplicate_item(
        glob                                                               function_name                preset    phase;
        ["consensus-spec-tests/tests/mainnet/phase0/finality/*/*/*"]       [phase0_mainnet_finality]    [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/mainnet/phase0/random/*/*/*"]         [phase0_mainnet_random]      [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/mainnet/phase0/sanity/blocks/*/*"]    [phase0_mainnet_sanity]      [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/finality/*/*/*"]       [phase0_minimal_finality]    [Minimal] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/random/*/*/*"]         [phase0_minimal_random]      [Minimal] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/sanity/blocks/*/*"]    [phase0_minimal_sanity]      [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/altair/finality/*/*/*"]       [altair_mainnet_finality]    [Mainnet] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/random/*/*/*"]         [altair_mainnet_random]      [Mainnet] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/sanity/blocks/*/*"]    [altair_mainnet_sanity]      [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/finality/*/*/*"]       [altair_minimal_finality]    [Minimal] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/random/*/*/*"]         [altair_minimal_random]      [Minimal] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/sanity/blocks/*/*"]    [altair_minimal_sanity]      [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/finality/*/*/*"]    [bellatrix_mainnet_finality] [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/bellatrix/random/*/*/*"]      [bellatrix_mainnet_random]   [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/bellatrix/sanity/blocks/*/*"] [bellatrix_mainnet_sanity]   [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/finality/*/*/*"]    [bellatrix_minimal_finality] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/random/*/*/*"]      [bellatrix_minimal_random]   [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/sanity/blocks/*/*"] [bellatrix_minimal_sanity]   [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/capella/finality/*/*/*"]      [capella_mainnet_finality]   [Mainnet] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/random/*/*/*"]        [capella_mainnet_random]     [Mainnet] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/sanity/blocks/*/*"]   [capella_mainnet_sanity]     [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/finality/*/*/*"]      [capella_minimal_finality]   [Minimal] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/random/*/*/*"]        [capella_minimal_random]     [Minimal] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/sanity/blocks/*/*"]   [capella_minimal_sanity]     [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/deneb/finality/*/*/*"]        [deneb_mainnet_finality]     [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/random/*/*/*"]          [deneb_mainnet_random]       [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/sanity/blocks/*/*"]     [deneb_mainnet_sanity]       [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/finality/*/*/*"]        [deneb_minimal_finality]     [Minimal] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/random/*/*/*"]          [deneb_minimal_random]       [Minimal] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/sanity/blocks/*/*"]     [deneb_minimal_sanity]       [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/electra/finality/*/*/*"]      [electra_mainnet_finality]   [Mainnet] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/random/*/*/*"]        [electra_mainnet_random]     [Mainnet] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/sanity/blocks/*/*"]   [electra_mainnet_sanity]     [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/finality/*/*/*"]      [electra_minimal_finality]   [Minimal] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/random/*/*/*"]        [electra_minimal_random]     [Minimal] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/sanity/blocks/*/*"]   [electra_minimal_sanity]     [Minimal] [Electra];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let config = preset::default_config().start_and_stay_in(Phase::phase);
        run_blocks_case::<preset>(&config, case);
    }

    #[duplicate_item(
        glob                                                              function_name                  preset;
        ["consensus-spec-tests/tests/mainnet/altair/transition/*/*/*"]    [altair_mainnet_transition]    [Mainnet];
        ["consensus-spec-tests/tests/minimal/altair/transition/*/*/*"]    [altair_minimal_transition]    [Minimal];
        ["consensus-spec-tests/tests/mainnet/bellatrix/transition/*/*/*"] [bellatrix_mainnet_transition] [Mainnet];
        ["consensus-spec-tests/tests/minimal/bellatrix/transition/*/*/*"] [bellatrix_minimal_transition] [Minimal];
        ["consensus-spec-tests/tests/mainnet/capella/transition/*/*/*"]   [capella_mainnet_transition]   [Mainnet];
        ["consensus-spec-tests/tests/minimal/capella/transition/*/*/*"]   [capella_minimal_transition]   [Minimal];
        ["consensus-spec-tests/tests/mainnet/deneb/transition/*/*/*"]     [deneb_mainnet_transition]     [Mainnet];
        ["consensus-spec-tests/tests/minimal/deneb/transition/*/*/*"]     [deneb_minimal_transition]     [Minimal];
        ["consensus-spec-tests/tests/mainnet/electra/transition/*/*/*"]   [electra_mainnet_transition]   [Mainnet];
        ["consensus-spec-tests/tests/minimal/electra/transition/*/*/*"]   [electra_minimal_transition]   [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_transition_case::<preset>(case);
    }

    fn run_slots_case<P: Preset>(config: &Config, case: Case) {
        let mut state = case.ssz::<_, BeaconState<P>>(config, "pre");
        let expected_post = case.ssz(config, "post");
        let slots = case.yaml::<u64>("slots");
        let last_slot = state.slot() + slots;

        process_slots(config, &mut state, last_slot)
            .expect("every slot processing test should perform processing successfully");

        assert_eq!(state, expected_post);
    }

    fn run_blocks_case<P: Preset>(config: &Config, case: Case) {
        let pre = case.ssz::<_, BeaconState<P>>(config, "pre");
        let blocks_count = case.meta().blocks_count;
        let blocks = case.numbered(config, "blocks", 0..blocks_count);
        let post = case.try_ssz(config, "post");

        let run = || -> Result<_> {
            let mut state = pre.clone();

            for block in blocks.clone() {
                untrusted_state_transition(config, &mut state, &block)?;
            }

            Ok(state)
        };

        if let Some(expected_post_state) = post {
            let actual_post_state = run().expect("state transition should succeed");

            assert_eq!(actual_post_state, expected_post_state);

            if should_run_blinded_block_processing(&pre, blocks.clone()) {
                let mut state = pre;

                assert_still_succeeeds_with_blinded_blocks(
                    config,
                    &mut state,
                    blocks,
                    &expected_post_state,
                );
            }
        } else {
            run().expect_err("state transition should fail");
        }
    }

    fn run_transition_case<P: Preset>(case: Case) {
        let meta = case.meta();
        let blocks_count = meta.blocks_count;
        let fork_epoch = meta.fork_epoch;
        let pre_block_count = meta.fork_block.map(|index| index + 1).unwrap_or_default();

        let post_phase = meta
            .post_fork
            .parse()
            .expect("every transition test should specify post_fork in metadata");

        let config = P::default_config().upgrade_once(post_phase, fork_epoch);

        let mut state = case.ssz(&config, "pre");

        let expected_post = case.ssz::<_, BeaconState<P>>(&config, "post");

        assert_eq!(expected_post.phase(), post_phase);

        for pre_block in case.numbered(&config, "blocks", 0..pre_block_count) {
            untrusted_state_transition(&config, &mut state, &pre_block)
                .expect("every transition test should process pre-phase blocks successfully");
        }

        assert!(accessors::get_current_epoch(&state) < fork_epoch);

        for post_block in case.numbered(&config, "blocks", pre_block_count..blocks_count) {
            untrusted_state_transition(&config, &mut state, &post_block)
                .expect("every transition test should process post-phase blocks successfully");
        }

        assert_eq!(state, expected_post);
    }

    fn should_run_blinded_block_processing<P: Preset>(
        state: &BeaconState<P>,
        blocks: impl IntoIterator<Item = SignedBeaconBlock<P>>,
    ) -> bool {
        // TODO(feature/electa):
        if state.phase() == Phase::Electra {
            return false;
        }

        // Starting with `consensus-specs` v1.4.0-alpha.0, all Capella blocks must be post-Merge.
        if state.phase() >= Phase::Capella {
            return true;
        }

        let Some(post_bellatrix_state) = state.post_bellatrix() else {
            return false;
        };

        let first_block = blocks
            .into_iter()
            .next()
            .expect("test case should contain at least one block");

        let Some(post_bellatrix_body) = first_block.message().body().post_bellatrix() else {
            return false;
        };

        // Some Bellatrix test cases are pre-Merge.
        // Our blinded block processing code assumes all blinded blocks are post-Merge.
        // See `transition_functions::bellatrix::custom_process_blinded_block`.
        predicates::is_execution_enabled(post_bellatrix_state, post_bellatrix_body)
    }

    // We can only test blinded block processing with valid blocks.
    // Processing would falsely succeed with incorrect values in `SignedBeaconBlock.signature`.
    // Having official test cases for blinded block processing would be nice.
    fn assert_still_succeeeds_with_blinded_blocks<P: Preset>(
        config: &Config,
        state: &mut BeaconState<P>,
        blocks: impl IntoIterator<Item = SignedBeaconBlock<P>>,
        expected_post_state: &BeaconState<P>,
    ) {
        blocks
            .into_iter()
            .try_for_each(|block| {
                process_slots(config, state, block.message().slot())?;

                let (message, _) = block.split();

                let header = message
                    .body()
                    .post_bellatrix()
                    .expect("blocks should be post-Merge")
                    .execution_payload()
                    .to_header();

                let blinded_block = message.into_blinded(header, None)?;

                process_untrusted_blinded_block(
                    config,
                    state,
                    &blinded_block,
                    NullSlotReport,
                    false,
                )
            })
            .expect("blinded block processing should succeed");

        assert_eq!(state, expected_post_state);
    }
}
