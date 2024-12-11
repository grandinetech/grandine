// TODO(Grandine Team): Optimize state transitions further.
//
//                      `altair::block_processing::apply_attestation` is slow due to calls to
//                      `PersistentList::get`. That could be optimized by implementing an iterator
//                      limited to specific indices.
//
//                      The most time-consuming parts of epoch processing in Phase 0 are
//                      (slowest to fastest):
//                      1. `phase0::epoch_intermediates::statistics`.
//                      2. `PersistentList::update` in `process_effective_balance_updates`.
//                      3. `phase0::epoch_intermediates::epoch_deltas`.
//                      4. `process_registry_updates`.
//                      5. Other calls to `PersistentList::update`.
//
//                      The most time-consuming parts of epoch processing in Altair are
//                      (slowest to fastest):
//                      1. `PersistentList::update` in `process_effective_balance_updates`.
//                      2. `altair::epoch_intermediates::statistics`.
//                      3. `altair::epoch_intermediates::epoch_deltas`.
//                      4. `PersistentList::update` in `process_rewards_and_penalties`.
//                      5. `process_registry_updates`.
//                      6. Other calls to `PersistentList::update`.
//
//                      Parallelizing iteration over `PersistentList`s with `ParallelBridge` adds
//                      enough overhead to slow it down further. An `IndexedParallelIterator` for
//                      `PersistentList` might help, but it's hard to implement.
//
//                      Using `AtomicU64` in `altair::epoch_intermediates::statistics` breaks it
//                      somehow (even with `Ordering::SeqCst`). Using Rayon in
//                      `altair::epoch_intermediates::epoch_deltas` does the same.

pub mod combined;

pub mod unphased {
    // TODO(Grandine Team): Try deduplicating even more functions by adding traits to
    //                      `helper_functions` and `transition_functions`.
    //
    //                      `epoch_intermediates` and `slot_processing`
    //                      are completely unchanged in Capella.
    //
    // TODO(Grandine Team): Try deduplicating `spec_tests` modules further.

    pub use block_processing::{
        validate_attestation, validate_attester_slashing, validate_attester_slashing_with_verifier,
        validate_proposer_slashing, validate_voluntary_exit, validate_voluntary_exit_with_verifier,
    };
    pub use epoch_intermediates::EpochDeltas;
    pub use slot_processing::{process_slot, ProcessSlots};
    pub use state_transition::StateRootPolicy;

    pub(crate) use block_processing::{
        process_block_header, process_block_header_for_gossip, process_eth1_data, process_randao,
        process_voluntary_exit, validate_attestation_with_verifier, validate_deposits,
        validate_proposer_slashing_with_verifier, CombinedDeposit,
    };
    pub(crate) use epoch_intermediates::ValidatorSummary;
    pub(crate) use epoch_processing::{
        process_effective_balance_updates, process_eth1_data_reset,
        process_historical_roots_update, process_randao_mixes_reset, process_registry_updates,
        process_rewards_and_penalties, process_slashings_reset,
        should_process_justification_and_finalization, should_process_rewards_and_penalties,
        weigh_justification_and_finalization, SlashingPenalties,
    };
    pub(crate) use error::Error;

    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod error;
    mod slot_processing;
    mod state_transition;

    #[cfg(test)]
    pub(crate) use {
        block_processing::verify_deposit_merkle_branch, epoch_intermediates::TestDeltas,
    };
}

pub mod phase0 {
    pub use epoch_intermediates::{
        EpochDeltasForReport, Performance, PerformanceForReport,
        Phase0ValidatorSummary as ValidatorSummary, Statistics, StatisticsForReport,
    };
    pub use epoch_processing::EpochReport;

    pub(crate) use block_processing::{
        count_required_signatures, process_block, process_block_for_gossip, process_deposit_data,
    };
    pub(crate) use epoch_intermediates::{statistics, StatisticsForTransition};
    pub(crate) use epoch_processing::{
        epoch_report, process_epoch, process_justification_and_finalization,
    };
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

pub mod altair {
    pub use epoch_intermediates::{
        AltairValidatorSummary as ValidatorSummary, EpochDeltasForReport, Statistics,
    };
    pub use epoch_processing::EpochReport;

    pub(crate) use block_processing::{
        apply_attestation, apply_deposits, count_required_signatures, process_block,
        process_block_for_gossip, process_deposit_data, process_sync_aggregate,
        verify_sync_aggregate_signature,
    };
    pub(crate) use epoch_intermediates::{
        statistics, AltairEpochDeltas as EpochDeltas, EpochDeltasForTransition,
    };
    pub(crate) use epoch_processing::{
        epoch_report, process_epoch, process_inactivity_updates,
        process_justification_and_finalization, process_participation_flag_updates,
        process_sync_committee_updates,
    };
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

pub(crate) mod bellatrix {
    pub use blinded_block_processing::custom_process_blinded_block;
    pub use block_processing::{
        process_attester_slashing, process_block, process_block_for_gossip,
        process_proposer_slashing,
    };
    pub use epoch_processing::{epoch_report, process_epoch, process_slashings};
    pub use slot_processing::process_slots;
    pub use state_transition::{state_transition, verify_signatures};

    mod blinded_block_processing;
    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

pub mod capella {
    pub use block_processing::{get_expected_withdrawals, validate_bls_to_execution_change};

    pub(crate) use blinded_block_processing::{
        custom_process_blinded_block, process_withdrawals_root,
    };
    pub(crate) use block_processing::{
        process_block, process_block_for_gossip, process_bls_to_execution_change,
        process_operations, process_withdrawals,
    };
    pub(crate) use epoch_processing::{epoch_report, process_epoch};
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod blinded_block_processing;
    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

// TODO(feature/deneb): Try to reuse existing functions more in `transition_functions::deneb`.
pub mod deneb {
    pub(crate) use blinded_block_processing::custom_process_blinded_block;
    pub(crate) use block_processing::{process_block, process_block_for_gossip};
    pub(crate) use epoch_processing::{epoch_report, process_epoch};
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod blinded_block_processing;
    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

pub mod electra {
    pub(crate) use blinded_block_processing::custom_process_blinded_block;
    pub use block_processing::{
        add_validator_to_registry, get_expected_withdrawals, validate_attestation_with_verifier,
        validate_voluntary_exit_with_verifier,
    };
    pub(crate) use block_processing::{
        apply_attestation, apply_deposits, process_attester_slashing, process_block,
        process_block_for_gossip, process_consolidation_request, process_deposit_data,
        process_deposit_request, process_operations, process_proposer_slashing,
        process_voluntary_exit, process_withdrawal_request, process_withdrawals,
    };
    pub(crate) use epoch_processing::{
        epoch_report, process_effective_balance_updates, process_epoch,
        process_pending_consolidations, process_pending_deposits, process_slashings,
    };
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod blinded_block_processing;
    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}

pub mod fulu {
    pub(crate) use blinded_block_processing::custom_process_blinded_block;
    pub(crate) use block_processing::{process_block, process_block_for_gossip};
    pub(crate) use epoch_processing::{epoch_report, process_epoch};
    pub(crate) use slot_processing::process_slots;
    pub(crate) use state_transition::{state_transition, verify_signatures};

    mod blinded_block_processing;
    mod block_processing;
    mod epoch_intermediates;
    mod epoch_processing;
    mod slot_processing;
    mod state_transition;
}
