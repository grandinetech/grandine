use core::num::NonZeroU64;
use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::{
    accessors, misc,
    slot_report::{Assignment, RealSlotReport, SlotReport as _},
};
use logging::trace_with_peers;
use prometheus_metrics::Metrics;
use serde::Serialize;
use tokio::sync::RwLock;
use types::{
    combined::BeaconState,
    nonstandard::{AttestationEpoch, AttestationOutcome, RelativeEpoch, WithStatus},
    phase0::{
        consts::GENESIS_EPOCH,
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::{Attestation as _, SignedBeaconBlock as _},
};

use crate::{
    statistics::Error,
    votes::{ValidatorVotes, VoteReport},
    ValidatorVote,
};

// `AttestationPerformance::for_previous_epoch` has to process slot reports in chronological order.
//
// We previously stored slot reports in `HashMap`s. The nondeterministic iteration order revealed
// some bugs in the code we were using to construct test data when we implemented snapshot tests.
pub type SlotReports = BTreeMap<Slot, RealSlotReport>;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AttestationAssignment {
    pub slot: Slot,
    pub committee_index: CommitteeIndex,
}

#[derive(Clone, Copy, Default, Debug, Serialize)]
pub struct AttestationPerformance {
    pub source: Option<H256>,
    pub target: Option<AttestationOutcome>,
    pub head: Option<AttestationOutcome>,
    pub inclusion_delay: Option<NonZeroU64>,
}

impl AttestationPerformance {
    #[must_use]
    pub const fn matching_source(self) -> bool {
        self.source.is_some()
    }

    #[must_use]
    pub const fn matching_target(self) -> bool {
        matches!(self.target, Some(AttestationOutcome::Match { .. }))
    }

    #[must_use]
    pub const fn matching_head(self) -> bool {
        matches!(self.head, Some(AttestationOutcome::Match { .. }))
    }

    #[must_use]
    pub fn for_previous_epoch(
        validator_index: ValidatorIndex,
        previous_epoch_slot_reports: &SlotReports,
        current_epoch_slot_reports: &SlotReports,
    ) -> Self {
        let mut performance = Self::default();

        for slot_report in previous_epoch_slot_reports.values() {
            performance.accumulate(slot_report, (validator_index, AttestationEpoch::Current));
        }

        for slot_report in current_epoch_slot_reports.values() {
            performance.accumulate(slot_report, (validator_index, AttestationEpoch::Previous));
        }

        performance
    }

    fn accumulate(&mut self, slot_report: &RealSlotReport, assignment: Assignment) {
        let new_target = slot_report.targets.get(&assignment).copied();
        let new_head = slot_report.heads.get(&assignment).copied();

        if !self.matching_source() {
            self.source = slot_report.sources.get(&assignment).copied();
        }

        if AttestationOutcome::should_replace(self.target, new_target) {
            self.target = new_target;
        }

        if AttestationOutcome::should_replace(self.head, new_head) {
            self.head = new_head;
        }

        if self.inclusion_delay.is_none() {
            self.inclusion_delay = slot_report.inclusion_delays.get(&assignment).copied();
        }
    }
}

#[derive(Default)]
pub struct AttestationVotes {
    attestation_head_votes: RwLock<ValidatorVotes>,
    attestation_target_votes: RwLock<ValidatorVotes>,
}

impl AttestationVotes {
    pub async fn track_attestation_vote<P: Preset>(
        &self,
        data: AttestationData,
        epoch: Epoch,
        validator_index: ValidatorIndex,
    ) {
        let mut attestation_votes = self.attestation_head_votes.write().await;

        let head_vote = ValidatorVote {
            validator_index,
            beacon_block_root: data.beacon_block_root,
            slot: data.slot,
        };

        if !attestation_votes.insert_vote(epoch, &head_vote) {
            trace_with_peers!("attestation head vote already present: {epoch} {head_vote:?}");
        }

        let mut attestation_votes = self.attestation_target_votes.write().await;

        let target_vote = ValidatorVote {
            validator_index,
            beacon_block_root: data.target.root,
            slot: misc::compute_start_slot_at_epoch::<P>(data.target.epoch),
        };

        if !attestation_votes.insert_vote(epoch, &target_vote) {
            trace_with_peers!("attestation target vote already present: {epoch} {target_vote:?}");
        }
    }

    pub async fn prune_older_than(&self, epoch: Epoch) {
        let mut attestation_head_votes = self.attestation_head_votes.write().await;
        attestation_head_votes.prune_older_than(epoch);

        let mut attestation_target_votes = self.attestation_target_votes.write().await;
        attestation_target_votes.prune_older_than(epoch);
    }

    pub async fn track_collection_metrics(&self, metrics: &Metrics) {
        let type_name = tynm::type_name::<Self>();

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "attestation_head_votes",
            self.attestation_head_votes.read().await.len(),
        );

        metrics.set_collection_length(
            module_path!(),
            &type_name,
            "attestation_target_votes",
            self.attestation_target_votes.read().await.len(),
        );
    }

    pub async fn correct_target_votes<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        epoch: Epoch,
    ) -> Result<Option<usize>> {
        let target_votes = self.attestation_target_votes.read().await;

        let Some(validator_votes) = target_votes.get(epoch) else {
            return Ok(None);
        };

        let mut correct_votes = 0;

        let slot = misc::compute_start_slot_at_epoch::<P>(epoch);
        let state = controller.preprocessed_state_at_epoch(epoch)?;
        let expected_target = accessors::get_block_root_at_slot::<P>(&state.value(), slot)?;

        for block_votes in validator_votes.values() {
            for (voted_root, voter_indices) in block_votes {
                if *voted_root == expected_target {
                    correct_votes += voter_indices.len();
                }
            }
        }

        Ok(Some(correct_votes))
    }

    pub async fn vote_report<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        epoch: Epoch,
    ) -> Result<Option<VoteReport>> {
        self.attestation_head_votes
            .read()
            .await
            .vote_report(controller, epoch)
    }
}

pub fn attestation_performance_slot_report<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    epoch: Epoch,
    attestation_data_epoch: Epoch,
    validators_indices: &HashSet<ValidatorIndex>,
) -> Result<SlotReports> {
    let snapshot = controller.snapshot();
    let mut slot_reports = SlotReports::new();
    let blocks = snapshot.blocks_by_range(misc::slots_in_epoch::<P>(epoch))?;

    for block_with_root in blocks {
        let slot = block_with_root.block.message().slot();
        let mut slot_report = RealSlotReport::default();

        let Some(state) = snapshot.state_at_slot(slot)?.map(WithStatus::value) else {
            return Err(Error::StateNotAvailable { slot }.into());
        };

        if let Some(post_electra_block_body) = block_with_root.block.message().body().post_electra()
        {
            for block_attestation in
                post_electra_block_body
                    .attestations()
                    .iter()
                    .filter(|attestation| {
                        misc::compute_epoch_at_slot::<P>(attestation.data().slot)
                            == attestation_data_epoch
                    })
            {
                slot_report.update_performance(
                    &state,
                    block_attestation.data(),
                    helper_functions::electra::get_attesting_indices(&state, block_attestation)?
                        .intersection(validators_indices)
                        .copied(),
                )?;
            }
        }

        slot_reports.insert(slot, slot_report);
    }

    Ok(slot_reports)
}

pub fn epoch_attestation_assignments<P: Preset>(
    state: &BeaconState<P>,
) -> Result<HashMap<ValidatorIndex, AttestationAssignment>> {
    if accessors::get_current_epoch(state) == GENESIS_EPOCH {
        return Ok(HashMap::new());
    }

    let active_validator_count =
        accessors::active_validator_count_usize(state, RelativeEpoch::Current);

    let mut attestation_assignments = HashMap::with_capacity(active_validator_count);

    for slot in misc::slots_in_epoch::<P>(accessors::get_current_epoch(state)) {
        let committees = accessors::beacon_committees(state, slot)?;

        for (committee_index, committee) in (0..).zip(committees) {
            let attestation_assignment = AttestationAssignment {
                slot,
                committee_index,
            };

            attestation_assignments.extend(
                committee
                    .into_iter()
                    .zip(core::iter::repeat(attestation_assignment)),
            );
        }
    }

    Ok(attestation_assignments)
}
