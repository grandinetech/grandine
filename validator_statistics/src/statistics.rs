use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::misc;
use log::{log, trace, Level};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use num_traits::identities::Zero as _;
use prometheus_metrics::Metrics;
use thiserror::Error;
use tokio::sync::RwLock;
use typenum::Unsigned as _;
use types::{
    nonstandard::WithStatus,
    phase0::{
        containers::AttestationData,
        primitives::{Epoch, Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    attestations::{
        attestation_performance_slot_report, epoch_attestation_assignments, AttestationPerformance,
        AttestationVotes,
    },
    sync_committees,
    votes::{self, ValidatorVote, ValidatorVotes, VoteReport},
};

pub struct ValidatorStatistics {
    tracking_start_epoch: AtomicU64,
    registered_validators: RwLock<HashSet<ValidatorIndex>>,
    attestation_votes: AttestationVotes,
    sync_committee_votes: RwLock<ValidatorVotes>,
    metrics: Option<Arc<Metrics>>,
}

impl ValidatorStatistics {
    #[must_use]
    pub fn new(metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            tracking_start_epoch: AtomicU64::new(u64::MAX),
            registered_validators: RwLock::default(),
            attestation_votes: AttestationVotes::default(),
            sync_committee_votes: RwLock::default(),
            metrics,
        }
    }

    pub async fn prune(&self, current_epoch: Epoch) {
        let previous_epoch = misc::previous_epoch(current_epoch);
        let epoch_before_previous = misc::previous_epoch(previous_epoch);

        // attestation valid inclusion range is two epochs
        self.attestation_votes
            .prune_older_than(epoch_before_previous)
            .await;

        let mut sync_committee_votes = self.sync_committee_votes.write().await;
        sync_committee_votes.prune_older_than(previous_epoch);
    }

    pub async fn set_registered_validator_indices(
        &self,
        validator_indices: HashSet<ValidatorIndex>,
    ) {
        debug_with_peers!(
            "setting registered validator indices: {}",
            validator_indices.len()
        );

        let mut registered_validators = self.registered_validators.write().await;
        *registered_validators = validator_indices;
    }

    pub fn set_tracking_start(&self, epoch: Epoch) {
        debug_with_peers!("setting tracking start at: {epoch}");
        self.tracking_start_epoch.store(epoch, Ordering::Relaxed);
    }

    pub async fn is_registered_validator(
        &self,
        _epoch: Epoch,
        validator_index: ValidatorIndex,
    ) -> bool {
        self.registered_validators
            .read()
            .await
            .contains(&validator_index)
    }

    pub async fn track_attestation_vote<P: Preset>(
        &self,
        data: AttestationData,
        validator_index: ValidatorIndex,
    ) {
        let epoch = misc::compute_epoch_at_slot::<P>(data.slot);

        if self.is_registered_validator(epoch, validator_index).await {
            self.attestation_votes
                .track_attestation_vote::<P>(data, epoch, validator_index)
                .await;
        }
    }

    pub async fn track_sync_committee_vote(&self, epoch: Epoch, vote: ValidatorVote) {
        if self
            .is_registered_validator(epoch, vote.validator_index)
            .await
        {
            let mut sync_committee_votes = self.sync_committee_votes.write().await;

            if !sync_committee_votes.insert_vote(epoch, &vote) {
                trace!("sync committee vote already present: {epoch} {vote:?}");
            }
        }
    }

    pub async fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "registered_validators",
                self.registered_validators.read().await.len(),
            );

            self.attestation_votes
                .track_collection_metrics(metrics)
                .await;

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "sync_committee_votes",
                self.sync_committee_votes.read().await.len(),
            );
        }
    }

    pub async fn report_validator_performance<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        current_epoch: Epoch,
    ) {
        debug_with_peers!("reporting validator performance for current epoch: {current_epoch}");

        let registered_validators = self.registered_validators.read().await;

        if registered_validators.is_empty() {
            debug_with_peers!(
                "no registered validators for validator performance report for \
                current epoch: {current_epoch}"
            );

            return;
        }

        if let Err(error) = self
            .report_attestation_performance(controller, current_epoch, &registered_validators)
            .await
        {
            warn_with_peers!("unable to report validator attestation performance: {error}");
        }

        if let Err(error) = self
            .report_sync_committee_performance(controller, current_epoch, &registered_validators)
            .await
        {
            warn_with_peers!("unable to report validator sync committee performance: {error}");
        }
    }

    async fn report_attestation_performance<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        current_epoch: Epoch,
        registered_validators: &HashSet<ValidatorIndex>,
    ) -> Result<()> {
        let previous_epoch = misc::previous_epoch(current_epoch);
        let epoch_before_previous = misc::previous_epoch(previous_epoch);

        debug_with_peers!("reporting attestation performance for epoch: {epoch_before_previous}");

        let Some(VoteReport {
            vote_summaries,
            canonical_votes: correct_head,
            total_votes,
        }) = self
            .attestation_votes
            .vote_report(controller, epoch_before_previous)
            .await?
        else {
            let level = if self.tracking_start_epoch() < epoch_before_previous {
                Level::Warn
            } else {
                Level::Debug
            };

            log!(
                level,
                "no validator attestations reported in epoch {epoch_before_previous}"
            );

            return Ok(());
        };

        let correct_target = self
            .attestation_votes
            .correct_target_votes(controller, epoch_before_previous)
            .await?
            .unwrap_or_default();

        tokio::task::block_in_place(|| {
            let mut expected = 0;
            let mut included = 0;
            let mut inclusion_delays = InclusionDelays::default();

            let snapshot = controller.snapshot();
            let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch_before_previous);

            let Some(state) = snapshot.state_at_slot(start_slot)?.map(WithStatus::value) else {
                return Err(Error::StateNotAvailable { slot: start_slot }.into());
            };

            let epoch_before_previous_assignments = epoch_attestation_assignments(&state)?;

            let epoch_before_previous_slot_reports = attestation_performance_slot_report(
                controller,
                epoch_before_previous,
                epoch_before_previous,
                registered_validators,
            )?;

            let previous_epoch_slot_reports = attestation_performance_slot_report(
                controller,
                previous_epoch,
                epoch_before_previous,
                registered_validators,
            )?;

            for validator_index in registered_validators {
                if epoch_before_previous_assignments.contains_key(validator_index) {
                    expected += 1;

                    let performance = AttestationPerformance::for_previous_epoch(
                        *validator_index,
                        &epoch_before_previous_slot_reports,
                        &previous_epoch_slot_reports,
                    );

                    if let Some(inclusion_delay) = performance.inclusion_delay {
                        included += 1;
                        inclusion_delays.insert(inclusion_delay);
                    } else {
                        trace!(
                            "{validator_index} attestation from \
                            {epoch_before_previous} epoch not included"
                        );
                    }
                }
            }

            info_with_peers!(
                "attestation performance for epoch: {epoch_before_previous}, \
                expected: {expected}, produced: {total_votes}, \
                correct target: {correct_target} ({}), correct head: {correct_head} ({}), \
                included: {included} ({}), inclusion delays: {inclusion_delays}",
                Rate::new(correct_target as u64, total_votes as u64),
                Rate::new(correct_head as u64, total_votes as u64),
                Rate::new(included, total_votes as u64),
            );

            votes::report_attestation_votes(vote_summaries);

            Ok(())
        })
    }

    async fn report_sync_committee_performance<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        current_epoch: Epoch,
        registered_validators: &HashSet<ValidatorIndex>,
    ) -> Result<()> {
        let previous_epoch = misc::previous_epoch(current_epoch);

        debug_with_peers!("reporting sync committee performance for epoch: {previous_epoch}");

        let start_slot = misc::compute_start_slot_at_epoch::<P>(previous_epoch);
        let snapshot = controller.snapshot();
        let sync_committee_votes = self.sync_committee_votes.read().await;

        tokio::task::block_in_place(|| {
            let Some(state) = snapshot.state_at_slot(start_slot)?.map(WithStatus::value) else {
                return Err(Error::StateNotAvailable { slot: start_slot }.into());
            };

            if state.post_altair().is_none() {
                return Ok(());
            }

            let mut expected = 0;
            let mut included = 0;

            let mut sync_committee_assignments =
                sync_committees::current_epoch_sync_committee_assignments(&state);

            let registered_validators_in_sync_committees = sync_committee_assignments
                .keys()
                .copied()
                .collect::<HashSet<_>>()
                .intersection(registered_validators)
                .count();

            if registered_validators_in_sync_committees.is_zero() {
                info_with_peers!(
                    "no sync committee members for epoch {previous_epoch} with {} registered validators",
                    registered_validators.len()
                );

                return Ok(());
            }

            let Some(VoteReport {
                vote_summaries,
                canonical_votes,
                total_votes,
            }) = sync_committee_votes.vote_report(controller, previous_epoch)?
            else {
                let level = if self.tracking_start_epoch() < previous_epoch {
                    Level::Warn
                } else {
                    Level::Debug
                };

                log!(
                    level,
                    "no validator sync committee messages reported in epoch {previous_epoch} with \
                    {registered_validators_in_sync_committees} registered validators in \
                    sync committees"
                );

                return Ok(());
            };

            let mut sync_aggregates_with_roots = HashMap::with_capacity(P::SlotsPerEpoch::USIZE);

            for block_with_root in
                snapshot.blocks_by_range(misc::slots_in_epoch::<P>(previous_epoch))?
            {
                let slot = block_with_root.block.message().slot();

                if let Some(pair) =
                    sync_committees::sync_aggregate_with_root(&block_with_root.block)
                {
                    sync_aggregates_with_roots.insert(slot, pair);
                }
            }

            for validator_index in registered_validators {
                let sync_committee_assignment = sync_committee_assignments.remove(validator_index);

                if let Some(assignment) = sync_committee_assignment.as_ref() {
                    expected += assignment.positions.len() * P::SlotsPerEpoch::USIZE;
                }

                let sync_committee_performance = sync_committees::sync_committee_performance(
                    sync_committee_assignment.as_ref(),
                    &sync_aggregates_with_roots,
                );

                for (_, performance) in sync_committee_performance {
                    included += performance
                        .positions
                        .values()
                        .filter(|value| **value)
                        .count();
                }
            }

            info_with_peers!(
                "sync committee message performance for epoch: {previous_epoch}, expected: {expected}, \
                produced: {total_votes}, correct: {canonical_votes}, included: {included} ({})",
                Rate::new(included as u64, total_votes as u64)
            );

            votes::report_sync_committee_votes(vote_summaries);

            Ok(())
        })
    }

    fn tracking_start_epoch(&self) -> Epoch {
        self.tracking_start_epoch.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("state not found for slot: {slot}")]
    StateNotAvailable { slot: Slot },
}

#[derive(Default)]
struct InclusionDelays {
    inclusion_delays: BTreeMap<NonZeroU64, NonZeroU64>,
}

impl InclusionDelays {
    fn insert(&mut self, inclusion_delay: NonZeroU64) {
        self.inclusion_delays
            .entry(inclusion_delay)
            .and_modify(|count| *count = count.checked_add(1).unwrap_or(NonZeroU64::MAX))
            .or_insert(NonZeroU64::MIN);
    }
}

impl Display for InclusionDelays {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let total = self
            .inclusion_delays
            .values()
            .map(|value| value.get())
            .sum::<u64>();

        if total.is_zero() {
            write!(formatter, "()")?;
            return Ok(());
        }

        let mut peekable = self.inclusion_delays.iter().peekable();

        while let Some((inclusion_delay, count)) = peekable.next() {
            let rate = Rate::new(count.get(), total);

            write!(formatter, "{inclusion_delay}: {count} ({rate})")?;

            if peekable.peek().is_some() {
                write!(formatter, ", ")?;
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct Rate {
    whole: u64,
    decimal: u64,
}

impl Rate {
    fn new(count: u64, total: u64) -> Self {
        if total == 0 {
            return Self::default();
        }

        // Scale to preserve 1 decimal place: e.g., 95.6% becomes 956
        let scaled = (count * 1000 + total / 2) / total;
        let whole = scaled / 10;
        let decimal = scaled % 10;

        Self { whole, decimal }
    }
}

impl Display for Rate {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        let Self { whole, decimal } = self;

        if decimal.is_zero() {
            write!(formatter, "{whole}%")?;
        } else {
            write!(formatter, "{whole}.{decimal}%")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Rate;

    #[test]
    fn test_rate_accuracy() {
        assert_eq!(Rate::new(478, 500).to_string(), "95.6%");
        assert_eq!(Rate::new(477, 500).to_string(), "95.4%");
        assert_eq!(Rate::new(0, 500).to_string(), "0%");
        assert_eq!(Rate::new(500, 0).to_string(), "0%");
        assert_eq!(Rate::new(1, 2).to_string(), "50%");
        assert_eq!(Rate::new(2, 3).to_string(), "66.7%");
        assert_eq!(Rate::new(3, 100).to_string(), "3%");
    }
}
