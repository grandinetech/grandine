use core::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};
use std::sync::Arc;

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::misc;
use itertools::Itertools as _;
use logging::{debug_with_peers, warn_with_peers};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use scc::HashMap as SccHashMap;
use std_ext::ArcExt as _;
use tracing::instrument;
use types::{
    combined::BeaconState,
    config::Config as ChainConfig,
    nonstandard::{ForkInfo, Phase},
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::BeaconNodeApi as _,
    beacon_nodes::BeaconNodes,
    misc::{
        self as own_members_misc, DutySource, SyncCommitteeMember,
        subnets_from_sync_committee_indices,
    },
    own_beacon_committee_members::OwnBeaconCommitteeMembers,
    own_ptc_members::OwnPTCMembers,
    own_validator_indices::OwnValidatorIndices,
};

pub struct UpdateBeaconCommitteeSubscriptionsTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub controller: Option<ApiController<P, W>>,
    pub source: DutySource<P>,
    pub own_beacon_committee_members: Arc<OwnBeaconCommitteeMembers>,
    pub own_ptc_members: Arc<OwnPTCMembers>,
    pub own_validator_indices: Arc<OwnValidatorIndices>,
    pub beacon_nodes: BeaconNodes<P, W>,
    pub wait_group: W,
}

impl<P: Preset, W: Wait + Sync> UpdateBeaconCommitteeSubscriptionsTask<P, W> {
    #[instrument(
        skip_all,
        fields(slot = %self.source.slot_head().slot()),
        name="UpdateBeaconCommitteeSubscriptionsTask::run",
    )]
    pub async fn run(self) {
        let Self {
            chain_config,
            controller,
            source,
            own_beacon_committee_members,
            own_ptc_members,
            own_validator_indices,
            beacon_nodes,
            wait_group,
        } = self;

        let current_slot = source.slot_head().slot();
        let fork_info = source.slot_head().fork_info;

        let mut beacon_state = match source {
            DutySource::Local { beacon_state, .. } => Some(beacon_state),
            DutySource::Remote { .. } => None,
        };

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        own_validator_indices
            .update(&beacon_nodes, current_epoch)
            .await;

        let validator_indices = own_validator_indices.get().await;

        // Sent every slot, as a restarted beacon node no longer knows about earlier ones.
        let mut subscriptions = vec![];

        let prefetch_slots = beacon_nodes.prefetch_slots(current_slot);

        for (epoch, slots) in own_members_misc::slots_by_epoch::<P>(prefetch_slots) {
            let Some(validator_index) = validator_indices.first().copied() else {
                continue;
            };

            let slots = match own_beacon_committee_members
                .slots_to_compute_at_epoch(&beacon_nodes, epoch, slots, validator_index)
                .await
            {
                Ok(slots) => slots,
                Err(error) => {
                    warn_with_peers!(
                        "unable to find dependent root for epoch: {epoch} in slot \
                         {current_slot}: {error:?}",
                    );

                    continue;
                }
            };

            // Attester duties may be cached from an earlier slot while PTC duties are not yet.
            if let Some(slots) = slots {
                // Only the built-in beacon node computes members from a state, and only it has one
                // to carry across a fork.
                if let Some(state) = &mut beacon_state
                    && let Some(controller) = &controller
                    && chain_config.phase_at_slot::<P>(current_slot)
                        != chain_config.phase_at_epoch(epoch)
                {
                    match state_at_fork_of_epoch(&chain_config, controller, epoch).await {
                        Ok(next) => *state = next,
                        Err(error) => {
                            warn_with_peers!(
                                "failed to preprocess next fork beacon state for beacon \
                                 committee subscriptions: {error:?}",
                            );
                            break;
                        }
                    }
                }

                debug_with_peers!("updating beacon committee subscriptions {epoch} {current_slot}");

                let fork_info =
                    fork_info_at_epoch(&chain_config, beacon_state.as_deref(), epoch, fork_info);

                if let Err(error) = own_beacon_committee_members
                    .init_at_slots(&beacon_nodes, fork_info, slots, &validator_indices)
                    .await
                {
                    warn_with_peers!(
                        "failed to obtain attester duties for epoch {epoch}: {error:?}"
                    );
                    continue;
                }
            }

            prefetch_ptc_duties(
                &chain_config,
                &own_beacon_committee_members,
                &own_ptc_members,
                &beacon_nodes,
                current_epoch,
                epoch,
                &validator_indices,
            )
            .await;
        }

        for slot in own_members_misc::slots_to_compute_in_advance(current_slot) {
            if let Some(members) = own_beacon_committee_members.get_at_slot::<P>(slot).await {
                subscriptions.extend(
                    members
                        .iter()
                        .copied()
                        .map(BeaconCommitteeSubscription::from),
                );
            }
        }

        if let Err(error) = beacon_nodes
            .subscribe_to_beacon_committees(current_slot, &subscriptions)
            .await
        {
            warn_with_peers!("failed to update beacon committee subscriptions: {error:?}");
        }

        drop(wait_group);
    }
}

async fn state_at_fork_of_epoch<P: Preset, W: Wait + Sync>(
    chain_config: &ChainConfig,
    controller: &ApiController<P, W>,
    epoch: Epoch,
) -> Result<Arc<BeaconState<P>>> {
    let fork_epoch = chain_config.fork_epoch(chain_config.phase_at_epoch(epoch));

    controller
        .preprocessed_state_at_epoch(fork_epoch)
        .await
        .map(|with_status| with_status.value)
}

fn fork_info_at_epoch<P: Preset>(
    chain_config: &ChainConfig,
    beacon_state: Option<&BeaconState<P>>,
    epoch: Epoch,
    current: ForkInfo<P>,
) -> ForkInfo<P> {
    match beacon_state {
        Some(state) => state.into(),
        // The epoch may lie in the next fork; the genesis validators root never changes.
        None => ForkInfo {
            fork: chain_config.fork_at_epoch(epoch),
            genesis_validators_root: current.genesis_validators_root,
            phantom: PhantomData,
        },
    }
}

// PTC duties are drawn from the same shuffling as attester duties, so they are refetched with
// them whenever the dependent root changes.
async fn prefetch_ptc_duties<P: Preset, W: Wait + Sync>(
    chain_config: &ChainConfig,
    own_beacon_committee_members: &OwnBeaconCommitteeMembers,
    own_ptc_members: &OwnPTCMembers,
    beacon_nodes: &BeaconNodes<P, W>,
    current_epoch: Epoch,
    epoch: Epoch,
    validator_indices: &[ValidatorIndex],
) {
    // No beacon node serves PTC duties from a pre-Gloas state, even for the fork epoch.
    if chain_config.phase_at_epoch(current_epoch) < Phase::Gloas {
        return;
    }

    let Some(dependent_root) = own_beacon_committee_members
        .cached_dependent_root(epoch)
        .await
    else {
        return;
    };

    if let Err(error) = own_ptc_members
        .init_at_epoch(beacon_nodes, epoch, dependent_root, validator_indices)
        .await
    {
        warn_with_peers!("failed to obtain PTC duties for epoch {epoch}: {error:?}");
    }
}

/// Keeps sync committee duties for the periods in flight cached ahead of the deadline.
pub struct PrefetchSyncCommitteeDutiesTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub current_slot: Slot,
    pub own_sync_committee_members: Arc<OwnSyncCommitteeMembers>,
    pub own_validator_indices: Arc<OwnValidatorIndices>,
    pub beacon_nodes: BeaconNodes<P, W>,
    pub wait_group: W,
}

impl<P: Preset, W: Wait + Sync> PrefetchSyncCommitteeDutiesTask<P, W> {
    #[instrument(
        skip_all,
        fields(slot = %self.current_slot),
        name = "PrefetchSyncCommitteeDutiesTask::run",
    )]
    pub async fn run(self) {
        let Self {
            chain_config,
            current_slot,
            own_sync_committee_members,
            own_validator_indices,
            beacon_nodes,
            wait_group,
        } = self;

        // Sync committees only exist from Altair on.
        if chain_config.phase_at_slot::<P>(current_slot) < Phase::Altair {
            drop(wait_group);
            return;
        }

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        own_validator_indices
            .update(&beacon_nodes, current_epoch)
            .await;

        let validator_indices = own_validator_indices.get().await;

        if validator_indices.is_empty() {
            drop(wait_group);
            return;
        }

        for period in OwnSyncCommitteeMembers::periods_to_prefetch::<P>(current_epoch) {
            if let Err(error) = own_sync_committee_members
                .init_at_period(&chain_config, &beacon_nodes, period, &validator_indices)
                .await
            {
                warn_with_peers!(
                    "failed to obtain sync committee duties for period {period}: {error:?}",
                );
            }
        }

        own_sync_committee_members.prune::<P>(current_epoch).await;

        // With a local node the subscriptions are sent from the state-based path instead.
        if !beacon_nodes.has_local_node()
            && let Some(subscriptions) = own_sync_committee_members
                .subscriptions_to_send::<P>(current_epoch)
                .await
            && let Err(error) = beacon_nodes
                .subscribe_to_sync_committees(current_epoch, &subscriptions)
                .await
        {
            warn_with_peers!("failed to update sync committee subscriptions: {error:?}");
        }

        drop(wait_group);
    }
}

/// Sync committee members of the periods in flight.
pub struct OwnSyncCommitteeMembers {
    periods: SccHashMap<u64, PeriodDuties>,
    /// The epoch subscriptions were last sent in; resent each epoch for restarted nodes.
    subscriptions_sent_at: AtomicU64,
}

/// One period's answer from one duties fetch.
struct PeriodDuties {
    /// The indices the duties were requested for; a key imported at runtime changes the set.
    requested: Arc<[ValidatorIndex]>,
    members: Arc<[SyncCommitteeMember]>,
    subscriptions: Arc<[SyncCommitteeSubscription]>,
}

impl OwnSyncCommitteeMembers {
    #[must_use]
    pub fn new() -> Self {
        Self {
            periods: SccHashMap::new(),
            subscriptions_sent_at: AtomicU64::new(u64::MAX),
        }
    }

    /// The members serving in `slot`.
    pub async fn get_at_slot<P: Preset>(&self, slot: Slot) -> Option<Arc<[SyncCommitteeMember]>> {
        let period = period_at_slot::<P>(slot);

        self.periods
            .get_async(&period)
            .await
            .map(|entry| entry.get().members.clone_arc())
    }

    /// [`Self::get_at_slot`], fetching the members when they were never prefetched.
    pub async fn get_or_init_at_slot<P: Preset, W: Wait + Sync>(
        &self,
        chain_config: &ChainConfig,
        beacon_nodes: &BeaconNodes<P, W>,
        slot: Slot,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Option<Arc<[SyncCommitteeMember]>>> {
        self.init_at_period(
            chain_config,
            beacon_nodes,
            period_at_slot::<P>(slot),
            validator_indices,
        )
        .await?;

        Ok(self.get_at_slot::<P>(slot).await)
    }

    /// Fetches the members of `period` unless they are already known.
    pub async fn init_at_period<P: Preset, W: Wait + Sync>(
        &self,
        chain_config: &ChainConfig,
        beacon_nodes: &BeaconNodes<P, W>,
        period: u64,
        validator_indices: &[ValidatorIndex],
    ) -> Result<()> {
        let cached = self
            .periods
            .get_async(&period)
            .await
            .is_some_and(|entry| *entry.get().requested == *validator_indices);

        if cached {
            return Ok(());
        }

        // A period reaching back before Altair only has committees from the fork on.
        let epoch =
            misc::start_of_sync_committee_period::<P>(period)?.max(chain_config.altair_fork_epoch);

        let duties = beacon_nodes
            .sync_committee_duties(epoch, validator_indices)
            .await?;

        let until_epoch = misc::start_of_sync_committee_period::<P>(period.saturating_add(1))?;

        let subscriptions = duties
            .iter()
            .map(|duty| SyncCommitteeSubscription {
                validator_index: duty.validator_index,
                sync_committee_indices: duty.validator_sync_committee_indices.clone(),
                until_epoch,
            })
            .collect::<Arc<[_]>>();

        let members = duties
            .into_iter()
            .map(|duty| {
                Ok(SyncCommitteeMember {
                    validator_index: duty.validator_index,
                    public_key: duty.pubkey,
                    subnets: subnets_from_sync_committee_indices::<P>(
                        duty.validator_sync_committee_indices,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .sorted_by_key(|member| member.validator_index)
            .collect::<Arc<[_]>>();

        // Cached even when empty, so the same question is not asked every slot of the period.
        self.periods
            .upsert_async(
                period,
                PeriodDuties {
                    requested: validator_indices.into(),
                    members,
                    subscriptions,
                },
            )
            .await;

        Ok(())
    }

    /// The subscriptions due at `current_epoch`, once per epoch so that a restarted or newly
    /// reachable node still learns them.
    pub async fn subscriptions_to_send<P: Preset>(
        &self,
        current_epoch: Epoch,
    ) -> Option<Vec<SyncCommitteeSubscription>> {
        if self
            .subscriptions_sent_at
            .swap(current_epoch, Ordering::Relaxed)
            == current_epoch
        {
            return None;
        }

        let current_period = misc::sync_committee_period::<P>(current_epoch);
        // The next period's subnets are joined an epoch ahead of its start.
        let next_epoch_period = misc::sync_committee_period::<P>(current_epoch.saturating_add(1));

        let mut subscriptions = vec![];

        self.periods
            .iter_async(|period, entry| {
                if *period == current_period || *period == next_epoch_period {
                    subscriptions.extend(entry.subscriptions.iter().cloned());
                }

                true
            })
            .await;

        Some(subscriptions)
    }

    /// The periods worth fetching at `current_epoch`: the one being served and the one after it.
    #[must_use]
    pub fn periods_to_prefetch<P: Preset>(current_epoch: Epoch) -> [u64; 2] {
        let current_period = misc::sync_committee_period::<P>(current_epoch);

        [current_period, current_period.saturating_add(1)]
    }

    pub async fn prune<P: Preset>(&self, current_epoch: Epoch) {
        let current_period = misc::sync_committee_period::<P>(current_epoch);

        self.periods
            .retain_async(|period, _| *period >= current_period)
            .await;
    }

    pub fn warn_about_missing_duties(slot: Slot) {
        warn_with_peers!(
            "no sync committee duties were prefetched for slot {slot}, so no sync committee \
             message will be produced; check that the beacon nodes given with --beacon-node-urls \
             are reachable",
        );
    }
}

impl Default for OwnSyncCommitteeMembers {
    fn default() -> Self {
        Self::new()
    }
}

// A message signed in `slot` is included in a block at `slot + 1` and verified against that
// block's committee.
fn period_at_slot<P: Preset>(slot: Slot) -> u64 {
    misc::sync_committee_period::<P>(misc::compute_epoch_at_slot::<P>(slot.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use types::preset::Minimal;

    use super::*;

    // `EPOCHS_PER_SYNC_COMMITTEE_PERIOD` is 8 under the minimal preset, with 8 slots per epoch.
    #[test]
    fn a_slot_maps_to_the_period_of_the_next_slots_epoch() {
        assert_eq!(period_at_slot::<Minimal>(0), 0);
        assert_eq!(period_at_slot::<Minimal>(62), 0);
        assert_eq!(period_at_slot::<Minimal>(63), 1);
        assert_eq!(period_at_slot::<Minimal>(64), 1);
    }

    #[test]
    fn prefetching_covers_the_current_period_and_the_next() {
        assert_eq!(
            OwnSyncCommitteeMembers::periods_to_prefetch::<Minimal>(0),
            [0, 1],
        );

        assert_eq!(
            OwnSyncCommitteeMembers::periods_to_prefetch::<Minimal>(8),
            [1, 2],
        );
    }
}
