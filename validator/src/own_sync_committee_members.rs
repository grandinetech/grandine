use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use fork_choice_control::Wait;
use helper_functions::misc;
use itertools::Itertools as _;
use logging::warn_with_peers;
use p2p::SyncCommitteeSubscription;
use scc::HashMap as SccHashMap;
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    config::Config as ChainConfig,
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::BeaconNodeApi as _,
    beacon_nodes::BeaconNodes,
    misc::{
        SyncCommitteeMember, subnets_from_sync_committee_indices, sync_subnet_subscription_epoch,
    },
};

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
    /// Each with the epoch it is due at, drawn when the period was cached.
    subscriptions: Arc<[(Epoch, SyncCommitteeSubscription)]>,
}

impl OwnSyncCommitteeMembers {
    #[must_use]
    pub fn new() -> Self {
        Self {
            periods: SccHashMap::new(),
            subscriptions_sent_at: AtomicU64::new(u64::MAX),
        }
    }

    pub async fn get_at_slot<P: Preset>(&self, slot: Slot) -> Option<Arc<[SyncCommitteeMember]>> {
        let period = period_at_slot::<P>(slot);

        self.periods
            .get_async(&period)
            .await
            .map(|entry| entry.get().members.clone_arc())
    }

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

        let period_start = misc::start_of_sync_committee_period::<P>(period)?;
        let until_epoch = misc::start_of_sync_committee_period::<P>(period.saturating_add(1))?;

        // Scoped because the generator is not `Send`, and the cache update below awaits.
        let subscriptions = {
            let mut rng = rand::thread_rng();

            duties
                .iter()
                .map(|duty| {
                    let subscription = SyncCommitteeSubscription {
                        validator_index: duty.validator_index,
                        sync_committee_indices: duty.validator_sync_committee_indices.clone(),
                        until_epoch,
                    };

                    (
                        sync_subnet_subscription_epoch(period_start, &mut rng),
                        subscription,
                    )
                })
                .collect::<Arc<[_]>>()
        };

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

    pub async fn subscriptions_to_send<P: Preset>(
        &self,
        current_epoch: Epoch,
    ) -> Option<Vec<SyncCommitteeSubscription>> {
        // Sent every epoch, so that a restarted or newly reachable node still learns them.
        if self.subscriptions_sent_at.load(Ordering::Relaxed) == current_epoch {
            return None;
        }

        let current_period = misc::sync_committee_period::<P>(current_epoch);
        let next_period = current_period.saturating_add(1);
        // The earliest draw is `SYNC_COMMITTEE_SUBNET_COUNT` epochs before the period.
        let next_period_may_be_due = misc::sync_committee_period::<P>(
            current_epoch.saturating_add(SyncCommitteeSubnetCount::U64),
        ) == next_period;

        let mut subscriptions = vec![];
        let mut found_current = false;
        let mut found_next = false;

        self.periods
            .iter_async(|period, entry| {
                found_current |= *period == current_period;
                found_next |= *period == next_period;

                subscriptions.extend(
                    entry
                        .subscriptions
                        .iter()
                        .filter(|(due_epoch, _)| *due_epoch <= current_epoch)
                        .map(|(_, subscription)| subscription.clone()),
                );

                true
            })
            .await;

        // A period whose fetch failed is not marked sent, so the next slot retries it.
        let complete = found_current && (found_next || !next_period_may_be_due);

        (complete && !subscriptions.is_empty()).then_some(subscriptions)
    }

    pub fn mark_subscriptions_sent(&self, current_epoch: Epoch) {
        self.subscriptions_sent_at
            .store(current_epoch, Ordering::Relaxed);
    }

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

fn period_at_slot<P: Preset>(slot: Slot) -> u64 {
    // A message signed in `slot` is verified against the committee of the block at `slot + 1`.
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

    fn subscription(
        validator_index: ValidatorIndex,
        until_epoch: Epoch,
    ) -> SyncCommitteeSubscription {
        SyncCommitteeSubscription {
            validator_index,
            sync_committee_indices: vec![0],
            until_epoch,
        }
    }

    async fn cache_period(
        members: &OwnSyncCommitteeMembers,
        period: u64,
        subscriptions: impl IntoIterator<Item = (Epoch, SyncCommitteeSubscription)>,
    ) {
        let inserted = members
            .periods
            .insert_async(
                period,
                PeriodDuties {
                    requested: Arc::from([0]),
                    members: Arc::from([]),
                    subscriptions: subscriptions.into_iter().collect(),
                },
            )
            .await;

        assert!(inserted.is_ok());
    }

    // Within `SYNC_COMMITTEE_SUBNET_COUNT` epochs of the next period some of its subscriptions may
    // be due, so an answer without that period cached is not marked as sent.
    #[tokio::test]
    async fn subscriptions_are_not_sent_while_the_next_period_is_missing() {
        let members = OwnSyncCommitteeMembers::new();

        cache_period(&members, 0, [(0, subscription(0, 8))]).await;

        // A period is 8 epochs and the subnet count 4 under the minimal preset.
        assert!(members.subscriptions_to_send::<Minimal>(3).await.is_some());
        assert!(members.subscriptions_to_send::<Minimal>(4).await.is_none());
        assert!(members.subscriptions_to_send::<Minimal>(7).await.is_none());
    }

    // A subscription is held back until the epoch drawn for it.
    #[tokio::test]
    async fn a_subscription_is_sent_from_its_drawn_epoch() {
        let members = OwnSyncCommitteeMembers::new();

        cache_period(&members, 0, [(0, subscription(0, 8))]).await;
        cache_period(&members, 1, [(6, subscription(1, 16))]).await;

        let members = &members;

        let indices = |epoch| async move {
            members
                .subscriptions_to_send::<Minimal>(epoch)
                .await
                .into_iter()
                .flatten()
                .map(|subscription| subscription.validator_index)
                .sorted()
                .collect::<Vec<_>>()
        };

        assert_eq!(indices(5).await, [0]);
        assert_eq!(indices(6).await, [0, 1]);
    }
}
