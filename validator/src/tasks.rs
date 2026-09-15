use std::sync::Arc;

use block_producer::ProposerData;
use fork_choice_control::Wait;
use helper_functions::misc;
use itertools::Itertools as _;
use keymanager::ProposerConfigs;
use logging::{debug_with_peers, warn_with_peers};
use p2p::BeaconCommitteeSubscription;
use tracing::instrument;
use types::{
    config::Config as ChainConfig,
    nonstandard::{ForkInfo, Phase},
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::BeaconNodeApi as _,
    beacon_nodes::BeaconNodes,
    misc::{OwnDuties, slots_by_epoch, slots_to_compute_in_advance},
    own_beacon_committee_members::OwnBeaconCommitteeMembers,
    own_proposer_duties::OwnProposerDuties,
    own_ptc_members::OwnPTCMembers,
    own_sync_committee_members::OwnSyncCommitteeMembers,
};

pub struct UpdateBeaconCommitteeSubscriptionsTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub own_duties: Arc<OwnDuties>,
    pub proposer_configs: Arc<ProposerConfigs>,
    pub beacon_nodes: BeaconNodes<P, W>,
    pub wait_group: W,
}

impl<P: Preset, W: Wait + Sync> UpdateBeaconCommitteeSubscriptionsTask<P, W> {
    #[expect(clippy::too_many_lines)]
    #[instrument(
        skip_all,
        fields(slot = %self.beacon_nodes.head().slot()),
        name="UpdateBeaconCommitteeSubscriptionsTask::run",
    )]
    pub async fn run(self) {
        let Self {
            chain_config,
            own_duties,
            proposer_configs,
            beacon_nodes,
            wait_group,
        } = self;

        let OwnDuties {
            validator_indices: own_validator_indices,
            beacon_committee_members: own_beacon_committee_members,
            proposer_duties: own_proposer_duties,
            ptc_members: own_ptc_members,
            ..
        } = own_duties.as_ref();

        let current_slot = beacon_nodes.head().slot();
        let fork_info = beacon_nodes.head().fork_info;

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        let validator_indices = own_validator_indices.sorted();

        // Sent every slot, as a restarted beacon node no longer knows about earlier ones.
        let proposers = own_validator_indices
            .load()
            .iter()
            .filter_map(|(pubkey, validator_index)| {
                Some(ProposerData {
                    validator_index: (*validator_index)?,
                    fee_recipient: proposer_configs.configured_fee_recipient(*pubkey)?,
                })
            })
            .collect_vec();

        if let Err(error) = beacon_nodes.prepare_beacon_proposer(&proposers).await {
            warn_with_peers!("failed to prepare beacon proposers: {error:?}");
        }

        let mut subscriptions = vec![];

        let prefetch_slots = beacon_nodes.prefetch_slots(current_slot);

        for (epoch, slots) in slots_by_epoch::<P>(prefetch_slots) {
            if validator_indices.is_empty() {
                continue;
            }

            let slots = match own_beacon_committee_members
                .slots_to_compute_at_epoch(&beacon_nodes, epoch, slots, &validator_indices)
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
                debug_with_peers!("updating beacon committee subscriptions {epoch} {current_slot}");

                let fork_info = fork_info_at_epoch(&chain_config, epoch, fork_info);

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
                own_beacon_committee_members,
                own_ptc_members,
                &beacon_nodes,
                current_epoch,
                epoch,
                &validator_indices,
            )
            .await;

            prefetch_proposer_duties(
                &chain_config,
                own_beacon_committee_members,
                own_proposer_duties,
                &beacon_nodes,
                epoch,
                &validator_indices,
            )
            .await;
        }

        for slot in slots_to_compute_in_advance(current_slot) {
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

fn fork_info_at_epoch(chain_config: &ChainConfig, epoch: Epoch, current: ForkInfo) -> ForkInfo {
    // The epoch may lie in the next fork; the genesis validators root never changes.
    ForkInfo {
        fork: chain_config.fork_at_epoch(epoch),
        genesis_validators_root: current.genesis_validators_root,
    }
}

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

    // PTC duties share the attester shuffling, so they are refetched with the dependent root.
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

pub fn proposer_dependent_epoch(chain_config: &ChainConfig, epoch: Epoch) -> Epoch {
    // The Fulu proposer lookahead fixes proposers an epoch earlier than before, but it is first
    // filled as the fork epoch begins, so the fork epoch itself keeps the old dependency.
    if chain_config.phase_at_epoch(epoch.saturating_sub(1)) >= Phase::Fulu {
        epoch
    } else {
        epoch.saturating_add(1)
    }
}

async fn prefetch_proposer_duties<P: Preset, W: Wait + Sync>(
    chain_config: &ChainConfig,
    own_beacon_committee_members: &OwnBeaconCommitteeMembers,
    own_proposer_duties: &OwnProposerDuties,
    beacon_nodes: &BeaconNodes<P, W>,
    epoch: Epoch,
    validator_indices: &[ValidatorIndex],
) {
    let Some(dependent_root) = own_beacon_committee_members
        .cached_dependent_root(proposer_dependent_epoch(chain_config, epoch))
        .await
    else {
        return;
    };

    if let Err(error) = own_proposer_duties
        .init_at_epoch(beacon_nodes, epoch, dependent_root, validator_indices)
        .await
    {
        warn_with_peers!("failed to obtain proposer duties for epoch {epoch}: {error:?}");
    }
}

/// Keeps sync committee duties for the periods in flight cached ahead of the deadline.
pub struct PrefetchSyncCommitteeDutiesTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub current_slot: Slot,
    pub own_duties: Arc<OwnDuties>,
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
            own_duties,
            beacon_nodes,
            wait_group,
        } = self;

        let OwnDuties {
            validator_indices: own_validator_indices,
            sync_committee_members: own_sync_committee_members,
            ..
        } = own_duties.as_ref();

        // Sync committees only exist from Altair on.
        if chain_config.phase_at_slot::<P>(current_slot) < Phase::Altair {
            drop(wait_group);
            return;
        }

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        let validator_indices = own_validator_indices.sorted();

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
        {
            match beacon_nodes
                .subscribe_to_sync_committees(current_epoch, &subscriptions)
                .await
            {
                Ok(()) => own_sync_committee_members.mark_subscriptions_sent(current_epoch),
                Err(error) => {
                    warn_with_peers!("failed to update sync committee subscriptions: {error:?}");
                }
            }
        }

        drop(wait_group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Fulu fork epoch's proposers are computed as it begins, so they depend on the previous
    // epoch's last block like before Fulu; the lookahead moves the root back only after it.
    #[test]
    fn proposer_duties_share_the_attester_root_of_the_same_epoch_after_the_fulu_fork_epoch() {
        let config = ChainConfig::mainnet();
        let fulu = config.fulu_fork_epoch;

        assert_eq!(proposer_dependent_epoch(&config, fulu - 1), fulu);
        assert_eq!(proposer_dependent_epoch(&config, fulu), fulu + 1);
        assert_eq!(proposer_dependent_epoch(&config, fulu + 1), fulu + 1);
        assert_eq!(proposer_dependent_epoch(&config, fulu + 2), fulu + 2);
    }
}
