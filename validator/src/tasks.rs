use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::Wait;
use logging::{debug_with_peers, warn_with_peers};
use p2p::BeaconCommitteeSubscription;
use tracing::instrument;
use types::{
    combined::BeaconState, config::Config as ChainConfig, preset::Preset, traits::BeaconState as _,
};

use crate::{
    beacon_node_api::BeaconNodeApi as _, beacon_nodes::BeaconNodes, misc as own_members_misc,
    own_beacon_committee_members::OwnBeaconCommitteeMembers,
};

pub struct UpdateBeaconCommitteeSubscriptionsTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub controller: ApiController<P, W>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub own_beacon_committee_members: Arc<OwnBeaconCommitteeMembers>,
    pub beacon_nodes: BeaconNodes<P, W>,
    pub wait_group: W,
}

impl<P: Preset, W: Wait + Sync> UpdateBeaconCommitteeSubscriptionsTask<P, W> {
    #[instrument(
        skip_all,
        fields(slot = %self.beacon_state.slot()),
        name="UpdateBeaconCommitteeSubscriptionsTask::run",
    )]
    pub async fn run(self) {
        let Self {
            chain_config,
            controller,
            mut beacon_state,
            own_beacon_committee_members,
            beacon_nodes,
            wait_group,
        } = self;

        let current_slot = beacon_state.slot();

        // Sent every slot, as a restarted beacon node no longer knows about earlier ones.
        let mut subscriptions = vec![];

        let prefetch_slots = beacon_nodes.prefetch_slots(current_slot);

        for (epoch, slots) in own_members_misc::slots_by_epoch::<P>(prefetch_slots) {
            let validator_indices =
                own_beacon_committee_members.own_validator_indices(&beacon_state);

            let Some(validator_index) = validator_indices.first().copied() else {
                continue;
            };

            let slots = match own_beacon_committee_members
                .slots_to_compute_at_epoch(&beacon_nodes, epoch, slots, validator_index)
                .await
            {
                Ok(Some(slots)) => slots,
                Ok(None) => continue,
                Err(error) => {
                    warn_with_peers!(
                        "unable to find dependent root for epoch: {epoch} against state with \
                        slot: {}: {error:?}",
                        beacon_state.slot(),
                    );

                    continue;
                }
            };

            let phase_at_epoch = chain_config.phase_at_epoch(epoch);

            if chain_config.phase_at_slot::<P>(current_slot) != phase_at_epoch {
                beacon_state = match controller
                    .preprocessed_state_at_epoch(chain_config.fork_epoch(phase_at_epoch))
                    .await
                {
                    Ok(with_status) => with_status.value,
                    Err(error) => {
                        warn_with_peers!(
                            "failed to preprocess next fork beacon state for beacon committee \
                            subscriptions: {error:?}",
                        );
                        break;
                    }
                }
            }

            debug_with_peers!("updating beacon committee subscriptions {epoch} {current_slot}");

            if let Err(error) = own_beacon_committee_members
                .init_at_slots(&beacon_nodes, &beacon_state, slots, &validator_indices)
                .await
            {
                warn_with_peers!("failed to obtain attester duties for epoch {epoch}: {error:?}");
            }
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
