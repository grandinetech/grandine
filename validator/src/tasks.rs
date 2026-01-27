use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::channel::mpsc::UnboundedSender;
use logging::{debug_with_peers, warn_with_peers};
use p2p::ToSubnetService;
use tracing::instrument;
use types::{
    combined::BeaconState, config::Config as ChainConfig, phase0::primitives::Slot, preset::Preset,
    traits::BeaconState as _,
};

use crate::own_beacon_committee_members::{BeaconCommitteeMember, OwnBeaconCommitteeMembers};

pub struct UpdateBeaconCommitteeSubscriptionsTask<P: Preset, W: Wait + Sync> {
    pub chain_config: Arc<ChainConfig>,
    pub controller: ApiController<P, W>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub own_beacon_committee_members: Arc<OwnBeaconCommitteeMembers>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
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
            subnet_service_tx,
            wait_group,
        } = self;

        let current_slot = beacon_state.slot();

        for slot in OwnBeaconCommitteeMembers::slots_to_compute_in_advance(current_slot) {
            let dependent_root = match controller
                .attestation_committee_dependent_root_for_slot(&beacon_state, slot)
            {
                Err(error) => {
                    warn_with_peers!(
                        "unable to find dependent root for slot: {slot} against state with \
                        slot: {}: {error:?}",
                        beacon_state.slot(),
                    );

                    continue;
                }
                Ok(dependent_root) => dependent_root,
            };

            if own_beacon_committee_members
                .needs_to_compute_members_at_slot(dependent_root, slot)
                .await
            {
                let phase_at_slot = chain_config.phase_at_slot::<P>(slot);

                if chain_config.phase_at_slot::<P>(current_slot) != phase_at_slot {
                    beacon_state = match controller
                        .preprocessed_state_at_epoch(chain_config.fork_epoch(phase_at_slot))
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

                debug_with_peers!("updating beacon committee subscriptions {slot} {current_slot}");

                if let Some(members) = own_beacon_committee_members
                    .get_or_init_at_slot(&beacon_state, dependent_root, slot)
                    .await
                {
                    update_beacon_committee_subscriptions(
                        current_slot,
                        &members,
                        &subnet_service_tx,
                    )
                    .await;
                }
            }
        }

        drop(wait_group);
    }
}

#[instrument(level = "debug", fields(slot = current_slot))]
pub async fn update_beacon_committee_subscriptions(
    current_slot: Slot,
    members: &[BeaconCommitteeMember],
    subnet_service_tx: &UnboundedSender<ToSubnetService>,
) {
    if members.is_empty() {
        return;
    }

    let subscriptions = members.iter().copied().map(Into::into).collect();

    let (sender, receiver) = futures::channel::oneshot::channel();

    ToSubnetService::UpdateBeaconCommitteeSubscriptions(current_slot, subscriptions, sender)
        .send(subnet_service_tx);

    if let Err(error) = receiver.await {
        warn_with_peers!("failed to update beacon committee subscriptions: {error:?}");
    }
}
