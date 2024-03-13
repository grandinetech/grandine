use std::sync::Arc;

use anyhow::Result;
use bls::PublicKeyBytes;
use fork_choice_control::{SubnetMessage, Wait};
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    select,
    stream::StreamExt as _,
};
use helper_functions::misc;
use log::{debug, warn};
use operation_pools::AttestationAggPool;
use types::{
    phase0::primitives::{Epoch, NodeId, Slot},
    preset::Preset,
};

use crate::{
    attestation_subnets::AttestationSubnets,
    beacon_committee_subscriptions::BeaconCommitteeSubscriptions,
    messages::{SubnetServiceToP2p, ToSubnetService},
    misc::{BeaconCommitteeSubscription, SyncCommitteeSubscription},
    sync_committee_subnets::SyncCommitteeSubnets,
};

pub struct SubnetService<P: Preset, W: Wait> {
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    attestation_subnets: AttestationSubnets<P>,
    sync_committee_subnets: SyncCommitteeSubnets<P>,
    beacon_committee_subscriptions: BeaconCommitteeSubscriptions,
    p2p_tx: UnboundedSender<SubnetServiceToP2p>,
    fork_choice_rx: UnboundedReceiver<SubnetMessage<W>>,
    rx: UnboundedReceiver<ToSubnetService>,
}

impl<P: Preset, W: Wait> SubnetService<P, W> {
    #[must_use]
    pub fn new(
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        node_id: NodeId,
        p2p_tx: UnboundedSender<SubnetServiceToP2p>,
        fork_choice_rx: UnboundedReceiver<SubnetMessage<W>>,
        rx: UnboundedReceiver<ToSubnetService>,
    ) -> Self {
        Self {
            attestation_agg_pool,
            attestation_subnets: AttestationSubnets::new(node_id),
            sync_committee_subnets: SyncCommitteeSubnets::default(),
            beacon_committee_subscriptions: BeaconCommitteeSubscriptions::default(),
            p2p_tx,
            fork_choice_rx,
            rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            select! {
                message = self.fork_choice_rx.select_next_some() => {
                    self.handle_fork_choice_message(message)
                }
                message = self.rx.select_next_some() => self.handle_other_message(message),
                complete => break Ok(()),
            }
        }
    }

    fn handle_fork_choice_message(&mut self, message: SubnetMessage<W>) {
        match message {
            SubnetMessage::Slot(wait_group, slot) => {
                if let Err(error) = self.on_slot(slot) {
                    warn!("failed to advance slot in subnet service: {error}");
                }

                // `wait_group` must not be dropped before the message is handled.
                // Values ignored with `_` or `..` in `match` arms are dropped after the `match`
                // expression, so using `wait_group` explicitly is unnecessary.
                // We do it anyway because temporary scope rules are confusing.
                drop(wait_group);
            }
        }
    }

    fn handle_other_message(&mut self, message: ToSubnetService) {
        match message {
            ToSubnetService::SetRegisteredValidators(pubkeys) => {
                self.set_registered_validators(pubkeys);
            }
            ToSubnetService::UpdateBeaconCommitteeSubscriptions(
                current_slot,
                subscriptions,
                receiver,
            ) => {
                let result =
                    self.update_beacon_committee_subscriptions(current_slot, subscriptions);

                if receiver.send(result).is_err() {
                    debug!("failed to send response because the receiver was dropped");
                }
            }
            ToSubnetService::UpdateSyncCommitteeSubscriptions(current_epoch, subscriptions) => {
                self.update_sync_committee_subscriptions(current_epoch, subscriptions);
            }
        }
    }

    fn on_slot(&mut self, slot: Slot) -> Result<()> {
        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);

        self.beacon_committee_subscriptions
            .discard_old_subscriptions(current_epoch);

        let actions = self.attestation_subnets.on_slot(
            self.attestation_agg_pool.config(),
            slot,
            self.beacon_committee_subscriptions.all(),
        )?;

        if !actions.is_empty() {
            SubnetServiceToP2p::UpdateAttestationSubnets(actions).send(&self.p2p_tx);
        }

        let actions = self.sync_committee_subnets.on_slot(slot);

        if !actions.is_empty() {
            SubnetServiceToP2p::UpdateSyncCommitteeSubnets(actions).send(&self.p2p_tx);
        }

        Ok(())
    }

    fn set_registered_validators(&self, pubkeys: Vec<PublicKeyBytes>) {
        self.attestation_agg_pool.set_registered_validators(pubkeys);
    }

    fn update_beacon_committee_subscriptions(
        &mut self,
        current_slot: Slot,
        subscriptions: Vec<BeaconCommitteeSubscription>,
    ) -> Result<()> {
        self.beacon_committee_subscriptions
            .update::<P>(subscriptions);

        let actions = self
            .attestation_subnets
            .update(current_slot, self.beacon_committee_subscriptions.all())?;

        SubnetServiceToP2p::UpdateAttestationSubnets(actions).send(&self.p2p_tx);

        Ok(())
    }

    fn update_sync_committee_subscriptions(
        &mut self,
        current_epoch: Epoch,
        subscriptions: Vec<SyncCommitteeSubscription>,
    ) {
        let actions = self
            .sync_committee_subnets
            .update(current_epoch, subscriptions);

        SubnetServiceToP2p::UpdateSyncCommitteeSubnets(actions).send(&self.p2p_tx);
    }
}
