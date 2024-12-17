use core::marker::PhantomData;

use anyhow::Result;
use features::Feature;
use helper_functions::misc;
use itertools::izip;
use typenum::Unsigned as _;
use types::{
    config::Config,
    phase0::{
        consts::AttestationSubnetCount,
        primitives::{Epoch, NodeId, Slot},
    },
    preset::Preset,
};

use crate::misc::{AttestationSubnetActions, BeaconCommitteeSubscription, SubnetPeerDiscovery};

use AttestationSubnetState::{DiscoveringPeers, Irrelevant, Persistent, Subscribed};

const SUBSCRIBE_IN_ADVANCE_SLOTS: u64 = 1;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum AttestationSubnetState {
    /// Not subscribed to the subnet and not attesting in it.
    #[default]
    Irrelevant,
    /// Not subscribed to the subnet but need to discover peers in it to publish attestations.
    DiscoveringPeers { expiration: Slot },
    /// Subscribed to the subnet.
    Subscribed { expiration: Slot },
    /// Subscribed to the subnet and advertising the subscription in the ENR.
    Persistent { expiration: Slot },
}

#[derive(Clone, Copy)]
pub struct AttestationSubnets<P> {
    active_discoveries: [Option<Slot>; AttestationSubnetCount::USIZE],
    states: [AttestationSubnetState; AttestationSubnetCount::USIZE],
    // Needed to track if app is subscribed to persistent subnets,
    // and allow to subscribe to them mid epoch on app start.
    persistent_subscriptions_expiration: Option<Slot>,
    node_id: NodeId,
    phantom: PhantomData<P>,
}

impl<P: Preset> AttestationSubnets<P> {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            active_discoveries: [None; AttestationSubnetCount::USIZE],
            states: [AttestationSubnetState::default(); AttestationSubnetCount::USIZE],
            persistent_subscriptions_expiration: None,
            node_id,
            phantom: PhantomData,
        }
    }

    pub fn on_slot(
        &mut self,
        config: &Config,
        slot: Slot,
        subscriptions: impl IntoIterator<Item = BeaconCommitteeSubscription>,
    ) -> Result<AttestationSubnetActions> {
        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);
        let old = *self;

        if self.subscribe_to_all_if_needed(current_epoch) {
            return Ok(self.actions(old, slot));
        }

        // Advance subnet states to the current slot.
        for state in &mut self.states {
            match *state {
                DiscoveringPeers { expiration }
                | Subscribed { expiration }
                | Persistent { expiration }
                    if expiration <= slot =>
                {
                    *state = Irrelevant;
                }
                _ => {}
            }
        }

        let persistent_subscriptions_expired = self
            .persistent_subscriptions_expiration
            .map(|expiration| expiration <= slot)
            .unwrap_or(true);

        if persistent_subscriptions_expired {
            let expiration_epoch =
                misc::next_subnet_subscription_epoch::<P>(self.node_id, config, current_epoch)?;
            let expiration = misc::compute_start_slot_at_epoch::<P>(expiration_epoch);

            for subnet_id in
                misc::compute_subscribed_subnets::<P>(self.node_id, config, current_epoch)?
            {
                let position = usize::try_from(subnet_id)?;

                self.states[position] = Persistent { expiration };
            }

            self.persistent_subscriptions_expiration = Some(expiration);
        }

        self.update_states(slot, subscriptions)?;

        Ok(self.actions(old, slot))
    }

    pub fn update(
        &mut self,
        current_slot: Slot,
        subscriptions: impl IntoIterator<Item = BeaconCommitteeSubscription>,
    ) -> Result<AttestationSubnetActions> {
        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);
        let old = *self;

        if self.subscribe_to_all_if_needed(current_epoch) {
            return Ok(self.actions(old, current_slot));
        }

        self.update_states(current_slot, subscriptions)?;

        Ok(self.actions(old, current_slot))
    }

    fn actions(&mut self, old: Self, slot: Slot) -> AttestationSubnetActions {
        let discoveries = izip!(0.., self.states)
            .filter_map(|(subnet_id, new_state)| {
                let expiration = match new_state {
                    DiscoveringPeers { expiration }
                    | Subscribed { expiration }
                    | Persistent { expiration } => {
                        if let Some(active_discovery_expiration) =
                            self.active_discoveries[subnet_id]
                        {
                            if slot < active_discovery_expiration {
                                // Avoid making a new discovery request in subnet while previous peer discovery is not expired
                                return None;
                            }
                        }

                        self.active_discoveries[subnet_id] = Some(expiration);

                        Some(expiration)
                    }
                    Irrelevant => {
                        self.active_discoveries[subnet_id] = None;

                        return None;
                    }
                };

                Some(SubnetPeerDiscovery {
                    subnet_id: subnet_id.try_into().expect("subnet id should fit into u64"),
                    expiration,
                })
            })
            .collect();

        let enr = izip!(0.., old.states, self.states)
            .filter_map(|(subnet_id, old_state, new_state)| {
                let add_to_enr = match (old_state, new_state) {
                    (Persistent { .. }, Persistent { .. }) => return None,
                    (_, Persistent { .. }) => true,
                    (Persistent { .. }, _) => false,
                    _ => return None,
                };

                Some((subnet_id, add_to_enr))
            })
            .collect();

        let subscriptions = izip!(0.., old.states, self.states)
            .filter_map(|(subnet_id, old_state, new_state)| {
                let subscribe = match (old_state, new_state) {
                    (
                        Irrelevant | DiscoveringPeers { .. },
                        Subscribed { .. } | Persistent { .. },
                    ) => true,
                    (
                        Subscribed { .. } | Persistent { .. },
                        Irrelevant | DiscoveringPeers { .. },
                    ) => false,
                    _ => return None,
                };

                Some((subnet_id, subscribe))
            })
            .collect();

        AttestationSubnetActions {
            discoveries,
            enr,
            subscriptions,
        }
    }

    fn subscribe_to_all_if_needed(&mut self, current_epoch: Epoch) -> bool {
        if !Feature::SubscribeToAllAttestationSubnets.is_enabled() {
            return false;
        }

        let expiration = misc::compute_start_slot_at_epoch::<P>(current_epoch + 1);

        self.states = [Persistent { expiration }; AttestationSubnetCount::USIZE];

        true
    }

    fn update_states(
        &mut self,
        current_slot: Slot,
        subscriptions: impl IntoIterator<Item = BeaconCommitteeSubscription>,
    ) -> Result<()> {
        for subscription in subscriptions {
            let BeaconCommitteeSubscription {
                validator_index: _,
                committee_index,
                committees_at_slot,
                slot,
                is_aggregator,
            } = subscription;

            let subnet_id: usize = misc::compute_subnet_for_attestation::<P>(
                committees_at_slot,
                slot,
                committee_index,
            )?
            .try_into()?;

            let subnet_state = &mut self.states[subnet_id];

            if is_aggregator
                && current_slot + SUBSCRIBE_IN_ADVANCE_SLOTS >= slot
                && current_slot <= slot
            {
                match subnet_state {
                    // Beacon committee subscriptions have no effect on persistent subnet subscriptions
                    Persistent { .. } => {}
                    // If there is a subnet subscription at current slot, extend its expiration
                    Subscribed { expiration } => {
                        *subnet_state = Subscribed {
                            expiration: (*expiration).max(slot + 1),
                        };
                    }
                    // Make a new subnet subscription
                    Irrelevant | DiscoveringPeers { .. } => {
                        *subnet_state = Subscribed {
                            expiration: slot + 1,
                        };
                    }
                };
            } else {
                // Discover peers instantly after processing beacon committee subscriptions
                match subnet_state {
                    DiscoveringPeers { expiration } => {
                        *subnet_state = DiscoveringPeers {
                            expiration: (*expiration).max(slot + 1),
                        };
                    }
                    Irrelevant => {
                        *subnet_state = DiscoveringPeers {
                            expiration: slot + 1,
                        };
                    }
                    _ => {}
                };
            }
        }

        Ok(())
    }
}
