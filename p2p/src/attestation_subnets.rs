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

const DISCOVER_PEERS_IN_ADVANCE_SLOTS: u64 = 2;
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

impl AttestationSubnetState {
    #[must_use]
    pub fn max_expiration(self, other_expiration: Slot) -> Slot {
        match self {
            Irrelevant => other_expiration,
            DiscoveringPeers { expiration }
            | Subscribed { expiration }
            | Persistent { expiration } => other_expiration.max(expiration),
        }
    }
}

#[derive(Clone, Copy)]
pub struct AttestationSubnets<P> {
    states: [AttestationSubnetState; AttestationSubnetCount::USIZE],
    // Needed to track if app is subscribed to persistent subnets,
    // and allow to subscribe to them mid epoch on app start.
    initialized_persistent: bool,
    node_id: NodeId,
    phantom: PhantomData<P>,
}

impl<P: Preset> AttestationSubnets<P> {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            states: [AttestationSubnetState::default(); AttestationSubnetCount::USIZE],
            initialized_persistent: false,
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
            return Ok(self.actions(old));
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

        if !self.initialized_persistent || misc::is_epoch_start::<P>(slot) {
            self.initialized_persistent = true;

            let expiration = misc::compute_start_slot_at_epoch::<P>(current_epoch + 1);

            for subnet_id in
                misc::compute_subscribed_subnets::<P>(self.node_id, config, current_epoch)?
            {
                let position = usize::try_from(subnet_id)?;

                self.states[position] = Persistent {
                    expiration: self.states[position].max_expiration(expiration),
                };
            }
        }

        self.update_states(slot, subscriptions)?;

        Ok(self.actions(old))
    }

    pub fn update(
        &mut self,
        current_slot: Slot,
        subscriptions: impl IntoIterator<Item = BeaconCommitteeSubscription>,
    ) -> Result<AttestationSubnetActions> {
        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);
        let old = *self;

        if self.subscribe_to_all_if_needed(current_epoch) {
            return Ok(self.actions(old));
        }

        self.update_states(current_slot, subscriptions)?;

        Ok(self.actions(old))
    }

    fn actions(self, old: Self) -> AttestationSubnetActions {
        let new = self;

        let discoveries = izip!(0.., old.states, new.states)
            .filter(|(_, old_state, new_state)| old_state != new_state)
            .filter_map(|(subnet_id, old_state, new_state)| {
                let expiration = match (old_state, new_state) {
                    (_, Persistent { .. }) => None,
                    (_, DiscoveringPeers { expiration } | Subscribed { expiration }) => {
                        Some(expiration)
                    }
                    _ => return None,
                };

                Some(SubnetPeerDiscovery {
                    subnet_id,
                    expiration,
                })
            })
            .collect();

        let enr = izip!(0.., old.states, new.states)
            .filter_map(|(subnet_id, old_state, new_state)| {
                let add_to_enr = match (old_state, new_state) {
                    (
                        Irrelevant | DiscoveringPeers { .. } | Subscribed { .. },
                        Persistent { .. },
                    ) => true,
                    (
                        Persistent { .. },
                        Irrelevant | DiscoveringPeers { .. } | Subscribed { .. },
                    ) => false,
                    _ => return None,
                };

                Some((subnet_id, add_to_enr))
            })
            .collect();

        let subscriptions = izip!(0.., old.states, new.states)
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

            let in_advance_slots = if is_aggregator {
                SUBSCRIBE_IN_ADVANCE_SLOTS
            } else {
                DISCOVER_PEERS_IN_ADVANCE_SLOTS
            };

            if current_slot + in_advance_slots < slot || current_slot > slot {
                continue;
            }

            let subnet_id: usize = misc::compute_subnet_for_attestation::<P>(
                committees_at_slot,
                slot,
                committee_index,
            )?
            .try_into()?;

            let subnet_state = &mut self.states[subnet_id];

            *subnet_state = match subnet_state {
                // If persistent subscription exists at current slot, do not change anything
                Persistent { expiration } => Persistent {
                    expiration: *expiration,
                },
                // If validator is aggregator, subscribe to subnet or extend existing subscription
                // (except if persistent subscription already exists)
                Subscribed { expiration } if is_aggregator => Subscribed {
                    expiration: (*expiration).max(slot + 1),
                },
                // Ignore DiscoveringPeers expiration for the new subscription
                Irrelevant | DiscoveringPeers { .. } if is_aggregator => Subscribed {
                    expiration: slot + 1,
                },
                // If validator is not an aggregator, and subscription exists at current slot, do not change anything
                Subscribed { expiration } => Subscribed {
                    expiration: *expiration,
                },
                // If validator is not an aggregator, discover peers in subnet
                Irrelevant | DiscoveringPeers { .. } => DiscoveringPeers {
                    expiration: subnet_state.max_expiration(slot + 1),
                },
            };
        }

        Ok(())
    }
}
