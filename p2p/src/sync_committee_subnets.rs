use core::marker::PhantomData;
use std::collections::BTreeMap;

use arithmetic::UsizeExt;
use features::Feature;
use helper_functions::misc;
use itertools::izip;
use typenum::Unsigned as _;
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    phase0::primitives::{Epoch, Slot, SubnetId},
    preset::{Preset, SyncSubcommitteeSize},
};

use crate::misc::{SyncCommitteeSubnetAction, SyncCommitteeSubscription};

use SyncCommitteeSubnetAction::{DiscoverPeers, Subscribe, Unsubscribe};
use SyncCommitteeSubnetState::{Subscribed, Unsubscribed};

#[derive(Clone, Copy, Default)]
pub enum SyncCommitteeSubnetState {
    #[default]
    Unsubscribed,
    Subscribed {
        expiration: Epoch,
    },
}

impl SyncCommitteeSubnetState {
    #[must_use]
    pub fn max_expiration(self, other_expiration: Epoch) -> Epoch {
        match self {
            Unsubscribed => other_expiration,
            Subscribed { expiration } => other_expiration.max(expiration),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct SyncCommitteeSubnets<P> {
    states: [SyncCommitteeSubnetState; SyncCommitteeSubnetCount::USIZE],
    // Only needed for one purpose:
    // allowing to subscribe to all subnets mid epoch on app start
    // (if `Feature::SubscribeToAllSyncCommitteeSubnets` is enabled).
    initialized: bool,
    phantom: PhantomData<P>,
}

impl<P: Preset> SyncCommitteeSubnets<P> {
    pub fn on_slot(&mut self, slot: Slot) -> BTreeMap<SubnetId, SyncCommitteeSubnetAction> {
        // Update at the start of every epoch to trigger `SyncCommitteeSubnetAction::DiscoverPeers`
        // and retain a sufficient number of peers.
        if self.initialized && !misc::is_epoch_start::<P>(slot) {
            return BTreeMap::new();
        }

        self.initialized = true;

        let current_epoch = misc::compute_epoch_at_slot::<P>(slot);
        let old = *self;

        if self.subscribe_to_all_if_needed(current_epoch) {
            return self.actions(old);
        }

        // Advance subnet states to the current epoch.
        for state in &mut self.states {
            match *state {
                Unsubscribed => {}
                Subscribed { expiration } => {
                    if expiration <= current_epoch {
                        *state = Unsubscribed;
                    }
                }
            }
        }

        self.actions(old)
    }

    pub fn update(
        &mut self,
        current_epoch: Epoch,
        subscriptions: impl IntoIterator<Item = SyncCommitteeSubscription>,
    ) -> BTreeMap<SubnetId, SyncCommitteeSubnetAction> {
        let old = *self;

        if self.subscribe_to_all_if_needed(current_epoch) {
            return self.actions(old);
        }

        for subscription in subscriptions {
            let SyncCommitteeSubscription {
                validator_index: _,
                sync_committee_indices,
                until_epoch,
            } = subscription;

            for subnet_id in sync_committee_indices
                .into_iter()
                .map(UsizeExt::div_typenum::<SyncSubcommitteeSize<P>>)
            {
                let subnet_state = &mut self.states[subnet_id];
                let expiration = subnet_state.max_expiration(until_epoch);

                *subnet_state = Subscribed { expiration };
            }
        }

        self.actions(old)
    }

    fn actions(self, old: Self) -> BTreeMap<SubnetId, SyncCommitteeSubnetAction> {
        let new = self;

        izip!(0.., old.states, new.states)
            .filter_map(|(subnet_id, old_state, new_state)| {
                let action = match (old_state, new_state) {
                    (Subscribed { .. }, Subscribed { .. }) => DiscoverPeers,
                    (_, Subscribed { .. }) => Subscribe,
                    (Subscribed { .. }, _) => Unsubscribe,
                    _ => return None,
                };

                Some((subnet_id, action))
            })
            .collect()
    }

    fn subscribe_to_all_if_needed(&mut self, current_epoch: Epoch) -> bool {
        if !Feature::SubscribeToAllSyncCommitteeSubnets.is_enabled() {
            return false;
        }

        let expiration = current_epoch + 1;

        self.states = [Subscribed { expiration }; SyncCommitteeSubnetCount::USIZE];

        true
    }
}
