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
                    (Subscribed { .. }, Subscribed { expiration }) => DiscoverPeers { expiration },
                    (_, Subscribed { expiration }) => Subscribe { expiration },
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

        let expiration = current_epoch.saturating_add(1);

        self.states = [Subscribed { expiration }; SyncCommitteeSubnetCount::USIZE];

        true
    }
}

#[cfg(test)]
mod tests {
    use types::preset::Mainnet;

    use super::*;

    fn subscription(sync_committee_index: usize, until_epoch: Epoch) -> SyncCommitteeSubscription {
        SyncCommitteeSubscription {
            validator_index: 0,
            sync_committee_indices: vec![sync_committee_index],
            until_epoch,
        }
    }

    // The peer manager keeps and replenishes peers on a subnet only for as long as the action
    // says, so the actions carry the subscription's expiration.
    #[test]
    fn actions_carry_the_expiration_of_the_subscription() {
        let mut subnets = SyncCommitteeSubnets::<Mainnet>::default();

        // Sync committee index 0 lies in subnet 0 under the mainnet subcommittee size of 128.
        let actions = subnets.update(1, [subscription(0, 8)]);

        assert!(matches!(actions.get(&0), Some(Subscribe { expiration: 8 })));

        // A later subscription to the same subnet extends it and only asks for more peers.
        let actions = subnets.update(1, [subscription(0, 16)]);

        assert!(matches!(
            actions.get(&0),
            Some(DiscoverPeers { expiration: 16 })
        ));

        // An earlier one does not shorten it.
        let actions = subnets.update(1, [subscription(0, 4)]);

        assert!(matches!(
            actions.get(&0),
            Some(DiscoverPeers { expiration: 16 })
        ));
    }
}
