use core::marker::PhantomData;
use std::collections::{BTreeMap, HashMap, HashSet};

use bls::{traits::BlsCachedPublicKey, PublicKeyBytes};
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use p2p::SyncCommitteeSubscription;
use rand::Rng as _;
use typenum::Unsigned as _;
use types::{
    altair::{consts::SyncCommitteeSubnetCount, containers::SyncCommittee},
    phase0::primitives::Epoch,
    preset::Preset,
    traits::PostAltairBeaconState,
};

#[derive(Default)]
pub struct OwnSyncCommitteeSubscriptions<P: Preset> {
    subscriptions: BTreeMap<u64, HashMap<Epoch, Vec<SyncCommitteeSubscription>>>,
    phantom: PhantomData<P>,
}

impl<P: Preset> OwnSyncCommitteeSubscriptions<P> {
    pub fn build(
        &mut self,
        state: &(impl PostAltairBeaconState<P> + ?Sized),
        own_public_keys: &HashSet<PublicKeyBytes>,
    ) {
        let current_epoch = accessors::get_current_epoch(state);
        let current_period = misc::sync_committee_period::<P>(current_epoch);
        let next_period = current_period + 1;
        let next_period_start = misc::start_of_sync_committee_period::<P>(next_period);

        if self.subscriptions.contains_key(&current_period) {
            let subscriptions = core::iter::repeat(current_epoch)
                .zip(sync_committee_subscriptions(
                    state,
                    own_public_keys,
                    state.current_sync_committee(),
                    next_period_start,
                ))
                .into_group_map();

            self.subscriptions.insert(current_period, subscriptions);
        }

        if self.subscriptions.contains_key(&next_period) {
            let next_period_expiration = misc::start_of_sync_committee_period::<P>(next_period + 1);

            let mut rng = rand::thread_rng();

            let subscriptions = sync_committee_subscriptions(
                state,
                own_public_keys,
                state.next_sync_committee(),
                next_period_expiration,
            )
            .map(|subscription| {
                // From the [Altair Honest Validator specification]:
                // > To join a sync committee subnet, select a random number of epochs before the
                // > end of the current sync committee period between 1 and
                // > `SYNC_COMMITTEE_SUBNET_COUNT`, inclusive. Validators should join their member
                // > subnet at the beginning of the epoch they have randomly selected. For example,
                // > if the next sync committee period starts at epoch `853,248` and the validator
                // > randomly selects an offset of `3`, they should join the subnet at the beginning
                // > of epoch `853,245`.
                //
                // [Altair Honest Validator specification]: https://github.com/ethereum/consensus-specs/blob/0b76c8367ed19014d104e3fbd4718e73f459a748/specs/altair/validator.md#sync-committee-subnet-stability
                let epoch_to_subscribe_at =
                    next_period_start - rng.gen_range(1..=SyncCommitteeSubnetCount::U64);

                (epoch_to_subscribe_at, subscription)
            })
            .into_group_map();

            self.subscriptions.insert(next_period, subscriptions);
        }
    }

    pub fn discard_old_subscriptions(&mut self, current_epoch: Epoch) {
        let current_period = misc::sync_committee_period::<P>(current_epoch);

        self.subscriptions = self.subscriptions.split_off(&current_period);
    }

    pub fn take_epoch_subscriptions(
        &mut self,
        current_epoch: Epoch,
    ) -> Option<Vec<SyncCommitteeSubscription>> {
        let current_period = misc::sync_committee_period::<P>(current_epoch);

        self.subscriptions
            .get_mut(&current_period)
            .and_then(|subscriptions| subscriptions.remove(&current_epoch))
    }
}

fn sync_committee_subscriptions<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
    own_public_keys: &HashSet<PublicKeyBytes>,
    sync_committee: &SyncCommittee<P>,
    until_epoch: Epoch,
) -> impl Iterator<Item = SyncCommitteeSubscription> {
    sync_committee
        .pubkeys
        .iter()
        .enumerate()
        .filter(|(_, public_key)| own_public_keys.contains(&public_key.to_bytes()))
        .filter_map(|(position, public_key)| {
            Some((
                accessors::index_of_public_key(state, public_key.to_bytes())?,
                position,
            ))
        })
        .into_group_map()
        .into_iter()
        .map(
            move |(validator_index, sync_committee_indices)| SyncCommitteeSubscription {
                validator_index,
                sync_committee_indices,
                until_epoch,
            },
        )
}
