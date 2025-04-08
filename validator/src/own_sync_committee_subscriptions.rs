use core::marker::PhantomData;
use std::collections::{BTreeMap, HashMap, HashSet};

use bls::{traits::CachedPublicKey as _, PublicKeyBytes};
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

        self.subscriptions.entry(current_period).or_insert_with(|| {
            core::iter::repeat(current_epoch)
                .zip(sync_committee_subscriptions(
                    state,
                    own_public_keys,
                    state.current_sync_committee(),
                    next_period_start,
                ))
                .into_group_map()
        });

        self.subscriptions.entry(next_period).or_insert_with(|| {
            let next_period_expiration = misc::start_of_sync_committee_period::<P>(next_period + 1);

            let mut rng = rand::thread_rng();

            sync_committee_subscriptions(
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
            .into_group_map()
        });
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

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use eth2_cache_utils::holesky;
    use hex_literal::hex;
    use std_ext::ArcExt as _;
    use types::{preset::Mainnet, traits::BeaconState as _};

    use super::*;

    #[tokio::test]
    async fn test_build_own_sync_committee_subscriptions() {
        let state = holesky::CAPELLA_BEACON_STATE.force().clone_arc();
        let mut own_sync_committee_subscriptions = OwnSyncCommitteeSubscriptions::default();

        assert!(own_sync_committee_subscriptions.subscriptions.is_empty());

        own_sync_committee_subscriptions.build(
            state
                .post_altair()
                .expect("post-altair state must be present"),
                &HashSet::from([
                    // current sync committee member
                    PublicKeyBytes::from(hex!("b8f0d05a9546ff830cd880170d4cb9c78aa0fd40d2b20919adc2ecb35ddac1496ade2819ff3b9d35244c0e0dc2b9dbe6")),
                    // next sync committee member
                    PublicKeyBytes::from(hex!("955bf6d459fca592c2eb0b71c934fcb046b40384e87870d87033013055cc698841c26d9e2f0e3c9e602ce319c630f8ec")),
                    // non sync committee member
                    PublicKeyBytes::from(hex!("83f66b69582ca67b8f0fc1e678015e72cce821d0930bcea582a011b495d6fed1e6c550b26d1a66331d8607ae34fd4423")),
                ])
        );

        let state_slot = state.slot();
        let current_epoch = misc::compute_epoch_at_slot::<Mainnet>(state_slot);
        let current_sync_committee_period = misc::sync_committee_period::<Mainnet>(current_epoch);

        let current_subscriptions = own_sync_committee_subscriptions
            .subscriptions
            .get(&current_sync_committee_period)
            .and_then(|subscriptions| subscriptions.get(&current_epoch))
            .expect("current sync committee subscriptions must have been built");

        let next_committee_epoch = 1792;

        assert_eq!(
            *current_subscriptions,
            vec![SyncCommitteeSubscription {
                validator_index: 1_287_329,
                sync_committee_indices: vec![509],
                until_epoch: next_committee_epoch,
            }],
        );

        let next_sync_committee_period =
            misc::sync_committee_period::<Mainnet>(next_committee_epoch);

        let next_subscriptions = own_sync_committee_subscriptions
            .subscriptions
            .get(&next_sync_committee_period)
            .expect("next sync committee subscriptions must have been built");

        assert_eq!(next_subscriptions.values().len(), 1);

        for subscription in next_subscriptions.values() {
            assert_eq!(
                *subscription,
                vec![SyncCommitteeSubscription {
                    validator_index: 993_919,
                    sync_committee_indices: vec![474],
                    until_epoch: 2048,
                }],
            )
        }
    }
}
