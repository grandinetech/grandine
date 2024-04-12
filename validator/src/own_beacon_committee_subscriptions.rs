use std::collections::HashMap;

use anyhow::Result;
use helper_functions::{accessors, misc, predicates, signing::SignForSingleFork as _};
use log::warn;
use p2p::BeaconCommitteeSubscription;
use signer::{Signer, SigningMessage, SigningTriple};
use types::{config::Config, phase0::primitives::Epoch, preset::Preset, traits::BeaconState};

#[derive(Default)]
pub struct OwnBeaconCommitteeSubscriptions {
    latest_computed_epoch: Option<Epoch>,
}

impl OwnBeaconCommitteeSubscriptions {
    pub async fn compute_for_epoch<P: Preset>(
        &mut self,
        config: &Config,
        epoch: Epoch,
        state: &impl BeaconState<P>,
        signer: &Signer,
    ) -> Result<Vec<BeaconCommitteeSubscription>> {
        if self
            .latest_computed_epoch
            .is_some_and(|computed_epoch| computed_epoch >= epoch)
        {
            return Ok(vec![]);
        }

        let signer_snapshot = signer.load();

        let own_public_keys = signer_snapshot
            .keys()
            .copied()
            .filter_map(|public_key| {
                let validator_index = accessors::index_of_public_key(state, public_key)?;
                Some((validator_index, public_key))
            })
            .collect::<HashMap<_, _>>();

        if own_public_keys.is_empty() {
            return Ok(vec![]);
        }

        let mut subscriptions = vec![];
        let mut triples = vec![];

        for slot in misc::slots_in_epoch::<P>(epoch) {
            let beacon_committees = (0..).zip(accessors::beacon_committees(state, slot)?);
            let relative_epoch = accessors::relative_epoch(state, epoch)?;
            let committees_at_slot = accessors::get_committee_count_per_slot(state, relative_epoch);

            for (committee_index, committee) in beacon_committees {
                for validator_index in committee {
                    let Some(public_key) = own_public_keys.get(&validator_index).copied() else {
                        continue;
                    };

                    subscriptions.push(BeaconCommitteeSubscription {
                        validator_index,
                        committee_index,
                        committees_at_slot,
                        slot,
                        is_aggregator: false,
                    });

                    triples.push(SigningTriple::<P> {
                        message: SigningMessage::AggregationSlot { slot },
                        signing_root: slot.signing_root(config, state),
                        public_key,
                    });
                }
            }
        }

        let slot_signatures = signer_snapshot
            .sign_triples(triples, Some(state.into()))
            .await?;

        let result = subscriptions
            .into_iter()
            .zip(slot_signatures)
            .map(|(subscription, slot_signature)| {
                let BeaconCommitteeSubscription {
                    validator_index,
                    committee_index,
                    committees_at_slot,
                    slot,
                    ..
                } = subscription;

                let is_aggregator =
                    predicates::is_aggregator(state, slot, committee_index, slot_signature.into())?;

                Ok(BeaconCommitteeSubscription {
                    validator_index,
                    committee_index,
                    committees_at_slot,
                    slot,
                    is_aggregator,
                })
            })
            .collect::<Result<_>>();

        match result {
            Ok(subscriptions) => {
                self.latest_computed_epoch = Some(epoch);
                Ok(subscriptions)
            }
            Err(error) => {
                warn!("failed to sign aggregation slots for selection proofs: {error:?}");
                Ok(vec![])
            }
        }
    }
}
