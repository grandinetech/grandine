use core::ops::RangeBounds;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use features::Feature;
use futures::stream::{FuturesOrdered, StreamExt as _};
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use ssz::SszHash;
use std_ext::ArcExt as _;
use tokio::sync::{Mutex, RwLock};
use types::{
    config::Config as ChainConfig,
    phase0::primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    preset::Preset,
    traits::BeaconState,
};

use crate::attestation_agg_pool::types::{
    Aggregate, AggregateMap, AttestationKey, AttestationMap, AttestationSet, PoolAttestation,
};

#[expect(type_alias_bounds)]
type AttestationsWithSlot<P: Preset> = (Vec<PoolAttestation<P>>, Slot);

pub struct Pool<P: Preset> {
    chain_config: Arc<ChainConfig>,
    aggregates: RwLock<BTreeMap<Epoch, AggregateMap<P>>>,
    data_root_to_key_map: RwLock<BTreeMap<Epoch, HashMap<H256, BTreeSet<AttestationKey>>>>,
    // The type of the inner map does not affect the result of attestation packing,
    // though that may change if the packers are redesigned again.
    singular_attestations: RwLock<BTreeMap<Epoch, AttestationMap<P>>>,
    best_proposable_attestations: Mutex<AttestationsWithSlot<P>>,
    committees_with_aggregators: RwLock<BTreeMap<Slot, BTreeSet<CommitteeIndex>>>,
    proposer_indices: RwLock<BTreeMap<Slot, ValidatorIndex>>,
    registered_validator_indices: RwLock<HashSet<ValidatorIndex>>,
}

impl<P: Preset> Pool<P> {
    pub fn new(chain_config: Arc<ChainConfig>) -> Self {
        Self {
            chain_config,
            aggregates: RwLock::default(),
            data_root_to_key_map: RwLock::default(),
            singular_attestations: RwLock::default(),
            best_proposable_attestations: Mutex::default(),
            committees_with_aggregators: RwLock::default(),
            proposer_indices: RwLock::default(),
            registered_validator_indices: RwLock::default(),
        }
    }

    pub async fn on_slot(&self, slot: Slot) {
        if misc::is_epoch_start::<P>(slot) {
            let current_epoch = misc::compute_epoch_at_slot::<P>(slot);
            let previous_epoch = misc::previous_epoch(current_epoch);

            let mut aggregates = self.aggregates.write().await;
            *aggregates = aggregates.split_off(&previous_epoch);

            let mut data_root_to_key_map = self.data_root_to_key_map.write().await;
            *data_root_to_key_map = data_root_to_key_map.split_off(&previous_epoch);

            let mut singular_attestations = self.singular_attestations.write().await;
            *singular_attestations = singular_attestations.split_off(&previous_epoch);
        }

        let mut proposer_indices = self.proposer_indices.write().await;
        *proposer_indices = proposer_indices.split_off(&slot);
    }

    pub async fn add_data_root_to_key_entry(&self, key: AttestationKey) {
        let root = key.data.hash_tree_root();

        self.data_root_to_key_map
            .write()
            .await
            .entry(key.data.target.epoch)
            .or_default()
            .entry(root)
            .or_default()
            .insert(key);
    }

    pub async fn aggregates(&self, key: AttestationKey) -> Arc<Mutex<Vec<Aggregate<P>>>> {
        let epoch = key.data.target.epoch;

        if let Some(aggregates) = self
            .aggregates
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_aggregates| epoch_aggregates.get(&key))
        {
            return aggregates.clone_arc();
        }

        self.aggregates
            .write()
            .await
            .entry(epoch)
            .or_default()
            .entry(key)
            .or_default()
            .clone_arc()
    }

    pub async fn aggregate_attestations_by_epoch(&self, epoch: Epoch) -> Vec<PoolAttestation<P>> {
        self.aggregates
            .read()
            .await
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|(key, aggregates)| async {
                aggregates
                    .lock()
                    .await
                    .iter()
                    .cloned()
                    .map(|aggregate| {
                        let AttestationKey {
                            data,
                            committee_index,
                        } = *key;
                        let Aggregate {
                            aggregation_bits,
                            signature,
                        } = aggregate;

                        PoolAttestation {
                            aggregation_bits,
                            data,
                            committee_index,
                            signature: signature.into(),
                        }
                    })
                    .collect_vec()
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect_vec()
    }

    pub async fn aggregate_in_committee(
        &self,
        committee_index: CommitteeIndex,
        attestation_slot: Slot,
    ) -> bool {
        let proposing_from_slot = attestation_slot.saturating_add(1);
        let proposing_to_slot = attestation_slot.saturating_add(2);

        if Feature::AggregateAllAttestations.is_enabled()
            || self
                .has_registered_validators_proposing_in_slots(
                    proposing_from_slot..=proposing_to_slot,
                )
                .await
        {
            return true;
        }

        self.committees_with_aggregators
            .read()
            .await
            .get(&attestation_slot)
            .is_some_and(|indices| indices.contains(&committee_index))
    }

    pub async fn best_aggregate_attestation(
        &self,
        key: AttestationKey,
    ) -> Option<PoolAttestation<P>> {
        let epoch = key.data.target.epoch;

        if let Some(aggregates) = self
            .aggregates
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_aggregates| epoch_aggregates.get(&key))
        {
            return aggregates
                .lock()
                .await
                .iter()
                .max_by_key(|aggregate| aggregate.aggregation_bits.count_ones())
                .cloned()
                .map(|aggregate| {
                    let AttestationKey {
                        data,
                        committee_index,
                    } = key;
                    let Aggregate {
                        aggregation_bits,
                        signature,
                    } = aggregate;

                    PoolAttestation {
                        aggregation_bits,
                        data,
                        committee_index,
                        signature: signature.into(),
                    }
                });
        }

        None
    }

    // Handler for the `/eth/v2/validator/aggregate_attestation` API call.
    // Expects `attestation_data_root` computed from the signed `AttestationData`,
    // with `committee_index` provided separately.
    pub async fn best_aggregate_attestation_by_data_root_and_committee_index(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
        committee_index: CommitteeIndex,
    ) -> Option<PoolAttestation<P>> {
        self.aggregate_attestations_by_epoch(epoch)
            .await
            .into_iter()
            .filter(|attestation| {
                attestation.committee_index == committee_index
                    && attestation.data.hash_tree_root() == attestation_data_root
            })
            .max_by_key(|attestation| attestation.aggregation_bits.count_ones())
    }

    pub async fn best_aggregate_attestation_by_data_root(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
    ) -> Option<PoolAttestation<P>> {
        if let Some(keys) = self
            .data_root_to_key_map
            .read()
            .await
            .get(&epoch)
            .and_then(|key_map| key_map.get(&attestation_data_root))
            .cloned()
        {
            let mut best_attestation = None;

            for key in keys {
                if let Some(attestation) = self.best_aggregate_attestation(key).await
                    && best_attestation
                        .as_ref()
                        .is_none_or(|best: &PoolAttestation<P>| {
                            attestation.aggregation_bits.count_ones()
                                > best.aggregation_bits.count_ones()
                        })
                {
                    best_attestation = Some(attestation);
                }
            }

            if best_attestation.is_some() {
                return best_attestation;
            }
        }

        self.aggregate_attestations_by_epoch(epoch)
            .await
            .into_iter()
            .filter(|attestation| attestation.data.hash_tree_root() == attestation_data_root)
            .max_by_key(|attestation| attestation.aggregation_bits.count_ones())
    }

    pub async fn best_proposable_attestations(&self, slot: Slot) -> Vec<PoolAttestation<P>> {
        let attestations_with_slot = self.best_proposable_attestations.lock().await;
        let (attestations, prepared_for_slot) = &*attestations_with_slot;

        if slot == *prepared_for_slot {
            attestations.clone()
        } else {
            Vec::new()
        }
    }

    pub async fn clear_best_proposable_attestations(&self) {
        core::mem::take(&mut *self.best_proposable_attestations.lock().await);
    }

    pub async fn compute_proposer_indices_for_epoch(
        &self,
        state: &impl BeaconState<P>,
        epoch: Epoch,
    ) -> Result<()> {
        let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
        let end_slot = misc::compute_start_slot_at_epoch::<P>(epoch.saturating_add(1));

        if self
            .has_precomputed_proposer_indices_in_slots(start_slot..end_slot)
            .await
        {
            return Ok(());
        }

        let slot_proposers = (start_slot..end_slot)
            .map(|slot| {
                Ok((
                    slot,
                    accessors::get_beacon_proposer_index_at_slot(&self.chain_config, state, slot)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut proposer_indices = self.proposer_indices.write().await;

        for (slot, proposer_index) in slot_proposers {
            proposer_indices.entry(slot).or_insert(proposer_index);
        }

        Ok(())
    }

    pub async fn has_registered_validators_proposing_in_slots(
        &self,
        range: impl RangeBounds<Slot> + Send,
    ) -> bool {
        let registered_indices = self.registered_validator_indices.read().await;

        self.proposer_indices
            .read()
            .await
            .range(range)
            .any(|(_, validator_index)| registered_indices.contains(validator_index))
    }

    pub async fn is_registered_validator(&self, validator_index: ValidatorIndex) -> bool {
        self.registered_validator_indices
            .read()
            .await
            .contains(&validator_index)
    }

    pub async fn registered_validator_indices(&self) -> HashSet<ValidatorIndex> {
        self.registered_validator_indices.read().await.clone()
    }

    pub async fn set_best_proposable_attestations(
        &self,
        attestations: Vec<PoolAttestation<P>>,
        prepared_for_slot: Slot,
    ) {
        *self.best_proposable_attestations.lock().await = (attestations, prepared_for_slot);
    }

    pub async fn set_committees_with_aggregators(
        &self,
        committees_with_aggregators: BTreeMap<Slot, BTreeSet<CommitteeIndex>>,
    ) {
        *self.committees_with_aggregators.write().await = committees_with_aggregators;
    }

    pub async fn set_registered_validator_indices(
        &self,
        validator_indices: HashSet<ValidatorIndex>,
    ) {
        *self.registered_validator_indices.write().await = validator_indices;
    }

    pub async fn singular_attestations(
        &self,
        key: AttestationKey,
    ) -> Arc<RwLock<AttestationSet<P>>> {
        let epoch = key.data.target.epoch;

        if let Some(attestations) = self
            .singular_attestations
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_attestations| epoch_attestations.get(&key))
        {
            return attestations.clone_arc();
        }

        self.singular_attestations
            .write()
            .await
            .entry(epoch)
            .or_default()
            .entry(key)
            .or_default()
            .clone_arc()
    }

    pub async fn singular_attestations_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Vec<Arc<PoolAttestation<P>>> {
        self.singular_attestations
            .read()
            .await
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|(_, attestations)| async { attestations.read().await.clone() })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect_vec()
    }

    async fn has_precomputed_proposer_indices_in_slots(
        &self,
        range: impl RangeBounds<Slot> + Send,
    ) -> bool {
        self.proposer_indices
            .read()
            .await
            .range(range)
            .next()
            .is_some()
    }
}
