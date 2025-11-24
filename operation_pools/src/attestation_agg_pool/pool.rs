use core::ops::RangeBounds;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use features::Feature;
use futures::stream::{FuturesUnordered, StreamExt as _};
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use ssz::{ContiguousList, SszHash};
use std_ext::ArcExt as _;
use tokio::sync::{Mutex, RwLock};
use types::{
    config::Config as ChainConfig,
    phase0::{
        containers::{Attestation, AttestationData},
        primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::BeaconState,
};

use crate::attestation_agg_pool::types::{Aggregate, AggregateMap, AttestationMap, AttestationSet};

#[expect(type_alias_bounds)]
type AttestationsWithSlot<P: Preset> = (ContiguousList<Attestation<P>, P::MaxAttestations>, Slot);

pub struct Pool<P: Preset> {
    chain_config: Arc<ChainConfig>,
    aggregates: RwLock<BTreeMap<Epoch, AggregateMap<P>>>,
    data_root_to_data_map: RwLock<BTreeMap<Epoch, HashMap<H256, AttestationData>>>,
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
            data_root_to_data_map: RwLock::default(),
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

            let mut data_root_to_data_map = self.data_root_to_data_map.write().await;
            *data_root_to_data_map = data_root_to_data_map.split_off(&previous_epoch);

            let mut singular_attestations = self.singular_attestations.write().await;
            *singular_attestations = singular_attestations.split_off(&previous_epoch);
        }

        let mut proposer_indices = self.proposer_indices.write().await;
        *proposer_indices = proposer_indices.split_off(&slot);
    }

    pub async fn add_data_root_to_data_entry(&self, data: AttestationData) {
        let root = data.hash_tree_root();

        self.data_root_to_data_map
            .write()
            .await
            .entry(data.target.epoch)
            .or_default()
            .insert(root, data);
    }

    pub async fn aggregates(&self, data: AttestationData) -> Arc<Mutex<Vec<Aggregate<P>>>> {
        let epoch = data.target.epoch;

        if let Some(aggregates) = self
            .aggregates
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_aggregates| epoch_aggregates.get(&data))
        {
            return aggregates.clone_arc();
        }

        self.aggregates
            .write()
            .await
            .entry(epoch)
            .or_default()
            .entry(data)
            .or_default()
            .clone_arc()
    }

    pub async fn aggregate_attestations_by_epoch(&self, epoch: Epoch) -> Vec<Attestation<P>> {
        self.aggregates
            .read()
            .await
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|(data, aggregates)| async {
                aggregates
                    .lock()
                    .await
                    .iter()
                    .cloned()
                    .map(|aggregate| {
                        let Aggregate {
                            aggregation_bits,
                            signature,
                        } = aggregate;

                        Attestation {
                            aggregation_bits,
                            data: *data,
                            signature: signature.into(),
                        }
                    })
                    .collect_vec()
            })
            .collect::<FuturesUnordered<_>>()
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
        let proposing_from_slot = attestation_slot + 1;
        let proposing_to_slot = attestation_slot + 2;

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
        data: AttestationData,
    ) -> Option<Attestation<P>> {
        let epoch = data.target.epoch;

        if let Some(aggregates) = self
            .aggregates
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_aggregates| epoch_aggregates.get(&data))
        {
            return aggregates
                .lock()
                .await
                .iter()
                .max_by_key(|aggregate| aggregate.aggregation_bits.count_ones())
                .cloned()
                .map(|aggregate| {
                    let Aggregate {
                        aggregation_bits,
                        signature,
                    } = aggregate;

                    Attestation {
                        aggregation_bits,
                        data,
                        signature: signature.into(),
                    }
                });
        }

        None
    }

    // Handler for the `/eth/v2/validator/aggregate_attestation` API call.
    // Expects `attestation_data_root` computed from the post-Electra `AttestationData`,
    // with `committee_index` explicitly set to 0 and provided separately.
    pub async fn best_aggregate_attestation_by_data_root_and_committee_index(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
        committee_index: CommitteeIndex,
    ) -> Option<Attestation<P>> {
        self.aggregate_attestations_by_epoch(epoch)
            .await
            .into_iter()
            .filter(|attestation| {
                let mut data = attestation.data;
                let data_committee_index = data.index;

                if epoch >= self.chain_config.electra_fork_epoch {
                    data.index = 0;
                }

                data_committee_index == committee_index
                    && data.hash_tree_root() == attestation_data_root
            })
            .max_by_key(|attestation| attestation.aggregation_bits.count_ones())
    }

    pub async fn best_aggregate_attestation_by_data_root(
        &self,
        attestation_data_root: H256,
        epoch: Epoch,
    ) -> Option<Attestation<P>> {
        if let Some(data) = self
            .data_root_to_data_map
            .read()
            .await
            .get(&epoch)
            .and_then(|data_map| data_map.get(&attestation_data_root))
        {
            return self.best_aggregate_attestation(*data).await;
        }

        self.aggregate_attestations_by_epoch(epoch)
            .await
            .into_iter()
            .filter(|attestation| attestation.data.hash_tree_root() == attestation_data_root)
            .max_by_key(|attestation| attestation.aggregation_bits.count_ones())
    }

    pub async fn best_proposable_attestations(
        &self,
        slot: Slot,
    ) -> ContiguousList<Attestation<P>, P::MaxAttestations> {
        let attestations_with_slot = self.best_proposable_attestations.lock().await;
        let (attestations, prepared_for_slot) = &*attestations_with_slot;

        if slot == *prepared_for_slot {
            attestations.clone()
        } else {
            ContiguousList::default()
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
        let end_slot = misc::compute_start_slot_at_epoch::<P>(epoch + 1);

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
        attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
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
        data: AttestationData,
    ) -> Arc<RwLock<AttestationSet<P>>> {
        let epoch = data.target.epoch;

        if let Some(attestations) = self
            .singular_attestations
            .read()
            .await
            .get(&epoch)
            .and_then(|epoch_attestations| epoch_attestations.get(&data))
        {
            return attestations.clone_arc();
        }

        self.singular_attestations
            .write()
            .await
            .entry(epoch)
            .or_default()
            .entry(data)
            .or_default()
            .clone_arc()
    }

    pub async fn singular_attestations_by_epoch(&self, epoch: Epoch) -> Vec<Arc<Attestation<P>>> {
        self.singular_attestations
            .read()
            .await
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|(_, attestations)| async { attestations.read().await.clone() })
            .collect::<FuturesUnordered<_>>()
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
