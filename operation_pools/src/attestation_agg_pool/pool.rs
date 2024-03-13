use core::ops::RangeBounds;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::DerefMut,
    sync::Arc,
};

use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt as _};
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use ssz::{ContiguousList, SszHash};
use std_ext::ArcExt as _;
use tokio::sync::{Mutex, RwLock};
use types::{
    phase0::{
        consts::GENESIS_EPOCH,
        containers::{Attestation, AttestationData},
        primitives::{Epoch, Slot, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::BeaconState,
};

use crate::attestation_agg_pool::{
    max_clique::MaxClique,
    types::{Aggregate, AggregateMap, AttestationMap, AttestationSet},
};

#[allow(type_alias_bounds)]
type AttestationsWithSlot<P: Preset> = (ContiguousList<Attestation<P>, P::MaxAttestations>, Slot);

#[derive(Default)]
pub struct Pool<P: Preset> {
    aggregates: RwLock<BTreeMap<Epoch, AggregateMap<P>>>,
    data_root_to_data_map: RwLock<BTreeMap<Epoch, HashMap<H256, AttestationData>>>,
    // The type of the inner map does not affect the result of attestation packing,
    // though that may change if the packers are redesigned again.
    singular_attestations: RwLock<BTreeMap<Epoch, AttestationMap<P>>>,
    best_proposable_attestations: Mutex<AttestationsWithSlot<P>>,
    proposer_indices: RwLock<BTreeMap<Slot, ValidatorIndex>>,
    registered_validator_indices: RwLock<HashSet<ValidatorIndex>>,
}

impl<P: Preset> Pool<P> {
    pub async fn on_slot(&self, slot: Slot) {
        if misc::is_epoch_start::<P>(slot) {
            let current_epoch = misc::compute_epoch_at_slot::<P>(slot);
            let previous_epoch = current_epoch.saturating_sub(1).max(GENESIS_EPOCH);

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

    pub async fn get_maximally_aggregated_attestations_by_epoch(
        &self,
        epoch: Epoch,
    ) -> Vec<Attestation<P>> {
        let mut aggregates = self.aggregate_attestations_by_epoch(epoch).await;

        let mut singular_arc = self.singular_attestations_by_epoch(epoch).await;

        let mut singular = Vec::new();
        for arc_attestation in singular_arc {
            let aggregation_bits = arc_attestation.aggregation_bits.clone();
            let data = arc_attestation.data;
            let signature = arc_attestation.signature;
            singular.push(Attestation {
                aggregation_bits,
                data,
                signature,
            });
        }

        aggregates.append(&mut singular);

        let max_clique = MaxClique::new();

        let maximal_cliques = max_clique.find_maximal_attestation_cliques(aggregates.clone());
        aggregates.clone()
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

        (slot == *prepared_for_slot)
            .then(|| attestations.clone())
            .unwrap_or_default()
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
                    accessors::get_beacon_proposer_index_at_slot(state, slot)?,
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

    pub async fn set_best_proposable_attestations(
        &self,
        attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
        prepared_for_slot: Slot,
    ) {
        *self.best_proposable_attestations.lock().await = (attestations, prepared_for_slot);
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
