use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Result};
use bls::traits::Signature as _;
use helper_functions::accessors;
use itertools::Itertools as _;
use log::debug;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tokio::sync::RwLock;
use types::{
    altair::{
        containers::{ContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::BeaconState,
    phase0::primitives::{Slot, ValidatorIndex, H256},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::sync_committee_agg_pool::types::{
    Aggregate, AggregateMap, ContributionData, SyncCommitteeMessageMap, SyncCommitteeMessageSet,
};

pub struct Pool<P: Preset> {
    aggregates: RwLock<AggregateMap<P>>,
    aggregator_contributions: RwLock<HashSet<(ValidatorIndex, Slot, SubcommitteeIndex)>>,
    sync_committee_messages: RwLock<SyncCommitteeMessageMap>,
}

impl<P: Preset> Pool<P> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            aggregates: RwLock::new(AggregateMap::new()),
            aggregator_contributions: RwLock::new(HashSet::new()),
            sync_committee_messages: RwLock::new(SyncCommitteeMessageMap::new()),
        }
    }

    // Messages and contributions should be discarded together.
    // Discarding them separately has led to a bug.
    pub async fn on_slot(&self, slot: Slot, metrics: Option<Arc<Metrics>>) {
        if let Some(metrics) = metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "aggregates",
                self.aggregates.read().await.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "aggregator_contributions",
                self.aggregator_contributions.read().await.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "sync_committee_messages",
                self.sync_committee_messages.read().await.len(),
            );
        }

        if let Some(previous_slot) = slot.checked_sub(1) {
            self.aggregates
                .write()
                .await
                .retain(|data, _| data.slot >= previous_slot);

            self.aggregator_contributions
                .write()
                .await
                .retain(|(_, slot, _)| *slot >= previous_slot);

            self.sync_committee_messages
                .write()
                .await
                .retain(|data, _| data.slot >= previous_slot);
        }
    }

    pub async fn add_sync_committee_contribution(
        &self,
        aggregator_index: ValidatorIndex,
        contribution: SyncCommitteeContribution<P>,
        beacon_state: &BeaconState<P>,
    ) -> Result<()> {
        let contribution_data = ContributionData::from(contribution);

        let SyncCommitteeContribution {
            subcommittee_index,
            aggregation_bits,
            signature,
            ..
        } = contribution;

        self.aggregator_contributions.write().await.insert((
            aggregator_index,
            contribution.slot,
            contribution.subcommittee_index,
        ));

        let state = beacon_state
            .post_altair()
            .ok_or_else(|| anyhow!("Pool::aggregate_messages called with a Phase 0 BeaconState"))?;

        let subcommittee_pubkeys =
            accessors::get_sync_subcommittee_pubkeys(state, subcommittee_index)?;

        let mut aggregate = Aggregate {
            aggregation_bits,
            signature: signature.try_into()?,
        };

        let messages = self.sync_committee_messages(contribution_data).await;

        for message in messages.read().await.iter() {
            let validator_pubkey = &beacon_state
                .validators()
                .get(message.validator_index)?
                .pubkey;

            let positions_in_subcommittee = subcommittee_pubkeys
                .iter()
                .enumerate()
                .filter(|(_, pubkey)| *pubkey == validator_pubkey)
                .map(|(index, _)| index)
                .collect_vec();

            for position_in_subcommittee in positions_in_subcommittee {
                if aggregate.aggregation_bits[position_in_subcommittee] {
                    continue;
                }

                aggregate
                    .aggregation_bits
                    .set(position_in_subcommittee, true);

                aggregate
                    .signature
                    .aggregate_in_place(message.signature.try_into()?);
            }
        }

        self.aggregates(contribution_data)
            .await
            .write()
            .await
            .push(aggregate);

        Ok(())
    }

    pub async fn add_sync_committee_messages(
        &self,
        contribution_data: ContributionData,
        messages: impl IntoIterator<Item = SyncCommitteeMessage> + Send,
    ) {
        let pool_messages = self.sync_committee_messages(contribution_data).await;
        let mut pool_messages = pool_messages.write().await;

        for message in messages {
            pool_messages.insert(message);
        }
    }

    pub async fn aggregate_messages(
        &self,
        contribution_data: ContributionData,
        messages: impl IntoIterator<Item = SyncCommitteeMessage> + Send,
        beacon_state: &BeaconState<P>,
    ) -> Result<()> {
        let state = beacon_state
            .post_altair()
            .ok_or_else(|| anyhow!("Pool::aggregate_messages called with a Phase 0 BeaconState"))?;

        let subcommittee_pubkeys =
            accessors::get_sync_subcommittee_pubkeys(state, contribution_data.subcommittee_index)?;

        let pool_aggregates = self.aggregates(contribution_data).await;
        let mut pool_aggregates = pool_aggregates.write().await;

        if pool_aggregates.is_empty() {
            pool_aggregates.push(Aggregate::default());
        }

        for message in messages {
            let validator_pubkey = &beacon_state
                .validators()
                .get(message.validator_index)?
                .pubkey;

            let positions_in_subcommittee = subcommittee_pubkeys
                .iter()
                .enumerate()
                .filter(|(_, pubkey)| *pubkey == validator_pubkey)
                .map(|(index, _)| index)
                .collect_vec();

            for position_in_subcommittee in positions_in_subcommittee {
                for aggregate in pool_aggregates.iter_mut() {
                    if aggregate.aggregation_bits[position_in_subcommittee] {
                        debug!(
                            "duplicate sync committee message from the same validator \
                            (message: {message:?}, position_in_subcommittee: {position_in_subcommittee})"
                        );

                        continue;
                    }

                    aggregate
                        .aggregation_bits
                        .set(position_in_subcommittee, true);

                    aggregate
                        .signature
                        .aggregate_in_place(message.signature.try_into()?);
                }
            }
        }

        Ok(())
    }

    pub async fn best_subcommittee_contribution(
        &self,
        slot: Slot,
        beacon_block_root: H256,
        subcommittee_index: SubcommitteeIndex,
    ) -> SyncCommitteeContribution<P> {
        let data = ContributionData {
            slot,
            beacon_block_root,
            subcommittee_index,
        };

        let aggregate = self
            .aggregates(data)
            .await
            .read()
            .await
            .iter()
            .max_by_key(|aggregate| aggregate.aggregation_bits.count_ones())
            .copied()
            .unwrap_or_default();

        SyncCommitteeContribution {
            slot,
            beacon_block_root,
            subcommittee_index,
            aggregation_bits: aggregate.aggregation_bits,
            signature: aggregate.signature.into(),
        }
    }

    pub async fn contribution_and_proof_exists(
        &self,
        contribution_and_proof: ContributionAndProof<P>,
    ) -> bool {
        let ContributionAndProof {
            aggregator_index,
            contribution,
            ..
        } = contribution_and_proof;

        self.aggregator_contributions.read().await.contains(&(
            aggregator_index,
            contribution.slot,
            contribution.subcommittee_index,
        ))
    }

    pub async fn is_subset(&self, contribution: SyncCommitteeContribution<P>) -> bool {
        let contribution_data = ContributionData::from(contribution);

        self.aggregates(contribution_data)
            .await
            .read()
            .await
            .iter()
            .any(|aggregate| {
                contribution
                    .aggregation_bits
                    .is_subset_of(&aggregate.aggregation_bits)
            })
    }

    pub async fn sync_committee_message_exists(
        &self,
        data: ContributionData,
        message: SyncCommitteeMessage,
    ) -> bool {
        if let Some(messages) = self.sync_committee_messages.read().await.get(&data) {
            return messages.read().await.contains(&message);
        }

        false
    }

    async fn aggregates(&self, data: ContributionData) -> Arc<RwLock<Vec<Aggregate<P>>>> {
        self.aggregates
            .write()
            .await
            .entry(data)
            .or_default()
            .clone_arc()
    }

    async fn sync_committee_messages(
        &self,
        data: ContributionData,
    ) -> Arc<RwLock<SyncCommitteeMessageSet>> {
        self.sync_committee_messages
            .write()
            .await
            .entry(data)
            .or_default()
            .clone_arc()
    }
}
