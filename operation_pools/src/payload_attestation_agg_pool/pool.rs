use std::sync::Arc;

use anyhow::{anyhow, Result};
use bls::traits::Signature as _;
use helper_functions::accessors;
use itertools::Itertools as _;
use logging::debug_with_peers;
use prometheus_metrics::Metrics;
use std_ext::ArcExt as _;
use tokio::sync::RwLock;
use types::{
    combined::BeaconState,
    gloas::containers::{PayloadAttestationData, PayloadAttestationMessage},
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::payload_attestation_agg_pool::types::{
    Aggregate, AggregateMap, PayloadAttestationMap, PayloadAttestationSet, PtcMembersMap,
};

pub struct Pool<P: Preset> {
    aggregates: RwLock<AggregateMap<P>>,
    ptc_members: RwLock<PtcMembersMap>,
    payload_attestation_messages: RwLock<PayloadAttestationMap>,
}

impl<P: Preset> Pool<P> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            aggregates: RwLock::new(AggregateMap::new()),
            ptc_members: RwLock::new(PtcMembersMap::new()),
            payload_attestation_messages: RwLock::new(PayloadAttestationMap::new()),
        }
    }

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
                "payload_attestation_messages",
                self.payload_attestation_messages.read().await.len(),
            );
        }

        if let Some(previous_slot) = slot.checked_sub(1) {
            self.aggregates
                .write()
                .await
                .retain(|data, _| data.slot >= previous_slot);

            self.ptc_members
                .write()
                .await
                .retain(|slot, _| *slot >= previous_slot);

            self.payload_attestation_messages
                .write()
                .await
                .retain(|data, _| data.slot >= previous_slot);
        }
    }

    pub async fn add_payload_attestation_messages(
        &self,
        data: PayloadAttestationData,
        messages: impl IntoIterator<Item = PayloadAttestationMessage> + Send,
    ) {
        let pool_messages = self.payload_attestation_messages(data).await;
        let mut pool_messages = pool_messages.write().await;
        pool_messages.extend(messages);
    }

    pub async fn aggregate_messages(
        &self,
        data: PayloadAttestationData,
        messages: impl IntoIterator<Item = PayloadAttestationMessage> + Send,
        beacon_state: Arc<BeaconState<P>>,
    ) -> Result<()> {
        if !beacon_state.is_post_gloas() {
            return Err(anyhow!(
                "Pool::aggregate_messages called with a pre-Gloas BeaconState"
            ));
        }

        let ptc_members = self
            .get_or_init_ptc_at_slot(&beacon_state, data.slot)
            .await?;

        let pool_aggregate = self.pool_aggregate(data).await;
        let mut pool_aggregate = pool_aggregate.write().await;

        for message in messages {
            let positions_in_committee = ptc_members
                .iter()
                .enumerate()
                .filter(|(_, validator_index)| **validator_index == message.validator_index)
                .map(|(index, _)| index)
                .collect_vec();

            for position in positions_in_committee {
                if pool_aggregate.aggregation_bits[position] {
                    debug_with_peers!(
                        "duplicate payload attestation message from the same validator \
                        (message: {message:?}, position_in_committee: {position})",
                    );

                    continue;
                }

                pool_aggregate.aggregation_bits.set(position, true);

                pool_aggregate
                    .signature
                    .aggregate_in_place(message.signature.try_into()?);
            }
        }

        Ok(())
    }

    async fn get_or_init_ptc_at_slot(
        &self,
        beacon_state: &BeaconState<P>,
        slot: Slot,
    ) -> Result<Vec<ValidatorIndex>> {
        if let Some(members) = self.ptc_members.read().await.get(&slot) {
            return Ok(members.read().await.to_vec());
        }

        let ptc_members = self
            .ptc_members
            .write()
            .await
            .entry(slot)
            .or_default()
            .clone_arc();
        let mut ptc_members = ptc_members.write().await;

        *ptc_members = match accessors::ptc_for_slot(beacon_state, slot) {
            Ok(members) => members.into_iter().collect_vec(),
            Err(error) => {
                return Err(anyhow!(
                    "failed to get PTC members at slot: {slot}: {error:?}"
                ));
            }
        };

        Ok(ptc_members.to_vec())
    }

    async fn pool_aggregate(&self, data: PayloadAttestationData) -> Arc<RwLock<Aggregate<P>>> {
        self.aggregates
            .write()
            .await
            .entry(data)
            .or_default()
            .clone_arc()
    }

    async fn payload_attestation_messages(
        &self,
        data: PayloadAttestationData,
    ) -> Arc<RwLock<PayloadAttestationSet>> {
        self.payload_attestation_messages
            .write()
            .await
            .entry(data)
            .or_default()
            .clone_arc()
    }
}
