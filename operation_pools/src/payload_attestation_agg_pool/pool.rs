use std::{collections::BTreeMap, sync::Arc};

use anyhow::{anyhow, Result};
use bls::traits::Signature as _;
use futures::stream::{FuturesUnordered, StreamExt as _};
use helper_functions::accessors;
use itertools::Itertools as _;
use logging::debug_with_peers;
use prometheus_metrics::Metrics;
use ssz::{ContiguousList, ContiguousVector};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tokio::sync::RwLock;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    combined::BeaconState,
    gloas::containers::{PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage},
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::payload_attestation_agg_pool::types::{
    Aggregate, AggregateMap, PayloadAttestationMap, PayloadAttestationSet,
};

pub struct Pool<P: Preset> {
    aggregates: RwLock<AggregateMap<P>>,
    ptc_members: RwLock<BTreeMap<Slot, ContiguousVector<ValidatorIndex, P::PtcSize>>>,
    payload_attestation_messages: RwLock<PayloadAttestationMap>,
}

impl<P: Preset> Pool<P> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            aggregates: RwLock::default(),
            ptc_members: RwLock::default(),
            payload_attestation_messages: RwLock::default(),
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

    pub async fn aggregate_payload_attestations(
        &self,
        slot: Slot,
    ) -> Result<ContiguousList<PayloadAttestation<P>, P::MaxPayloadAttestation>> {
        self.aggregates
            .read()
            .await
            .iter()
            .map(|(data, aggregate)| async {
                if data.slot == slot {
                    let Aggregate {
                        aggregation_bits,
                        signature,
                    } = *aggregate.read().await;

                    Some(PayloadAttestation {
                        aggregation_bits,
                        data: *data,
                        signature: signature.into(),
                    })
                } else {
                    None
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .take(P::MaxPayloadAttestation::USIZE)
            .pipe(ContiguousList::try_from_iter)
            .map_err(Into::into)
    }

    async fn get_or_init_ptc_at_slot(
        &self,
        beacon_state: &BeaconState<P>,
        slot: Slot,
    ) -> Result<ContiguousVector<ValidatorIndex, P::PtcSize>> {
        if let Some(members) = self.ptc_members.read().await.get(&slot) {
            return Ok(members.clone());
        }

        let mut ptc_members_map = self.ptc_members.write().await;
        let ptc_members = accessors::ptc_for_slot(beacon_state, slot)?;
        ptc_members_map.insert(slot, ptc_members.clone());

        Ok(ptc_members)
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
