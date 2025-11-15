use std::sync::Arc;

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use logging::{debug_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use types::{
    combined::BeaconState,
    gloas::containers::{PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage},
    phase0::primitives::Slot,
    preset::Preset,
};

use crate::{misc::PoolTask, payload_attestation_agg_pool::pool::Pool};

pub struct HandleSlotTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub slot: Slot,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset> PoolTask for HandleSlotTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            slot,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.payload_att_pool_handle_slot_times.start_timer());

        pool.on_slot(slot, metrics).await;

        Ok(())
    }
}

pub struct InsertPayloadAttestationTask<P: Preset, W: Wait> {
    pub wait_group: W,
    pub controller: ApiController<P, W>,
    pub pool: Arc<Pool<P>>,
    pub payload_attestation: Arc<PayloadAttestationMessage>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for InsertPayloadAttestationTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            wait_group,
            controller,
            pool,
            payload_attestation,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.payload_att_pool_insert_message_times.start_timer());

        let beacon_state = match controller.preprocessed_state_at_current_slot() {
            Ok(beacon_state) => beacon_state,
            Err(error) => {
                debug_with_peers!("cannot process payload attestation message: {error:?}");
                return Ok(());
            }
        };

        let data = payload_attestation.data;

        if let Err(error) = pool
            .aggregate_messages(data, vec![*payload_attestation], beacon_state)
            .await
        {
            warn_with_peers!(
                "failed to aggregate payload attestaton message from validator {}: {error}",
                payload_attestation.validator_index
            );
        }

        pool.add_payload_attestation_messages(data, vec![*payload_attestation])
            .await;

        drop(wait_group);

        Ok(())
    }
}

pub struct AggregateOwnMessagesTask<P: Preset, W> {
    pub wait_group: W,
    pub pool: Arc<Pool<P>>,
    pub data: PayloadAttestationData,
    pub messages: Vec<PayloadAttestationMessage>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Send + 'static> PoolTask for AggregateOwnMessagesTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            wait_group,
            pool,
            data,
            messages,
            beacon_state,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .payload_att_pool_aggregate_own_messages_times
                .start_timer()
        });

        if let Err(error) = pool
            .aggregate_messages(data, messages.iter().copied(), beacon_state)
            .await
        {
            warn_with_peers!("failed to aggregate own payload attestaton messages: {error}",);
        }

        pool.add_payload_attestation_messages(data, messages).await;

        drop(wait_group);

        Ok(())
    }
}

pub struct AggregatePayloadAttestationsTask<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub pool: Arc<Pool<P>>,
}

impl<P: Preset, W: Wait> PoolTask for AggregatePayloadAttestationsTask<P, W> {
    type Output = ContiguousList<PayloadAttestation<P>, P::MaxPayloadAttestation>;

    async fn run(self) -> Result<Self::Output> {
        let Self { controller, pool } = self;

        let slot = controller.slot();

        pool.aggregate_payload_attestations(slot).await
    }
}
