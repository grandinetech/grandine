use std::{collections::HashSet, sync::Arc};

use anyhow::Error as AnyhowError;
use axum::{
    extract::{DefaultBodyLimit, FromRef, State},
    routing::{get, post},
    Json, Router,
};
use block_producer::BlockProducer;
use bls::PublicKeyBytes;
use eth1_api::{ApiController, Eth1Api};
use features::Feature;
use fork_choice_control::{EventChannels, Wait};
use futures::channel::mpsc::UnboundedSender;
use genesis::AnchorCheckpointProvider;
use liveness_tracker::ApiToLiveness;
use operation_pools::{AttestationAggPool, BlsToExecutionChangePool, SyncCommitteeAggPool};
use p2p::{ApiToP2p, NetworkConfig, ToSubnetService};
use prometheus_metrics::Metrics;
use serde_qs::axum::QsQuery;
use std_ext::ArcExt as _;
use types::{config::Config as ChainConfig, preset::Preset};
use validator::{ApiToValidator, ValidatorConfig};

use crate::{
    error::Error,
    gui, middleware,
    misc::SyncedStatus,
    standard::{
        beacon_events, beacon_heads, beacon_state, blinded_block, blob_sidecars, block,
        block_attestations, block_attestations_v2, block_headers, block_id_headers, block_rewards,
        block_root, config_spec, debug_beacon_data_column_sidecars, debug_fork_choice,
        deposit_contract, expected_withdrawals, fork_schedule, genesis,
        get_state_validator_balances, get_state_validators, node_health, node_identity, node_peer,
        node_peer_count, node_peers, node_syncing_status, node_version, pool_attestations,
        pool_attestations_v2, pool_attester_slashings, pool_attester_slashings_v2,
        pool_bls_to_execution_changes, pool_proposer_slashings, pool_voluntary_exits,
        post_state_validator_balances, post_state_validators, publish_blinded_block,
        publish_blinded_block_v2, publish_block, publish_block_v2, state_committees,
        state_finality_checkpoints, state_fork, state_pending_consolidations,
        state_pending_deposits, state_pending_partial_withdrawals, state_randao, state_root,
        state_sync_committees, state_validator, state_validator_identities,
        submit_pool_attestations, submit_pool_attestations_v2, submit_pool_attester_slashing,
        submit_pool_attester_slashing_v2, submit_pool_bls_to_execution_change,
        submit_pool_proposer_slashing, submit_pool_sync_committees, submit_pool_voluntary_exit,
        sync_committee_rewards, validator_aggregate_attestation,
        validator_aggregate_attestation_v2, validator_attestation_data, validator_attester_duties,
        validator_beacon_committee_selections, validator_blinded_block, validator_block,
        validator_block_v3, validator_liveness, validator_prepare_beacon_proposer,
        validator_proposer_duties, validator_publish_aggregate_and_proofs,
        validator_publish_contributions_and_proofs, validator_register_validator,
        validator_subscribe_to_beacon_committee, validator_subscribe_to_sync_committees,
        validator_sync_committee_contribution, validator_sync_committee_duties,
        validator_sync_committee_selections,
    },
};

#[cfg(test)]
use ::{
    crossbeam_utils::sync::WaitGroup,
    fork_choice_control::{P2pMessage, SyncMessage},
    operation_pools::PoolToP2pMessage,
    p2p::ValidatorToP2p,
};

#[cfg(test)]
use crate::{misc::SpyReceiver, test_endpoints};

#[derive(Clone)]
pub struct NormalState<P: Preset, W: Wait> {
    pub chain_config: Arc<ChainConfig>,
    pub block_producer: Arc<BlockProducer<P, W>>,
    pub controller: ApiController<P, W>,
    pub anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    pub eth1_api: Arc<Eth1Api>,
    pub validator_keys: Arc<HashSet<PublicKeyBytes>>,
    pub validator_config: Arc<ValidatorConfig>,
    pub metrics: Option<Arc<Metrics>>,
    pub network_config: Arc<NetworkConfig>,
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    pub is_synced: Arc<SyncedStatus>,
    pub event_channels: Arc<EventChannels<P>>,
    pub api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    pub api_to_p2p_tx: UnboundedSender<ApiToP2p<P>>,
    pub api_to_validator_tx: UnboundedSender<ApiToValidator<P>>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
}

// The `FromRef` derive macro cannot handle type parameters as of `axum` version 0.6.7.

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<ChainConfig> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.chain_config.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<BlockProducer<P, W>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.block_producer.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for ApiController<P, W> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.controller.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for AnchorCheckpointProvider<P> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.anchor_checkpoint_provider.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<Eth1Api> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.eth1_api.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<HashSet<PublicKeyBytes>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.validator_keys.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<ValidatorConfig> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.validator_config.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<NetworkConfig> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.network_config.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<AttestationAggPool<P, W>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.attestation_agg_pool.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<SyncCommitteeAggPool<P, W>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.sync_committee_agg_pool.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<BlsToExecutionChangePool> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.bls_to_execution_change_pool.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<SyncedStatus> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.is_synced.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Arc<EventChannels<P>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.event_channels.clone_arc()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Option<UnboundedSender<ApiToLiveness>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.api_to_liveness_tx.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for UnboundedSender<ApiToP2p<P>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.api_to_p2p_tx.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for UnboundedSender<ApiToValidator<P>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.api_to_validator_tx.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for UnboundedSender<ToSubnetService> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.subnet_service_tx.clone()
    }
}

impl<P: Preset, W: Wait> FromRef<NormalState<P, W>> for Option<Arc<Metrics>> {
    fn from_ref(state: &NormalState<P, W>) -> Self {
        state.metrics.clone()
    }
}

#[expect(clippy::struct_field_names)]
#[cfg(test)]
#[derive(Clone)]
pub struct TestState<P: Preset> {
    pub api_to_p2p_rx: SpyReceiver<ApiToP2p<P>>,
    pub fc_to_p2p_rx: SpyReceiver<P2pMessage<P>>,
    pub fc_to_sync_rx: SpyReceiver<SyncMessage<P>>,
    pub pool_to_p2p_rx: SpyReceiver<PoolToP2pMessage>,
    pub validator_to_p2p_rx: SpyReceiver<ValidatorToP2p<P>>,
}

pub fn normal_routes<P: Preset, W: Wait>(state: NormalState<P, W>) -> Router {
    gui_routes()
        .merge(eth_v1_beacon_routes())
        .merge(eth_v2_beacon_routes())
        .merge(eth_v1_builder_routes())
        .merge(eth_v1_config_routes())
        .merge(eth_v1_debug_routes())
        .merge(eth_v2_debug_routes())
        .route("/eth/v1/events", get(beacon_events))
        .merge(eth_v1_node_routes())
        .merge(eth_v1_validator_routes(state.clone()))
        .merge(eth_v1_validator_routes_no_sync_check())
        .merge(eth_v2_validator_routes(state.clone()))
        .merge(eth_v3_validator_routes_no_sync_check())
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

fn gui_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route(
            "/beacon/head",
            get(|extracted| async {
                let State(controller) = extracted;
                Json(gui::get_beacon_head(&controller))
            }),
        )
        .route(
            "/validator/statistics",
            get(|extracted| async {
                let (
                    State(controller),
                    State(anchor_checkpoint_provider),
                    State::<Arc<_>>(validator_keys),
                    State(api_to_validator_tx),
                    QsQuery(query),
                ) = extracted;

                gui::get_validator_statistics(
                    &controller,
                    anchor_checkpoint_provider,
                    &validator_keys,
                    api_to_validator_tx,
                    query,
                )
                .await
                .map(Json)
                .map_err(Error::Internal)
            })
            .route_layer(axum::middleware::map_request_with_state(
                Feature::ServeCostlyEndpoints,
                middleware::feature_is_enabled,
            )),
        )
        .route(
            "/validator/registered",
            get(|extracted| async {
                let (State(controller), State(api_to_validator_tx)) = extracted;

                gui::get_validator_registered(&controller, api_to_validator_tx)
                    .await
                    .map(Json)
                    .map_err(Error::Internal)
            })
            .route_layer(axum::middleware::map_request_with_state(
                Feature::ServeCostlyEndpoints,
                middleware::feature_is_enabled,
            )),
        )
        .route(
            "/validator/owned",
            get(|extracted| async {
                let (State(controller), State::<Arc<_>>(validator_keys)) = extracted;

                Json(gui::get_validator_owned(&controller, &validator_keys))
            })
            .route_layer(axum::middleware::map_request_with_state(
                Feature::ServeCostlyEndpoints,
                middleware::feature_is_enabled,
            )),
        )
        .route(
            "/system/stats",
            get(|extracted| async {
                let State::<Option<Arc<Metrics>>>(metrics) = extracted;

                metrics
                    .map(|metrics| metrics.system_stats())
                    .map(Json)
                    .ok_or_else(|| AnyhowError::msg("metrics service is not configured"))
                    .map_err(Error::Internal)
            })
            .route_layer(axum::middleware::map_request_with_state(
                Feature::ServeLeakyEndpoints,
                middleware::feature_is_enabled,
            )),
        )
}

// TODO(Grandine Team): The standard routes should be restricted with `Feature`s too. The easiest way
//                      to do this would be to add `Feature`s corresponding to groups of endpoints
//                      (`beacon`, `config`, `debug`, etc.). The same could be done with `gui`, but
//                      `PATCH /features` requires special attention because it's more dangerous.

#[expect(clippy::too_many_lines)]
fn eth_v1_beacon_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    let state_routes = Router::new()
        .route("/eth/v1/beacon/states/{state_id}/root", get(state_root))
        .route("/eth/v1/beacon/states/{state_id}/fork", get(state_fork))
        .route(
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            get(state_finality_checkpoints),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators",
            get(get_state_validators),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators",
            post(post_state_validators),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validator_identities",
            post(state_validator_identities),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
            get(state_validator),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validator_balances",
            get(get_state_validator_balances).post(post_state_validator_balances),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/committees",
            get(state_committees),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/sync_committees",
            get(state_sync_committees),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_consolidations",
            get(state_pending_consolidations),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_deposits",
            get(state_pending_deposits),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/pending_partial_withdrawals",
            get(state_pending_partial_withdrawals),
        )
        .route("/eth/v1/beacon/states/{state_id}/randao", get(state_randao));

    let header_routes = Router::new()
        .route("/eth/v1/beacon/headers", get(block_headers))
        .route("/eth/v1/beacon/headers/{block_id}", get(block_id_headers));

    let block_v1_routes = Router::new()
        .route("/eth/v1/beacon/blocks/{block_id}/root", get(block_root))
        .route(
            "/eth/v1/beacon/blocks/{block_id}/attestations",
            get(block_attestations),
        )
        .route("/eth/v1/beacon/blocks", post(publish_block));

    let block_v2_routes = Router::new().route(
        "/eth/v2/beacon/blocks/{block_id}/attestations",
        get(block_attestations_v2),
    );

    let pool_v1_routes = Router::new()
        .route(
            "/eth/v1/beacon/pool/attestations",
            get(pool_attestations).post(submit_pool_attestations),
        )
        .route(
            "/eth/v1/beacon/pool/bls_to_execution_changes",
            get(pool_bls_to_execution_changes).post(submit_pool_bls_to_execution_change),
        )
        .route(
            "/eth/v1/beacon/pool/voluntary_exits",
            get(pool_voluntary_exits).post(submit_pool_voluntary_exit),
        )
        .route(
            "/eth/v1/beacon/pool/attester_slashings",
            get(pool_attester_slashings).post(submit_pool_attester_slashing),
        )
        .route(
            "/eth/v1/beacon/pool/proposer_slashings",
            get(pool_proposer_slashings).post(submit_pool_proposer_slashing),
        )
        .route(
            "/eth/v1/beacon/pool/sync_committees",
            post(submit_pool_sync_committees),
        );

    let pool_v2_routes = Router::new()
        .route(
            "/eth/v2/beacon/pool/attestations",
            get(pool_attestations_v2).post(submit_pool_attestations_v2),
        )
        .route(
            "/eth/v2/beacon/pool/attester_slashings",
            get(pool_attester_slashings_v2).post(submit_pool_attester_slashing_v2),
        );

    let reward_routes = Router::new()
        .route(
            "/eth/v1/beacon/rewards/blocks/{block_id}",
            get(block_rewards),
        )
        .route(
            "/eth/v1/beacon/rewards/sync_committee/{block_id}",
            post(sync_committee_rewards),
        );

    Router::new()
        .route(
            "/eth/v1/beacon/blinded_blocks/{block_id}",
            get(blinded_block),
        )
        .route("/eth/v1/beacon/blinded_blocks", post(publish_blinded_block))
        .route(
            "/eth/v1/beacon/blob_sidecars/{block_id}",
            get(blob_sidecars),
        )
        .route("/eth/v1/beacon/genesis", get(genesis))
        .merge(state_routes)
        .merge(header_routes)
        .merge(block_v1_routes)
        .merge(block_v2_routes)
        .merge(pool_v1_routes)
        .merge(pool_v2_routes)
        .merge(reward_routes)
}

fn eth_v2_beacon_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route("/eth/v2/beacon/blocks/{block_id}", get(block))
        .route("/eth/v2/beacon/blocks", post(publish_block_v2))
        .route(
            "/eth/v2/beacon/blinded_blocks",
            post(publish_blinded_block_v2),
        )
}

fn eth_v1_builder_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new().route(
        "/eth/v1/builder/states/{state_id}/expected_withdrawals",
        get(expected_withdrawals),
    )
}

fn eth_v1_config_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route("/eth/v1/config/fork_schedule", get(fork_schedule::<P>))
        .route("/eth/v1/config/spec", get(config_spec::<P>))
        .route("/eth/v1/config/deposit_contract", get(deposit_contract))
}

fn eth_v1_debug_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route("/eth/v1/debug/fork_choice", get(debug_fork_choice))
        .route(
            "/eth/v1/debug/beacon/data_column_sidecars/{block_id}",
            get(debug_beacon_data_column_sidecars),
        )
}

fn eth_v2_debug_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route("/eth/v2/debug/beacon/states/{state_id}", get(beacon_state))
        .route("/eth/v2/debug/beacon/heads", get(beacon_heads))
}

fn eth_v1_node_routes<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route("/eth/v1/node/identity", get(node_identity))
        .route("/eth/v1/node/peers", get(node_peers))
        .route("/eth/v1/node/peers/{peer_id}", get(node_peer))
        .route("/eth/v1/node/peer_count", get(node_peer_count))
        .route("/eth/v1/node/version", get(node_version))
        .route("/eth/v1/node/syncing", get(node_syncing_status))
        .route("/eth/v1/node/health", get(node_health))
}

fn eth_v1_validator_routes<P: Preset, W: Wait>(
    state: NormalState<P, W>,
) -> Router<NormalState<P, W>> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(validator_attester_duties),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            post(validator_sync_committee_duties),
        )
        .route(
            "/eth/v1/validator/blinded_blocks/{slot}",
            get(validator_blinded_block),
        )
        .route(
            "/eth/v1/validator/attestation_data",
            get(validator_attestation_data),
        )
        .route(
            "/eth/v1/validator/aggregate_attestation",
            get(validator_aggregate_attestation),
        )
        .route(
            "/eth/v1/validator/aggregate_and_proofs",
            post(validator_publish_aggregate_and_proofs),
        )
        .route(
            "/eth/v1/validator/beacon_committee_subscriptions",
            post(validator_subscribe_to_beacon_committee),
        )
        .route(
            "/eth/v1/validator/sync_committee_subscriptions",
            post(validator_subscribe_to_sync_committees),
        )
        .route(
            "/eth/v1/validator/sync_committee_contribution",
            get(validator_sync_committee_contribution),
        )
        .route(
            "/eth/v1/validator/contribution_and_proofs",
            post(validator_publish_contributions_and_proofs),
        )
        .route(
            "/eth/v1/validator/register_validator",
            post(validator_register_validator),
        )
        .route(
            "/eth/v1/validator/liveness/{epoch}",
            post(validator_liveness),
        )
        .route(
            "/eth/v1/validator/beacon_committee_selections",
            post(validator_beacon_committee_selections),
        )
        .route(
            "/eth/v1/validator/sync_committee_selections",
            post(validator_sync_committee_selections),
        )
        .layer(axum::middleware::map_request_with_state(
            state,
            middleware::is_synced,
        ))
}

fn eth_v1_validator_routes_no_sync_check<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(validator_proposer_duties),
        )
        .route(
            "/eth/v1/validator/prepare_beacon_proposer",
            post(validator_prepare_beacon_proposer),
        )
}

fn eth_v2_validator_routes<P: Preset, W: Wait>(
    state: NormalState<P, W>,
) -> Router<NormalState<P, W>> {
    Router::new()
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(validator_aggregate_attestation_v2),
        )
        .route(
            "/eth/v2/validator/aggregate_and_proofs",
            post(validator_publish_aggregate_and_proofs),
        )
        .route("/eth/v2/validator/blocks/{slot}", get(validator_block))
        .layer(axum::middleware::map_request_with_state(
            state,
            middleware::is_synced,
        ))
}

fn eth_v3_validator_routes_no_sync_check<P: Preset, W: Wait>() -> Router<NormalState<P, W>> {
    Router::new().route("/eth/v3/validator/blocks/{slot}", get(validator_block_v3))
}

#[cfg(test)]
pub fn test_routes<P: Preset>(
    normal_state: NormalState<P, WaitGroup>,
    test_state: TestState<P>,
) -> Router {
    Router::new()
        .route("/test/tick", post(test_endpoints::post_tick))
        .route(
            "/test/payload_status",
            post(test_endpoints::post_payload_status),
        )
        .with_state(normal_state)
        .route(
            "/test/take_messages",
            post(test_endpoints::post_take_messages),
        )
        .with_state(test_state)
}
