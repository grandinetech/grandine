use core::time::Duration;
use std::sync::Arc;

use anyhow::Result;
use log::warn;
use once_cell::sync::OnceCell;
use prometheus::{
    histogram_opts, opts, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec,
};
use types::phase0::primitives::{Epoch, Gwei, Slot, UnixSeconds};

use crate::helpers;

pub static METRICS: OnceCell<Arc<Metrics>> = OnceCell::new();

#[derive(Debug)]
pub struct Metrics {
    // Overview
    live: IntGauge,

    // System stats
    cores: IntGauge,
    disk_usage: IntGauge,
    used_memory: IntGauge,
    rx_bytes: IntGauge,
    tx_bytes: IntGauge,
    system_cpu_percentage: Gauge,
    system_used_memory: IntGauge,
    system_total_memory: IntGauge,
    total_cpu_percentage: Gauge,

    // Collection Lengths
    collection_lengths: IntGaugeVec,

    // HTTP API metrics
    http_api_response_times: HistogramVec,

    // Validator API metrics
    validator_api_response_times: HistogramVec,

    // Dedicated Executor
    pub dedicated_executor_task_times: Histogram,
    dedicated_executor_task_count: IntGauge,
    dedicated_executor_thread_count: IntGauge,

    // Network / Gossip stats
    gossip_objects: IntCounterVec,
    pub received_sync_contribution_subsets: IntCounter,
    pub received_aggregated_attestation_subsets: IntCounter,

    // Custody Subnets / PeerDAS
    column_subnet_peers: IntGaugeVec,
    pub data_column_sidecars_submitted_for_processing: IntCounter,
    pub verified_gossip_data_column_sidecar: IntCounter,
    pub data_column_sidecar_verification_times: Histogram,
    pub reconstructed_columns: IntCounter, // TODO
    pub columns_reconstruction_time: Histogram,
    pub data_column_sidecar_computation: Histogram,
    pub data_column_sidecar_inclusion_proof_verification: Histogram,
    pub data_column_sidecar_kzg_verification_single: Histogram, // TODO?
    pub data_column_sidecar_kzg_verification_batch: Histogram,
    pub beacon_custody_columns_count_total: IntCounter, // TODO
    
    // Extra Network stats
    gossip_block_slot_start_delay_time: Histogram,

    // Mutator
    mutator_attestations: IntCounterVec,
    mutator_aggregate_and_proofs: IntCounterVec,

    pub block_processing_times: Histogram,
    pub block_post_processing_times: Histogram,

    // Attestation Verifier
    attestation_verifier_active_task_count: IntGauge,

    pub attestation_verifier_process_attestation_batch_times: Histogram,
    pub attestation_verifier_processs_aggregate_batch_times: Histogram,
    pub attestation_verifier_verify_agg_batch_signature_times: Histogram,

    // Validator ticks + Epoch processing
    pub validator_propose_tick_times: Histogram,
    pub validator_attest_tick_times: Histogram,
    pub validator_aggregate_tick_times: Histogram,
    pub validator_epoch_processing_times: Histogram,

    // Attestations
    pub validator_own_attestations_init_times: Histogram,
    pub validator_attest_times: Histogram,
    pub validator_attest_slashing_protector_times: Histogram,

    // eth/v1/validator/attestation_data
    pub validator_api_attestation_data_times: Histogram,

    // Blocks
    pub validator_propose_times: Histogram,
    pub validator_propose_successes: IntCounter,
    pub validator_proposal_slashing_protector_times: Histogram,

    // Build beacon block times
    pub build_beacon_block_times: Histogram,
    pub local_execution_payload_times: Histogram,
    pub process_sync_committee_contribution_times: Histogram,
    pub prepare_bls_to_execution_changes_times: Histogram,
    pub eth1_vote_times: Histogram,
    pub eth1_pending_deposits_times: Histogram,
    pub prepare_attester_slashings_times: Histogram,
    pub prepare_proposer_slashings_times: Histogram,
    pub prepare_voluntary_exits_times: Histogram,

    // Pools
    pub att_pool_pack_proposable_attestation_task_times: Histogram,
    pub att_pool_insert_attestation_task_times: Histogram,

    pub sync_pool_add_own_contribution_times: Histogram,
    pub sync_pool_aggregate_own_messages_times: Histogram,
    pub sync_pool_handle_external_contribution_times: Histogram,
    pub sync_pool_handle_external_message_times: Histogram,
    pub sync_pool_handle_slot_times: Histogram,

    pub bls_pool_discard_old_changes_times: Histogram,
    pub bls_pool_handle_external_change_times: Histogram,

    // Fork choice tasks
    pub fc_block_task_times: HistogramVec,
    pub fc_aggregate_and_proof_task_times: HistogramVec,
    pub fc_attestation_task_times: HistogramVec,

    pub fc_blob_sidecar_task_times: Histogram,
    pub fc_data_column_sidecar_task_times: Histogram,
    pub fc_blob_sidecar_persist_task_times: Histogram,
    pub fc_data_column_sidecar_persist_task_times: Histogram,
    pub fc_block_attestation_task_times: Histogram,
    pub fc_attester_slashing_task_times: Histogram,
    pub fc_preprocess_state_task_times: Histogram,
    pub fc_checkpoint_state_task_times: Histogram,

    // Cache metrics
    pub active_validator_indices_ordered_init_count: IntCounter,
    pub active_validator_indices_shuffled_init_count: IntCounter,
    pub beacon_proposer_index_init_count: IntCounter,
    pub total_active_balance_init_count: IntCounter,
    pub validator_indices_init_count: IntCounter,

    // Transition function metrics
    pub blinded_block_transition_times: Histogram,
    pub block_transition_times: Histogram,
    pub epoch_processing_times: Histogram,
    pub process_slot_times: Histogram,

    // EF interop metrics
    beacon_current_active_validators: IntGauge,
    beacon_current_justified_epoch: IntGauge,
    beacon_finalized_epoch: IntGauge,
    beacon_safe_head_slot: IntGauge,
    beacon_slot: IntGauge,
    beacon_processed_deposits_total: IntGauge,

    pub beacon_reorgs_total: IntCounter,

    beacon_participation_prev_epoch_active_gwei_total: IntGauge,
    beacon_participation_prev_epoch_target_attesting_gwei_total: IntGauge,
    validator_count: IntGauge,

    // Builder API
    pub builder_register_validator_times: Histogram,
    pub builder_post_blinded_block_times: Histogram,
    pub builder_get_execution_payload_header_times: Histogram,

    // WebSigner
    pub web3signer_load_keys_times: Histogram,
    pub web3signer_sign_times: Histogram,

    // Eth1 API
    pub eth1_api_request_times: HistogramVec,
    pub eth1_api_errors_count: IntCounter,
    pub eth1_api_reset_count: IntCounter,

    // Jemalloc stats
    pub jemalloc_bytes_allocated: IntGauge,
    pub jemalloc_bytes_active: IntGauge,
    pub jemalloc_bytes_metadata: IntGauge,
    pub jemalloc_bytes_resident: IntGauge,
    pub jemalloc_bytes_mapped: IntGauge,
    pub jemalloc_bytes_retained: IntGauge,

    // Tick delay metrics
    tick_delay_times: GaugeVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            // Overview
            live: IntGauge::new("IS_LIVE", "Grandine status")?,

            // System stats
            cores: IntGauge::new("CORE_COUNT", "Number of core in the node")?,
            disk_usage: IntGauge::new("GRANDINE_DISK_USAGE", "Grandine disk usage")?,
            used_memory: IntGauge::new("GRANDINE_USED_MEMORY", "Grandine memory usage")?,
            rx_bytes: IntGauge::new("NODE_RX_BYTES", "Node total bytes received")?,
            tx_bytes: IntGauge::new("NODE_TX_BYTES", "Node total bytes sent")?,

            system_cpu_percentage: Gauge::new(
                "SYSTEM_CPU_PERCENTAGE",
                "Node CPU load usage measured in percentage",
            )?,

            total_cpu_percentage: Gauge::new(
                "GRANDINE_TOTAL_CPU_PERCENTAGE",
                "Grandine CPU load usage measured in percentage",
            )?,

            system_used_memory: IntGauge::new("SYSTEM_USED_MEMORY", "Node memory usage")?,
            system_total_memory: IntGauge::new("SYSTEM_TOTAL_MEMORY", "Total node mmeory")?,

            // Collection Lengths
            collection_lengths: IntGaugeVec::new(
                opts!("COLLECTION_LENGTHS", "Number of items in each collection"),
                &["type", "name"],
            )?,

            // HTTP API metrics
            http_api_response_times: HistogramVec::new(
                histogram_opts!(
                    "HTTP_API_RESPONSE_TIMES",
                    "Response times for HTTP API responses"
                ),
                &["request_path"],
            )?,

            // Validator API metrics
            validator_api_response_times: HistogramVec::new(
                histogram_opts!(
                    "VALIDATOR_API_RESPONSE_TIMES",
                    "Response times for Validator API responses"
                ),
                &["request_path"],
            )?,

            // Dedicated Executor
            dedicated_executor_task_times: Histogram::with_opts(histogram_opts!(
                "DEDICATED_EXECUTOR_TASK_TIMES",
                "Dedicated executor task times",
            ))?,

            dedicated_executor_task_count: IntGauge::new(
                "DEDICATED_EXECUTOR_TASK_COUNT",
                "Number of currently active tasks in dedicated executor",
            )?,

            dedicated_executor_thread_count: IntGauge::new(
                "DEDICATED_EXECUTOR_THREAD_COUNT",
                "Number of threads that back dedicated executor",
            )?,

            // Network / Gossip stats
            gossip_objects: IntCounterVec::new(
                opts!(
                    "RECEIVED_OBJECTS_OVER_GOSSIP",
                    "Counter for different objects received via gossip",
                ),
                &["type"],
            )?,

            received_sync_contribution_subsets: IntCounter::new(
                "RECEIVED_SYNC_CONTRIBUTION_SUBSETS",
                "Number of received sync contributions that are subsets of already known aggregates"
            )?,

            received_aggregated_attestation_subsets: IntCounter::new(
                "RECEIVED_AGGREGATED_ATTESTATION_SUBSETS",
                "Number of received aggregated attestations that are subsets of already known aggregates"
            )?,

            // Custody Subnets / PeerDAS
            column_subnet_peers: IntGaugeVec::new(
                opts!("PEERS_PER_COLUMN_SUBNET", "Number of connected peers per column subnet"),
                &["subnet_id"],
            )?,

            data_column_sidecars_submitted_for_processing: IntCounter::new(
                "beacon_data_column_sidecar_processing_requests_total", 
                "Number of data column sidecars submitted for processing"
            )?,

            verified_gossip_data_column_sidecar: IntCounter::new(
                "beacon_data_column_sidecar_processing_successes_total", 
                "Number of data column sidecars verified for gossip"
            )?,

            data_column_sidecar_verification_times: Histogram::with_opts(histogram_opts!(
                "beacon_data_column_sidecar_gossip_verification_seconds",
                "Full runtime of data column sidecars gossip verification"
            ))?,

            reconstructed_columns: IntCounter::new(
                "beacon_data_availability_reconstructed_columns_total", 
                "Total count of reconstructed columns"
            )?,

            columns_reconstruction_time: Histogram::with_opts(histogram_opts!(
                "beacon_data_availability_reconstruction_time_seconds",
                "Time taken to reconstruct columns"
            ))?,

            data_column_sidecar_computation: Histogram::with_opts(histogram_opts!(
                "beacon_data_column_sidecar_computation_seconds",
                "Time taken to compute data column sidecar, including cells, proofs and inclusion proof"
            ))?,

            data_column_sidecar_inclusion_proof_verification: Histogram::with_opts(histogram_opts!(
                "beacon_data_column_sidecar_inclusion_proof_verification_seconds",
                "Time taken to verify data column sidecar inclusion proof"
            ))?,

            data_column_sidecar_kzg_verification_single: Histogram::with_opts(histogram_opts!(
                "beacon_kzg_verification_data_column_single_seconds",
                "Runtime of single data column kzg verification"
            ))?,

            data_column_sidecar_kzg_verification_batch: Histogram::with_opts(histogram_opts!(
                "beacon_kzg_verification_data_column_batch_seconds",
                "Runtime of batched data column kzg verification"
            ))?,

            beacon_custody_columns_count_total: IntCounter::new(
                "beacon_custody_columns_count_total",
                "Total count of columns in custody within the data availability boundary"
            )?,

            // Extra Network stats
            gossip_block_slot_start_delay_time: Histogram::with_opts(histogram_opts!(
                "beacon_block_gossip_slot_start_delay_time",
                "Duration between when the block is received and the start of the slot it belongs to.",
            ))?,

            // Mutator
            mutator_attestations: IntCounterVec::new(
                opts!(
                    "MUTATOR_ATTESTATIONS",
                    "Counter for different attestations (delayed/ignored etc) for Mutator",
                ),
                &["type"],
            )?,

            mutator_aggregate_and_proofs: IntCounterVec::new(
                opts!(
                    "MUTATOR_AGGREGATE_AND_PROOFS",
                    "Counter for different aggregate and proofs (delayed/ignored etc) for Mutator",
                ),
                &["type"],
            )?,

            block_processing_times: Histogram::with_opts(histogram_opts!(
                "MUTATOR_BLOCK_PROCESSING_TIMES",
                "Mutator Block processing times",
            ))?,

            block_post_processing_times: Histogram::with_opts(histogram_opts!(
                "MUTATOR_BLOCK_POST_PROCESSING_TIMES",
                "Mutator Block post processing times",
            ))?,

            // Attestation Verifier
            attestation_verifier_active_task_count: IntGauge::new(
                "ATTESTATION_VERIFIER_ACTIVE_TASK_COUNT",
                "Attestation verifier active task count",
            )?,

            attestation_verifier_process_attestation_batch_times: Histogram::with_opts(
                histogram_opts!(
                    "ATTESTATION_VERIFIER_PROCESS_ATTESTATION_BATCH_TIMES",
                    "Attestation verifier process attestation batch task times",
                )
            )?,

            attestation_verifier_processs_aggregate_batch_times: Histogram::with_opts(
                histogram_opts!(
                    "ATTESTATION_VERIFIER_PROCESS_AGGREGATE_BATCH_TIMES",
                    "Attestation verifier process aggregate batch task times",
                )
            )?,

            attestation_verifier_verify_agg_batch_signature_times: Histogram::with_opts(
                histogram_opts!(
                    "ATTESTATION_VERIFIER_VERIFY_AGG_BATCH_SIGNATURES_TIMES",
                    "Attestation verifier verify aggregate batch signature times",
                )
            )?,

            // Validator ticks + Epoch processing
            validator_propose_tick_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_PROPOSE_TICK_TIMES",
                "Validator propose tick times",
            ))?,

            validator_attest_tick_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_ATTEST_TICK_TIMES",
                "Validator attest tick times",
            ))?,

            validator_aggregate_tick_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_AGGREGATE_TICK_TIMES",
                "Validator aggregate tick times",
            ))?,

            validator_epoch_processing_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_EPOCH_PROCESSING_TIMES",
                "Validator epoch processing times",
            ))?,

            // Attestations
            validator_own_attestations_init_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_OWN_ATTESTATIONS_INIT_TIMES",
                "Validator own_singular_attestations init times",
            ))?,

            validator_attest_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_ATTEST_TIMES",
                "Attest duty times",
            ))?,

            validator_attest_slashing_protector_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_ATTEST_SLASHING_PROTECTOR_TIMES",
                "Slashing protection times when attesting",
            ))?,

            // eth/v1/validator/attestation_data
            validator_api_attestation_data_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_API_ATTESTATION_DATA_TIMES",
                "Singular attestation data production times in HTTP API",
            ))?,

            // Blocks
            validator_propose_times: Histogram::with_opts(histogram_opts!(
                "VALIDATOR_PROPOSE_TIMES",
                "Beacon block production times",
            ))?,

            validator_propose_successes: IntCounter::new(
                "VALIDATOR_PROPOSE_SUCCESSES",
                "Number of validator propose duties successes",
            )?,

            validator_proposal_slashing_protector_times: Histogram::with_opts(
                histogram_opts!(
                    "VALIDATOR_PROPOSAL_SLASHING_PROTECTOR_TIMES",
                    "Slashing protection times when checking block proposal",
                )
            )?,

            // Build beacon block times
            build_beacon_block_times: Histogram::with_opts(histogram_opts!(
                "BUILD_BEACON_BLOCK_TIMES",
                "Build beacon block times",
            ))?,

            local_execution_payload_times: Histogram::with_opts(histogram_opts!(
                "LOCAL_EXECUTION_PAYLOAD_TIMES",
                "Local execution payload times",
            ))?,

            process_sync_committee_contribution_times: Histogram::with_opts(histogram_opts!(
                "PROCESS_SYNC_COMMITTEE_CONTRIBUTION_TIMES",
                "Sync committee contribution processing times",
            ))?,

            prepare_bls_to_execution_changes_times: Histogram::with_opts(histogram_opts!(
                "PREPARE_BLS_TO_EXECUTION_CHANGES_TIMES",
                "Prepare BLS to execution changes times",
            ))?,

            eth1_vote_times: Histogram::with_opts(histogram_opts!(
                "ETH1_VOTE_TIMES",
                "Eth1 vote times",
            ))?,

            eth1_pending_deposits_times: Histogram::with_opts(histogram_opts!(
                "ETH1_PENDING_DEPOSITS_TIMES",
                "Eth1 pending deposits times",
            ))?,

            prepare_attester_slashings_times: Histogram::with_opts(histogram_opts!(
                "PREPARE_ATTESTER_SLASHINGS_TIMES",
                "Prepare attester slashing times",
            ))?,

            prepare_proposer_slashings_times: Histogram::with_opts(histogram_opts!(
                "PREPARE_PROPOSER_SLASHINGS_TIMES",
                "Prepare proposer slashing times",
            ))?,

            prepare_voluntary_exits_times: Histogram::with_opts(histogram_opts!(
                "PREPARE_VOLUNTARY_EXIT_TIMES",
                "Prepare voluntary exit times",
            ))?,

            // Pools
            att_pool_pack_proposable_attestation_task_times: Histogram::with_opts(histogram_opts!(
                "ATT_POOL_PACK_PROPOSABLE_ATTESTATION_TASK_TIMES",
                "Attestation agg pool packing proposable attestation task times",
            ))?,

            att_pool_insert_attestation_task_times: Histogram::with_opts(histogram_opts!(
                "ATT_POOL_INSERT_ATTESTATION_TASK_TIMES",
                "Attestation agg pool insert attestation task times",
            ))?,

            sync_pool_add_own_contribution_times: Histogram::with_opts(histogram_opts!(
                "SYNC_POOL_ADD_OWN_CONTRIBUTION_TIMES",
                "Sync committee contribution agg pool add own contribution task times",
            ))?,

            sync_pool_aggregate_own_messages_times: Histogram::with_opts(histogram_opts!(
                "SYNC_POOL_AGGREGATE_OWN_MESSAGES_TIMES",
                "Sync committee contribution agg pool aggregate own message task times",
            ))?,

            sync_pool_handle_external_contribution_times: Histogram::with_opts(histogram_opts!(
                "SYNC_POOL_HANDLE_EXTERNAL_CONTRIBUTION_TIMES",
                "Sync committee contribution agg pool handle external contribution task times",
            ))?,

            sync_pool_handle_external_message_times: Histogram::with_opts(histogram_opts!(
                "SYNC_POOL_HANDLE_EXTERNAL_MESSAGE_TIMES",
                "Sync committee contribution agg pool handle external message task times",
            ))?,

            sync_pool_handle_slot_times: Histogram::with_opts(histogram_opts!(
                "SYNC_POOL_HANDLE_SLOT_TIMES",
                "Sync committee contribution agg pool handle slot times",
            ))?,

            bls_pool_discard_old_changes_times: Histogram::with_opts(histogram_opts!(
                "BLS_POOL_DISCARD_OLD_CHANGES_TIMES",
                "Bls to Execution changes pool discard old change times",
            ))?,

            bls_pool_handle_external_change_times: Histogram::with_opts(histogram_opts!(
                "BLS_POOL_HANDLE_EXTERNAL_CHANGE_TIMES",
                "Bls to Execution changes pool handle exertnal change times",
            ))?,

            // Fork choice tasks
            fc_block_task_times: HistogramVec::new(
                histogram_opts!(
                    "FC_BLOCK_TASK_TIMES",
                    "Forkchoice BlockTask times",
                ),
                &["origin"],
            )?,

            fc_aggregate_and_proof_task_times: HistogramVec::new(
                histogram_opts!(
                    "FC_AGGREGATE_AND_PROOF_TASK_TIMES",
                    "Forkchoice AggregateAndProofTask times",
                ),
                &["origin"],
            )?,

            fc_attestation_task_times: HistogramVec::new(
                histogram_opts!(
                    "FC_ATTESTATION_TASK_TIMES",
                    "Forkchoice AttesttionTask times",
                ),
                &["origin"],
            )?,

            fc_blob_sidecar_task_times: Histogram::with_opts(histogram_opts!(
                "FC_BLOB_SIDECAR_TASK_TIMES",
                "Forkchoice BlobSidecar times",
            ))?,

            fc_blob_sidecar_persist_task_times: Histogram::with_opts(histogram_opts!(
                "FC_BLOB_SIDECAR_PERSIST_TASK_TIMES",
                "Forkchoice BlobSidecar persist task times",
            ))?,

            fc_data_column_sidecar_task_times: Histogram::with_opts(histogram_opts!(
                "FC_DATA_COLUMN_SIDECAR_TASK_TIMES",
                "Forkchoice DataColumnSidecar times",
            ))?,

            fc_data_column_sidecar_persist_task_times: Histogram::with_opts(histogram_opts!(
                "FC_DATA_COLUMN_SIDECAR_PERSIST_TASK_TIMES",
                "Forkchoice DataColumnSidecar persist task times",
            ))?,

            fc_block_attestation_task_times: Histogram::with_opts(histogram_opts!(
                "FC_BLOCK_ATTESTATION_TASK_TIMES",
                "Forkchoice BlockAttesttionTask times",
            ))?,

            fc_attester_slashing_task_times: Histogram::with_opts(histogram_opts!(
                "FC_ATTESTER_SLASHING_TASK_TIMES",
                "Forkchoice AttesterSlashingTask times",
            ))?,

            fc_preprocess_state_task_times: Histogram::with_opts(histogram_opts!(
                "FC_PREPROCESS_STATE_TASK_TIMES",
                "Forkchoice PreprocessStateTask times",
            ))?,

            fc_checkpoint_state_task_times: Histogram::with_opts(histogram_opts!(
                "FC_CHECKPOINT_STATE_TASK_TIMES",
                "Forkchoice CheckpointStateTask times",
            ))?,

            // Cache metrics
            active_validator_indices_ordered_init_count: IntCounter::new(
                "ACTIVE_VALIDATOR_INDICES_ORDERED_INIT_COUNT",
                "Active validator indices ordered cache init count",
            )?,

            active_validator_indices_shuffled_init_count: IntCounter::new(
                "ACTIVE_VALIDATOR_INDICES_SHUFFLED_INIT_COUNT",
                "Active validator indices shuffled cache init count",
            )?,

            beacon_proposer_index_init_count: IntCounter::new(
                "BEACON_PROPOSER_INDEX_INIT_COUNT",
                "Beacon proposer index cache init count",
            )?,

            total_active_balance_init_count: IntCounter::new(
                "TOTAL_ACTIVE_BALANCE_INIT_COUNT",
                "Total active balance cache init count",
            )?,

            validator_indices_init_count: IntCounter::new(
                "VALIDATOR_INDICES_INIT_COUNT",
                "Validator indices cache init count",
            )?,

            // Transition function metrics
            blinded_block_transition_times: Histogram::with_opts(histogram_opts!(
                "BLINDED_BLOCK_TRANSITION_TIMES",
                "Transition function blinded block processing times",
            ))?,

            block_transition_times: Histogram::with_opts(histogram_opts!(
                "BLOCK_TRANSITION_TIMES",
                "Transition function block processing times",
            ))?,

            epoch_processing_times: Histogram::with_opts(histogram_opts!(
                "EPOCH_PROCESSING_TIMES",
                "Transition function epoch processing times",
            ))?,

            process_slot_times: Histogram::with_opts(histogram_opts!(
                "PROCESS_SLOT_TIMES",
                "Transition function empty slots processing times",
            ))?,

            // EF interop metrics
            beacon_current_active_validators: IntGauge::new(
                "beacon_current_active_validators",
                "Number of active validators",
            )?,

            beacon_current_justified_epoch: IntGauge::new(
                "beacon_current_justified_epoch",
                "Justified epoch at head",
            )?,

            beacon_finalized_epoch: IntGauge::new(
                "beacon_finalized_epoch",
                "Finalized epoch at head",
            )?,

            beacon_safe_head_slot: IntGauge::new(
                "beacon_head_slot",
                "Head slot",
            )?,

            beacon_slot: IntGauge::new(
                "beacon_slot",
                "Slot at the latest beacon head",
            )?,

            beacon_processed_deposits_total: IntGauge::new(
                "beacon_processed_deposits_total",
                "Number of processed Eth1 deposits at head",
            )?,

            beacon_reorgs_total: IntCounter::new(
                "beacon_reorgs_total",
                "Total number of reorgs",
            )?,

            beacon_participation_prev_epoch_active_gwei_total: IntGauge::new(
                "beacon_participation_prev_epoch_active_gwei_total",
                "Total effective balance of previous epoch active validators",
            )?,

            beacon_participation_prev_epoch_target_attesting_gwei_total: IntGauge::new(
                "beacon_participation_prev_epoch_target_attesting_gwei_total",
                "Total effective balance of previous epoch attesters",
            )?,

            validator_count: IntGauge::new(
                "validator_count",
                "Number of total validators",
            )?,

            // Builder API
            builder_register_validator_times: Histogram::with_opts(histogram_opts!(
                "BUILDER_REGISTER_VALIDATORS_TIMES",
                "Builder register validators times",
            ))?,

            builder_post_blinded_block_times: Histogram::with_opts(histogram_opts!(
                "BUILDER_POST_BLINDED_BLOCK_TIMES",
                "Builder post blinded block times",
            ))?,

            builder_get_execution_payload_header_times: Histogram::with_opts(histogram_opts!(
                "BUILDER_GET_EXECUTION_PAYLOAD_HEADER_TIMES",
                "Builder get execution payload header times",
            ))?,

            // WebSigner
            web3signer_load_keys_times: Histogram::with_opts(histogram_opts!(
                "WEB3SIGNER_LOAD_KEYS_TIMES",
                "Web3Signer load keys times",
            ))?,

            web3signer_sign_times: Histogram::with_opts(histogram_opts!(
                "WEB3SIGNER_SIGN_TIMES",
                "Web3Signer sign times",
            ))?,

            // Eth1 API
            eth1_api_request_times: HistogramVec::new(
                histogram_opts!(
                    "ETH1_API_REQUEST_TIMES",
                    "Times for ETH1 API calls",
                ),
                &["method"]
            )?,

            eth1_api_errors_count: IntCounter::new(
                "ETH1_API_RESET_COUNT",
                "Number of times ETH1 API endpoints have been reset",
            )?,

            eth1_api_reset_count: IntCounter::new(
                "ETH1_API_ERRORS_COUNT",
                "Number of ETH1 API errors",
            )?,

            // Jemalloc stats
            jemalloc_bytes_allocated: IntGauge::new(
                "JEMALLOC_BYTES_ALLOCATED",
                "Total number of bytes allocated by the application",
            )?,

            jemalloc_bytes_active: IntGauge::new(
                "JEMALLOC_BYTES_ACTIVE",
                "Total number of bytes in active pages allocated by the application",
            )?,

            jemalloc_bytes_metadata: IntGauge::new(
                "JEMALLOC_BYTES_METADATA",
                "Total number of bytes dedicated to `jemalloc` metadata",
            )?,

            jemalloc_bytes_resident: IntGauge::new(
                "JEMALLOC_BYTES_RESIDENT",
                "Total number of bytes in physically resident data pages mapped by the allocator",
            )?,

            jemalloc_bytes_mapped: IntGauge::new(
                "JEMALLOC_BYTES_MAPPED",
                "Total number of bytes in active extents mapped by the allocator",
            )?,

            jemalloc_bytes_retained: IntGauge::new(
                "JEMALLOC_BYTES_RETAINED",
                "Total number of bytes in virtual memory mappings that were retained rather than being returned to the operating system",
            )?,

            // Tick delay metrics
            tick_delay_times: GaugeVec::new(
                opts!("TICK_DELAY_TIMES", "Tick delay times"),
                &["tick"],
            )?,
        })
    }

    pub fn register_with_default_metrics(&self) -> Result<()> {
        let default_registry = prometheus::default_registry();

        default_registry.register(Box::new(self.live.clone()))?;
        default_registry.register(Box::new(self.cores.clone()))?;
        default_registry.register(Box::new(self.disk_usage.clone()))?;
        default_registry.register(Box::new(self.used_memory.clone()))?;
        default_registry.register(Box::new(self.rx_bytes.clone()))?;
        default_registry.register(Box::new(self.tx_bytes.clone()))?;
        default_registry.register(Box::new(self.system_cpu_percentage.clone()))?;
        default_registry.register(Box::new(self.system_used_memory.clone()))?;
        default_registry.register(Box::new(self.system_total_memory.clone()))?;
        default_registry.register(Box::new(self.total_cpu_percentage.clone()))?;
        default_registry.register(Box::new(self.collection_lengths.clone()))?;
        default_registry.register(Box::new(self.http_api_response_times.clone()))?;
        default_registry.register(Box::new(self.validator_api_response_times.clone()))?;
        default_registry.register(Box::new(self.dedicated_executor_task_count.clone()))?;
        default_registry.register(Box::new(self.dedicated_executor_thread_count.clone()))?;
        default_registry.register(Box::new(self.gossip_objects.clone()))?;
        default_registry.register(Box::new(self.received_sync_contribution_subsets.clone()))?;
        default_registry.register(Box::new(
            self.received_aggregated_attestation_subsets.clone(),
        ))?;
        default_registry.register(Box::new(self.column_subnet_peers.clone()))?;
        default_registry.register(Box::new(self.data_column_sidecars_submitted_for_processing.clone()))?;
        default_registry.register(Box::new(self.verified_gossip_data_column_sidecar.clone()))?;
        default_registry.register(Box::new(
            self.data_column_sidecar_verification_times.clone(),
        ))?;
        default_registry.register(Box::new(self.reconstructed_columns.clone(),))?;
        default_registry.register(Box::new(
            self.columns_reconstruction_time.clone(),
        ))?;
        default_registry.register(Box::new(
            self.data_column_sidecar_computation.clone(),
        ))?;
        default_registry.register(Box::new(
            self.data_column_sidecar_inclusion_proof_verification.clone(),
        ))?;
        default_registry.register(Box::new(
            self.data_column_sidecar_kzg_verification_single.clone(),
        ))?;
        default_registry.register(Box::new(
            self.data_column_sidecar_kzg_verification_batch.clone(),
        ))?;
        default_registry.register(Box::new(
            self.beacon_custody_columns_count_total.clone(),
        ))?;
        default_registry.register(Box::new(self.gossip_block_slot_start_delay_time.clone()))?;
        default_registry.register(Box::new(self.mutator_attestations.clone()))?;
        default_registry.register(Box::new(self.mutator_aggregate_and_proofs.clone()))?;
        default_registry.register(Box::new(self.block_processing_times.clone()))?;
        default_registry.register(Box::new(self.block_post_processing_times.clone()))?;
        default_registry.register(Box::new(
            self.attestation_verifier_active_task_count.clone(),
        ))?;
        default_registry.register(Box::new(
            self.attestation_verifier_process_attestation_batch_times
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.attestation_verifier_processs_aggregate_batch_times
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.attestation_verifier_verify_agg_batch_signature_times
                .clone(),
        ))?;
        default_registry.register(Box::new(self.validator_propose_tick_times.clone()))?;
        default_registry.register(Box::new(self.validator_attest_tick_times.clone()))?;
        default_registry.register(Box::new(self.validator_aggregate_tick_times.clone()))?;
        default_registry.register(Box::new(self.validator_epoch_processing_times.clone()))?;
        default_registry.register(Box::new(self.validator_own_attestations_init_times.clone()))?;
        default_registry.register(Box::new(self.validator_attest_times.clone()))?;
        default_registry.register(Box::new(
            self.validator_attest_slashing_protector_times.clone(),
        ))?;
        default_registry.register(Box::new(self.validator_api_attestation_data_times.clone()))?;
        default_registry.register(Box::new(self.validator_propose_times.clone()))?;
        default_registry.register(Box::new(self.validator_propose_successes.clone()))?;
        default_registry.register(Box::new(
            self.validator_proposal_slashing_protector_times.clone(),
        ))?;
        default_registry.register(Box::new(self.build_beacon_block_times.clone()))?;
        default_registry.register(Box::new(self.local_execution_payload_times.clone()))?;
        default_registry.register(Box::new(
            self.process_sync_committee_contribution_times.clone(),
        ))?;
        default_registry.register(Box::new(
            self.prepare_bls_to_execution_changes_times.clone(),
        ))?;
        default_registry.register(Box::new(self.eth1_vote_times.clone()))?;
        default_registry.register(Box::new(self.eth1_pending_deposits_times.clone()))?;
        default_registry.register(Box::new(self.prepare_attester_slashings_times.clone()))?;
        default_registry.register(Box::new(self.prepare_proposer_slashings_times.clone()))?;
        default_registry.register(Box::new(self.prepare_voluntary_exits_times.clone()))?;
        default_registry.register(Box::new(
            self.att_pool_pack_proposable_attestation_task_times.clone(),
        ))?;
        default_registry.register(Box::new(
            self.att_pool_insert_attestation_task_times.clone(),
        ))?;
        default_registry.register(Box::new(self.sync_pool_add_own_contribution_times.clone()))?;
        default_registry.register(Box::new(
            self.sync_pool_aggregate_own_messages_times.clone(),
        ))?;
        default_registry.register(Box::new(
            self.sync_pool_handle_external_contribution_times.clone(),
        ))?;
        default_registry.register(Box::new(
            self.sync_pool_handle_external_message_times.clone(),
        ))?;
        default_registry.register(Box::new(self.sync_pool_handle_slot_times.clone()))?;
        default_registry.register(Box::new(self.bls_pool_discard_old_changes_times.clone()))?;
        default_registry.register(Box::new(self.bls_pool_handle_external_change_times.clone()))?;
        default_registry.register(Box::new(self.fc_block_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_aggregate_and_proof_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_attestation_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_blob_sidecar_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_blob_sidecar_persist_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_data_column_sidecar_task_times.clone()))?;
        default_registry.register(Box::new(
            self.fc_data_column_sidecar_persist_task_times.clone(),
        ))?;
        default_registry.register(Box::new(self.fc_block_attestation_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_attester_slashing_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_preprocess_state_task_times.clone()))?;
        default_registry.register(Box::new(self.fc_checkpoint_state_task_times.clone()))?;
        default_registry.register(Box::new(
            self.active_validator_indices_ordered_init_count.clone(),
        ))?;
        default_registry.register(Box::new(
            self.active_validator_indices_shuffled_init_count.clone(),
        ))?;
        default_registry.register(Box::new(self.beacon_proposer_index_init_count.clone()))?;
        default_registry.register(Box::new(self.total_active_balance_init_count.clone()))?;
        default_registry.register(Box::new(self.validator_indices_init_count.clone()))?;
        default_registry.register(Box::new(self.blinded_block_transition_times.clone()))?;
        default_registry.register(Box::new(self.block_transition_times.clone()))?;
        default_registry.register(Box::new(self.epoch_processing_times.clone()))?;
        default_registry.register(Box::new(self.process_slot_times.clone()))?;
        default_registry.register(Box::new(self.beacon_current_active_validators.clone()))?;
        default_registry.register(Box::new(self.beacon_current_justified_epoch.clone()))?;
        default_registry.register(Box::new(self.beacon_finalized_epoch.clone()))?;
        default_registry.register(Box::new(self.beacon_safe_head_slot.clone()))?;
        default_registry.register(Box::new(self.beacon_slot.clone()))?;
        default_registry.register(Box::new(self.beacon_processed_deposits_total.clone()))?;
        default_registry.register(Box::new(self.beacon_reorgs_total.clone()))?;
        default_registry.register(Box::new(
            self.beacon_participation_prev_epoch_active_gwei_total
                .clone(),
        ))?;
        default_registry.register(Box::new(
            self.beacon_participation_prev_epoch_target_attesting_gwei_total
                .clone(),
        ))?;
        default_registry.register(Box::new(self.validator_count.clone()))?;
        default_registry.register(Box::new(self.builder_register_validator_times.clone()))?;
        default_registry.register(Box::new(self.builder_post_blinded_block_times.clone()))?;
        default_registry.register(Box::new(
            self.builder_get_execution_payload_header_times.clone(),
        ))?;
        default_registry.register(Box::new(self.web3signer_load_keys_times.clone()))?;
        default_registry.register(Box::new(self.web3signer_sign_times.clone()))?;
        default_registry.register(Box::new(self.eth1_api_request_times.clone()))?;
        default_registry.register(Box::new(self.eth1_api_errors_count.clone()))?;
        default_registry.register(Box::new(self.eth1_api_reset_count.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_allocated.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_active.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_metadata.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_resident.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_mapped.clone()))?;
        default_registry.register(Box::new(self.jemalloc_bytes_retained.clone()))?;
        default_registry.register(Box::new(self.tick_delay_times.clone()))?;

        Ok(())
    }

    // Overview
    pub fn set_live(&self) {
        self.live.set(1)
    }

    // System stats
    pub fn set_cores(&self, core_count: usize) {
        self.cores.set(core_count as i64)
    }

    pub fn set_disk_usage(&self, disk_usage: u64) {
        self.disk_usage.set(disk_usage as i64)
    }

    pub fn set_used_memory(&self, used_memory: u64) {
        self.used_memory.set(used_memory as i64)
    }

    pub fn set_rx_bytes(&self, bytes: u64) {
        self.rx_bytes.set(bytes as i64)
    }

    pub fn set_tx_bytes(&self, bytes: u64) {
        self.tx_bytes.set(bytes as i64)
    }

    pub fn set_system_cpu_percentage(&self, cpu_percentage: f32) {
        self.system_cpu_percentage.set(cpu_percentage as f64)
    }

    pub fn set_total_cpu_percentage(&self, cpu_percentage: f32) {
        self.total_cpu_percentage.set(cpu_percentage as f64)
    }

    pub fn set_system_used_memory(&self, used_memory: u64) {
        self.system_used_memory.set(used_memory as i64)
    }

    pub fn set_system_total_memory(&self, total_memory: u64) {
        self.system_total_memory.set(total_memory as i64)
    }

    // Collection Lengths
    pub fn set_collection_length(&self, typename: &str, collection_name: &str, value: usize) {
        self.collection_lengths
            .get_metric_with_label_values(&[typename, collection_name])
            .expect(
                "the number of label values should match the number \
                 of labels that collection_lengths was created with",
            )
            .set(value as i64)
    }

    // HTTP API metrics
    pub fn set_http_api_response_time(&self, labels: &[&str], response_duration: Duration) {
        match self
            .http_api_response_times
            .get_metric_with_label_values(labels)
        {
            Ok(metrics) => metrics.observe(response_duration.as_secs_f64()),
            Err(error) => warn!("unable to track HTTP API resposne time for {labels:?}: {error:?}"),
        }
    }

    // Validator API metrics
    pub fn set_validator_api_response_time(&self, labels: &[&str], response_duration: Duration) {
        match self
            .validator_api_response_times
            .get_metric_with_label_values(labels)
        {
            Ok(metrics) => metrics.observe(response_duration.as_secs_f64()),
            Err(error) => {
                warn!("unable to track Validator API resposne time for {labels:?}: {error:?}")
            }
        }
    }

    // Dedicated Executor
    pub fn set_dedicated_exutor_task_count(&self, task_count: usize) {
        self.dedicated_executor_task_count.set(task_count as i64)
    }

    pub fn set_dedicated_exutor_thread_count(&self, thread_count: usize) {
        self.dedicated_executor_thread_count
            .set(thread_count as i64)
    }

    // Network / Gossip stats
    pub fn register_gossip_object(&self, labels: &[&str]) {
        match self.gossip_objects.get_metric_with_label_values(labels) {
            Ok(counter) => counter.inc(),
            Err(error) => {
                warn!("unable to register received object over gossip for {labels:?}: {error:?}")
            }
        }
    }

    // Custody Subnets / PeerDAS
    pub fn set_column_subnet_peers(&self, subnet_id: &str, num_peers: usize) {
        match self
            .column_subnet_peers
            .get_metric_with_label_values(&[subnet_id])
        {
            Ok(metric) => metric.set(num_peers as i64),
            Err(error) => {
                warn!(
                    "the number of label values should match the number \
                 of labels that column_subnet_peers was created: {error:?}"
                );
            }
        }
    }
    
    // Extra Network stats
    pub fn observe_block_duration_to_slot(&self, block_slot_timestamp: UnixSeconds) {
        match helpers::duration_from_now_to(block_slot_timestamp) {
            Ok(duration) => self
                .gossip_block_slot_start_delay_time
                .observe(duration.as_secs_f64()),
            Err(error) => warn!("unable to observe block duration to slot: {error:?}"),
        }
    }

    // Mutator
    pub fn register_mutator_attestation(&self, labels: &[&str]) {
        match self
            .mutator_attestations
            .get_metric_with_label_values(labels)
        {
            Ok(counter) => counter.inc(),
            Err(error) => {
                warn!("unable to register mutator attestation for {labels:?}: {error:?}")
            }
        }
    }

    pub fn register_mutator_aggregate_and_proof(&self, labels: &[&str]) {
        match self
            .mutator_aggregate_and_proofs
            .get_metric_with_label_values(labels)
        {
            Ok(counter) => counter.inc(),
            Err(error) => {
                warn!("unable to register mutator aggregate_and_proof for {labels:?}: {error:?}")
            }
        }
    }

    // Attestation Verifier
    pub fn set_attestation_verifier_active_task_count(&self, task_count: usize) {
        self.attestation_verifier_active_task_count
            .set(task_count as i64)
    }

    // EF interop metrics
    pub fn set_active_validators(&self, validator_count: usize) {
        self.beacon_current_active_validators
            .set(validator_count as i64);
    }

    pub fn set_justified_epoch(&self, epoch: Epoch) {
        self.beacon_current_justified_epoch.set(epoch as i64);
    }

    pub fn set_finalized_epoch(&self, epoch: Epoch) {
        self.beacon_finalized_epoch.set(epoch as i64);
    }

    pub fn set_safe_head_slot(&self, slot: Slot) {
        self.beacon_safe_head_slot.set(slot as i64);
    }

    pub fn set_slot(&self, slot: Slot) {
        self.beacon_slot.set(slot as i64);
    }

    pub fn set_processed_deposits(&self, total_deposits: u64) {
        self.beacon_processed_deposits_total
            .set(total_deposits as i64);
    }

    pub fn set_beacon_participation_prev_epoch_active_gwei_total(&self, gwei: Gwei) {
        self.beacon_participation_prev_epoch_active_gwei_total
            .set(gwei as i64);
    }

    pub fn set_beacon_participation_prev_epoch_target_attesting_gwei_total(&self, gwei: Gwei) {
        self.beacon_participation_prev_epoch_target_attesting_gwei_total
            .set(gwei as i64);
    }

    pub fn set_validator_count(&self, validator_count: usize) {
        self.validator_count.set(validator_count as i64);
    }

    // Jemalloc stats
    pub fn set_jemalloc_bytes_allocated(&self, bytes: usize) {
        self.jemalloc_bytes_allocated.set(bytes as i64)
    }

    pub fn set_jemalloc_bytes_active(&self, bytes: usize) {
        self.jemalloc_bytes_active.set(bytes as i64)
    }

    pub fn set_jemalloc_bytes_metadata(&self, bytes: usize) {
        self.jemalloc_bytes_metadata.set(bytes as i64)
    }

    pub fn set_jemalloc_bytes_resident(&self, bytes: usize) {
        self.jemalloc_bytes_resident.set(bytes as i64)
    }

    pub fn set_jemalloc_bytes_mapped(&self, bytes: usize) {
        self.jemalloc_bytes_mapped.set(bytes as i64)
    }

    pub fn set_jemalloc_bytes_retained(&self, bytes: usize) {
        self.jemalloc_bytes_retained.set(bytes as i64)
    }

    // Tick delay metrics
    pub fn set_tick_delay(&self, tick_kind: &str, delay: Duration) {
        self.tick_delay_times
            .get_metric_with_label_values(&[tick_kind])
            .expect(
                "the number of label values should match the number \
                 of labels that tick_delay_times was created with",
            )
            .set(delay.as_secs_f64())
    }
}
