use std::{path::PathBuf, sync::Arc};

use clock::Tick;
use duplicate::duplicate_item;
use execution_engine::PayloadStatusWithBlockHash;
use helper_functions::misc;
use pubkey_cache::PubkeyCache;
use serde::Deserialize;
use spec_test_utils::Case;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use test_generator::test_resources;
use typenum::Unsigned as _;
use types::{
    combined::{
        Attestation, AttesterSlashing, BeaconBlock, BeaconState, DataColumnSidecar,
        SignedBeaconBlock,
    },
    config::Config,
    deneb::primitives::{Blob, KzgProof},
    gloas::{
        containers::{
            CombinedPayloadAttestation, PayloadAttestationMessage, SignedExecutionPayloadEnvelope,
        },
        primitives::PayloadStatus,
    },
    nonstandard::{Phase, TimedPowBlock},
    phase0::{
        containers::Checkpoint,
        primitives::{H256, Slot, UnixSeconds},
    },
    preset::{Minimal, Preset},
    traits::{BeaconState as _, BlockBodyWithBlobKzgCommitments, SignedBeaconBlock as _},
};

use crate::helpers::Context;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "lowercase", untagged)]
enum Step {
    Tick {
        tick: UnixSeconds,
    },
    Attestation {
        attestation: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    Block {
        block: PathBuf,
        blobs: Option<PathBuf>,
        columns: Option<Vec<PathBuf>>,
        proofs: Option<Vec<KzgProof>>,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    PayloadAttestation {
        payload_attestation_message: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    ExecutionPayload {
        execution_payload: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    MergeBlock {
        pow_block: PathBuf,
    },
    PayloadStatus(PayloadStatusWithBlockHash),
    AttesterSlashing {
        attester_slashing: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    Checks {
        checks: Box<Checks>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Checks {
    head: Option<HeadCheck>,
    head_payload_status: Option<u8>,
    time: Option<UnixSeconds>,
    genesis_time: Option<UnixSeconds>,
    justified_checkpoint: Option<Checkpoint>,
    finalized_checkpoint: Option<Checkpoint>,
    proposer_boost_root: Option<H256>,
    // TODO: assert viable_for_head_roots_and_weights
    viable_for_head_roots_and_weights: Option<Vec<ViableHeadRootAndWeight>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct HeadCheck {
    slot: Slot,
    root: H256,
    payload_status: Option<PayloadStatus>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ViableHeadRootAndWeight {
    root: H256,
    payload_status: Option<PayloadStatus>,
    weight: u64,
}

#[duplicate_item(
    glob                                                                                            function_name                                  preset    phase;
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/attester_slashing_test/*/*"]   [fulu_minimal_compliance_attester_slashing]    [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/block_cover_test/*/*"]         [fulu_minimal_compliance_block_cover]          [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/block_tree_test/*/*"]          [fulu_minimal_compliance_block_tree]           [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/block_weight_test/*/*"]        [fulu_minimal_compliance_block_weight]         [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/invalid_message_test/*/*"]     [fulu_minimal_compliance_invalid_message]      [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice_compliance/shuffling_test/*/*"]           [fulu_minimal_compliance_shuffling]            [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/attester_slashing_test/*/*"]  [gloas_minimal_compliance_attester_slashing]   [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/block_cover_test/*/*"]        [gloas_minimal_compliance_block_cover]         [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/block_tree_test/*/*"]         [gloas_minimal_compliance_block_tree]          [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/block_weight_test/*/*"]       [gloas_minimal_compliance_block_weight]        [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/invalid_message_test/*/*"]    [gloas_minimal_compliance_invalid_message]     [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice_compliance/shuffling_test/*/*"]          [gloas_minimal_compliance_shuffling]           [Minimal] [Gloas];
)]
#[test_resources(glob)]
fn function_name(case: Case<'_>) {
    let rt = tokio::runtime::Runtime::new().expect("Tokio runtime starts successfully in tests");
    let config = Arc::new(preset::default_config().start_and_stay_in(Phase::phase));

    rt.block_on(async {
        run_case::<preset>(&config, case).await;
    });
}

#[expect(clippy::too_many_lines)]
async fn run_case<P: Preset>(config: &Arc<Config>, case: Case<'_>) {
    let anchor_block = case
        .ssz::<_, BeaconBlock<P>>(config.as_ref(), "anchor_block")
        .with_zero_signature()
        .pipe(Arc::new);

    let anchor_state = case.ssz::<_, Arc<BeaconState<P>>>(config.as_ref(), "anchor_state");
    let meta = case.compliance_meta();
    let steps = case.yaml::<Vec<Step>>("steps");
    let genesis_time = anchor_state.genesis_time();
    let pubkey_cache = Arc::new(PubkeyCache::default());

    let tick_at_time = |time| {
        Tick::at_time::<P>(config, time, genesis_time)
            .expect("configurations used in tests have valid values of SECONDS_PER_SLOT")
    };

    let mut context = Context::<P>::new(
        config.clone_arc(),
        pubkey_cache,
        anchor_block,
        anchor_state,
        false,
        // Use a single worker thread to serialise task execution. Two same-slot blocks are delayed in
        // the proposer equivocation case; only the first received gets the boost. In production the
        // race is inconsequential, but compliance tests assert a specific proposer_boost_root so the
        // retry order of delayed blocks must be deterministic.
        Some(1),
    );

    let mut last_payload_status: Option<PayloadStatusWithBlockHash> = None;

    for step in steps {
        match step {
            Step::Tick { tick } => {
                let tick = tick_at_time(tick);
                context.on_tick(tick);
            }
            Step::Attestation { attestation, valid } => {
                let attestation = case.ssz::<_, Attestation<P>>(config, attestation);

                if valid {
                    context.on_valid_test_attestation(attestation, meta.bls_setting);
                } else {
                    context.on_invalid_test_attestation(attestation, meta.bls_setting);
                }
            }
            Step::Block {
                block,
                blobs,
                columns,
                proofs,
                valid,
            } => {
                type BlobBundle<P> =
                    ContiguousList<Blob<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>;

                let block = case.ssz::<_, Arc<SignedBeaconBlock<P>>>(config.as_ref(), block);

                let mut data_column_sidecar_count: usize = 0;
                if block.phase().is_peerdas_activated() {
                    if let Some(paths) = columns {
                        let data_column_sidecars = paths
                            .into_iter()
                            .map(|path| case.ssz::<_, DataColumnSidecar<P>>(config.as_ref(), path));

                        for data_column_sidecar in data_column_sidecars {
                            data_column_sidecar_count = data_column_sidecar_count.saturating_add(1);
                            context.on_data_column_sidecar(data_column_sidecar).await;
                        }
                    }
                } else {
                    let blobs = blobs
                        .map(|path| case.ssz_default::<BlobBundle<P>>(path))
                        .into_iter()
                        .flatten();
                    let proofs = proofs.into_iter().flatten();

                    // TODO(feature/deneb): Constructing proofs and sidecars is unnecessary.
                    //                      Consider mocking `retrieve_blobs_and_proofs`
                    //                      from `consensus-specs` using something like
                    //                      `TestExecutionEngine`.
                    let blob_sidecars = misc::construct_blob_sidecars(&block, blobs, proofs)
                        .expect("blob sidecars should be constructed successfully");

                    for blob_sidecar in blob_sidecars {
                        context.on_blob_sidecar(blob_sidecar);
                    }
                }

                let expected_blob_count = block
                    .message()
                    .body()
                    .with_blob_kzg_commitments()
                    .map(BlockBodyWithBlobKzgCommitments::blob_kzg_commitments)
                    .map(|contiguous_list| contiguous_list.len())
                    .unwrap_or_default();

                let beacon_block_root = block.message().hash_tree_root();

                if let Some(PayloadStatusWithBlockHash {
                    block_hash,
                    payload_status,
                }) = last_payload_status.take()
                {
                    context.on_notified_new_payload(
                        beacon_block_root,
                        block_hash,
                        payload_status.into(),
                    );
                }

                if !valid && expected_blob_count > 0 {
                    // If half of data column sidecars are available, we can reconstruct the rest
                    // and consider the block valid
                    if block.phase().is_peerdas_activated()
                        && data_column_sidecar_count.saturating_mul(2) >= P::NumberOfColumns::USIZE
                    {
                        context.on_test_block_with_reconstructing_data_columns(
                            &block,
                            meta.bls_setting,
                        );
                    } else {
                        context.on_test_block_with_missing_blobs(
                            &block,
                            expected_blob_count,
                            meta.bls_setting,
                        );
                    }
                } else if valid {
                    context.on_valid_test_block(&block, meta.bls_setting);
                } else {
                    context.on_invalid_test_block(&block, meta.bls_setting);
                }
            }
            Step::PayloadAttestation {
                payload_attestation_message,
                valid,
            } => {
                let message = case.ssz::<_, PayloadAttestationMessage>(
                    config.as_ref(),
                    payload_attestation_message,
                );

                let combined = Arc::new(CombinedPayloadAttestation::<P>::Message(message.into()));

                if valid {
                    context.on_valid_payload_attestation(combined, meta.bls_setting);
                } else {
                    context.on_invalid_payload_attestation(combined, meta.bls_setting);
                }
            }
            Step::ExecutionPayload {
                execution_payload,
                valid,
            } => {
                let envelope = case.ssz::<_, Arc<SignedExecutionPayloadEnvelope<P>>>(
                    config.as_ref(),
                    execution_payload,
                );

                if valid {
                    context.on_valid_execution_payload(&envelope, meta.bls_setting);
                } else {
                    context.on_invalid_execution_payload(&envelope, meta.bls_setting);
                }
            }
            Step::MergeBlock { pow_block } => {
                let block_hash = pow_block
                    .to_str()
                    .expect("pow_block should be a valid UTF-8 string")
                    .strip_prefix("pow_block_")
                    .expect("pow_block should start with pow_block_")
                    .parse()
                    .expect("pow_block should contain a valid Eth1 block hash");

                let pow_block = case.ssz_default(pow_block);

                let timed_pow_block = TimedPowBlock {
                    pow_block,
                    timestamp: 0,
                };

                context.on_merge_block(block_hash, timed_pow_block);
            }
            Step::PayloadStatus(payload_status_with_block_hash) => {
                last_payload_status = Some(payload_status_with_block_hash);
            }
            Step::AttesterSlashing {
                attester_slashing: file_name,
                // TODO: check validity
                // (requires spawning validator and operations pool as it is done in gossip_spec_tests)
                valid: _valid,
            } => {
                let attester_slashing = match config.genesis_phase() {
                    Phase::Phase0
                    | Phase::Altair
                    | Phase::Bellatrix
                    | Phase::Capella
                    | Phase::Deneb => AttesterSlashing::Phase0(case.ssz(config, file_name)),
                    Phase::Electra | Phase::Fulu | Phase::Gloas => {
                        AttesterSlashing::Electra(case.ssz(config, file_name))
                    }
                };

                context.on_test_attester_slashing(attester_slashing, meta.bls_setting);
            }
            Step::Checks { checks } => {
                let Checks {
                    head,
                    head_payload_status,
                    time,
                    genesis_time,
                    justified_checkpoint,
                    finalized_checkpoint,
                    proposer_boost_root,
                    viable_for_head_roots_and_weights: _,
                } = *checks;

                if let Some(HeadCheck {
                    slot,
                    root,
                    payload_status,
                }) = head
                {
                    context.assert_head(slot, root);

                    if let Some(payload_status) = payload_status {
                        context.assert_head_payload_status(payload_status);
                    }
                }

                if let Some(payload_status) = head_payload_status {
                    context.assert_head_payload_status(payload_status);
                }

                if let Some(time) = time {
                    let tick = tick_at_time(time);
                    context.assert_tick(tick);
                }

                if let Some(genesis_time) = genesis_time {
                    context.assert_genesis_time(genesis_time);
                }

                if let Some(justified_checkpoint) = justified_checkpoint {
                    context.assert_justified_checkpoint(justified_checkpoint);
                }

                if let Some(finalized_checkpoint) = finalized_checkpoint {
                    context.assert_finalized_checkpoint(finalized_checkpoint);
                }

                if let Some(proposer_boost_root) = proposer_boost_root {
                    context.assert_proposer_boost_root(proposer_boost_root);
                }
            }
        }
    }
}
