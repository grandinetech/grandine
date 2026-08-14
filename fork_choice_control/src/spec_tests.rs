use std::{path::PathBuf, sync::Arc};

use clock::Tick;
use duplicate::duplicate_item;
use execution_engine::{PayloadStatusV1, PayloadStatusWithBlockHash, PayloadValidationStatus};
use helper_functions::misc;
use pubkey_cache::PubkeyCache;
use serde::Deserialize;
use spec_test_utils::{BlsSetting, Case};
use ssz::{ContiguousList, SszList};
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
        containers::{PayloadAttestationMessage, SignedExecutionPayloadEnvelope},
        primitives::PayloadStatus,
    },
    nonstandard::{Phase, TimedPowBlock},
    phase0::{
        containers::Checkpoint,
        primitives::{H256, Slot, UnixSeconds},
    },
    preset::{Mainnet, Minimal, Preset},
    traits::{BeaconState as _, BlockBodyWithBlobKzgCommitments, SignedBeaconBlock as _},
};

use crate::helpers::Context;

#[derive(Deserialize)]
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
    ExecutionPayload {
        execution_payload: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    MergeBlock {
        pow_block: PathBuf,
    },
    PayloadAttestation {
        payload_attestation_message: PathBuf,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    PayloadStatus(PayloadStatusWithBlockHash),
    AttesterSlashing {
        attester_slashing: PathBuf,
    },
    Checks {
        checks: Box<Checks>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checks {
    head: Option<HeadCheck>,
    time: Option<UnixSeconds>,
    genesis_time: Option<UnixSeconds>,
    justified_checkpoint: Option<Checkpoint>,
    finalized_checkpoint: Option<Checkpoint>,
    proposer_boost_root: Option<H256>,
    payload_timeliness_vote: Option<PtcVotes>,
    payload_data_availability_vote: Option<PtcVotes>,

    // FCR checks — present only in `tests/*/phase0/fast_confirmation/*/*/*` vectors.
    // See `tests/formats/fast_confirmation/README.md` in `consensus-specs`.
    previous_epoch_observed_justified_checkpoint: Option<Checkpoint>,
    current_epoch_observed_justified_checkpoint: Option<Checkpoint>,
    previous_epoch_greatest_unrealized_checkpoint: Option<Checkpoint>,
    previous_slot_head: Option<H256>,
    current_slot_head: Option<H256>,
    confirmed_root: Option<H256>,
    safe_execution_block_hash: Option<H256>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadCheck {
    slot: Slot,
    root: H256,
    payload_status: Option<PayloadStatus>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PtcVotes {
    block_root: H256,
    votes: Vec<Option<bool>>,
}

// Starting with `consensus-specs` version 1.3.0-rc.4,
// fork choice test vectors are no longer generated for Phase 0.
// The reason for doing so is not clearly explained. See:
// - <https://github.com/ethereum/consensus-specs/pull/3294>
// - <https://github.com/ethereum/consensus-specs/pull/3297>
//
// We do not run the following test cases:
// - `consensus-spec-tests/tests/*/*/fork_choice/get_proposer_head/*/*`
// - `consensus-spec-tests/tests/*/*/fork_choice/should_override_forkchoice_update/*/*`
// Grandine does not implement proposer boost re-orgs.
#[duplicate_item(
    glob                                                                                        function_name                                  preset    phase;
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/ex_ante/*/*"]                       [altair_mainnet_ex_ante]                       [Mainnet] [Altair];
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/get_head/*/*"]                      [altair_mainnet_get_head]                      [Mainnet] [Altair];
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/on_block/*/*"]                      [altair_mainnet_on_block]                      [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/ex_ante/*/*"]                       [altair_minimal_ex_ante]                       [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/get_head/*/*"]                      [altair_minimal_get_head]                      [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/on_block/*/*"]                      [altair_minimal_on_block]                      [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/reorg/*/*"]                         [altair_minimal_reorg]                         [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/withholding/*/*"]                   [altair_minimal_withholding]                   [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/ex_ante/*/*"]                    [bellatrix_mainnet_ex_ante]                    [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/get_head/*/*"]                   [bellatrix_mainnet_get_head]                   [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/on_block/*/*"]                   [bellatrix_mainnet_on_block]                   [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/on_merge_block/*/*"]             [bellatrix_mainnet_on_merge_block]             [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/ex_ante/*/*"]                    [bellatrix_minimal_ex_ante]                    [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/get_head/*/*"]                   [bellatrix_minimal_get_head]                   [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/on_block/*/*"]                   [bellatrix_minimal_on_block]                   [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/on_merge_block/*/*"]             [bellatrix_minimal_on_merge_block]             [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/reorg/*/*"]                      [bellatrix_minimal_reorg]                      [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/withholding/*/*"]                [bellatrix_minimal_withholding]                [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/sync/*/*/*"]                                 [bellatrix_sync_mainnet]                       [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/sync/*/*/*"]                                 [bellatrix_sync_minimal]                       [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/ex_ante/*/*"]                      [capella_mainnet_ex_ante]                      [Mainnet] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/get_head/*/*"]                     [capella_mainnet_get_head]                     [Mainnet] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/on_block/*/*"]                     [capella_mainnet_on_block]                     [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/ex_ante/*/*"]                      [capella_minimal_ex_ante]                      [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/get_head/*/*"]                     [capella_minimal_get_head]                     [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/on_block/*/*"]                     [capella_minimal_on_block]                     [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/reorg/*/*"]                        [capella_minimal_reorg]                        [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/withholding/*/*"]                  [capella_minimal_withholding]                  [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/sync/*/*/*"]                                   [capella_sync_mainnet]                         [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/sync/*/*/*"]                                   [capella_sync_minimal]                         [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/ex_ante/*/*"]                        [deneb_mainnet_ex_ante]                        [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/get_head/*/*"]                       [deneb_mainnet_get_head]                       [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/on_block/*/*"]                       [deneb_mainnet_on_block]                       [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/ex_ante/*/*"]                        [deneb_minimal_ex_ante]                        [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/get_head/*/*"]                       [deneb_minimal_get_head]                       [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/on_block/*/*"]                       [deneb_minimal_on_block]                       [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/reorg/*/*"]                          [deneb_minimal_reorg]                          [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/withholding/*/*"]                    [deneb_minimal_withholding]                    [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/sync/*/*/*"]                                     [deneb_sync_mainnet]                           [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/sync/*/*/*"]                                     [deneb_sync_minimal]                           [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/ex_ante/*/*"]                      [electra_mainnet_ex_ante]                      [Mainnet] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/get_head/*/*"]                     [electra_mainnet_get_head]                     [Mainnet] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/on_block/*/*"]                     [electra_mainnet_on_block]                     [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/deposit_with_reorg/*/*"]           [electra_deposit_with_reorg_minimal]           [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/ex_ante/*/*"]                      [electra_minimal_ex_ante]                      [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/get_head/*/*"]                     [electra_minimal_get_head]                     [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/on_block/*/*"]                     [electra_minimal_on_block]                     [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/reorg/*/*"]                        [electra_minimal_reorg]                        [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/withholding/*/*"]                  [electra_minimal_withholding]                  [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/sync/*/*/*"]                                   [electra_sync_mainnet]                         [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/sync/*/*/*"]                                   [electra_sync_minimal]                         [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/fulu/fork_choice/ex_ante/*/*"]                         [fulu_mainnet_ex_ante]                         [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/mainnet/fulu/fork_choice/get_head/*/*"]                        [fulu_mainnet_get_head]                        [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/mainnet/fulu/fork_choice/on_block/*/*"]                        [fulu_mainnet_on_block]                        [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/deposit_with_reorg/*/*"]              [fulu_deposit_with_reorg_minimal]              [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/ex_ante/*/*"]                         [fulu_minimal_ex_ante]                         [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/get_head/*/*"]                        [fulu_minimal_get_head]                        [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/on_block/*/*"]                        [fulu_minimal_on_block]                        [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/reorg/*/*"]                           [fulu_minimal_reorg]                           [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/fork_choice/withholding/*/*"]                     [fulu_minimal_withholding]                     [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/fulu/sync/*/*/*"]                                      [fulu_sync_mainnet]                            [Mainnet] [Fulu];
    ["consensus-spec-tests/tests/minimal/fulu/sync/*/*/*"]                                      [fulu_sync_minimal]                            [Minimal] [Fulu];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/ex_ante/*/*"]                        [gloas_mainnet_ex_ante]                        [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/get_head/*/*"]                       [gloas_mainnet_get_head]                       [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/get_parent_payload_status/*/*"]      [gloas_mainnet_get_parent_payload_status]      [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/on_attestation/*/*"]                 [gloas_mainnet_on_attestation]                 [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/on_block/*/*"]                       [gloas_mainnet_on_block]                       [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/on_execution_payload_envelope/*/*"]  [gloas_mainnet_on_execution_payload_envelope]  [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/on_payload_attestation_message/*/*"] [gloas_mainnet_on_payload_attestation_message] [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/payload_data_availability/*/*"]      [gloas_mainnet_payload_data_availability]      [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/mainnet/gloas/fork_choice/payload_timeliness/*/*"]             [gloas_mainnet_payload_timeliness]             [Mainnet] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/deposit_with_reorg/*/*"]             [gloas_minimal_deposit_with_reorg]             [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/ex_ante/*/*"]                        [gloas_minimal_ex_ante]                        [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/get_head/*/*"]                       [gloas_minimal_get_head]                       [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/get_parent_payload_status/*/*"]      [gloas_minimal_get_parent_payload_status]      [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/on_attestation/*/*"]                 [gloas_minimal_on_attestation]                 [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/on_block/*/*"]                       [gloas_minimal_on_block]                       [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/on_execution_payload_envelope/*/*"]  [gloas_minimal_on_execution_payload_envelope]  [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/on_payload_attestation_message/*/*"] [gloas_minimal_on_payload_attestation_message] [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/payload_data_availability/*/*"]      [gloas_minimal_payload_data_availability]      [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/payload_timeliness/*/*"]             [gloas_minimal_payload_timeliness]             [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/reorg/*/*"]                          [gloas_minimal_reorg]                          [Minimal] [Gloas];
    ["consensus-spec-tests/tests/minimal/gloas/fork_choice/withholding/*/*"]                    [gloas_minimal_withholding]                    [Minimal] [Gloas];
)]
#[test_resources(glob)]
fn function_name(case: Case<'_>) {
    let rt = tokio::runtime::Runtime::new().expect("Tokio runtime starts successfully in tests");
    let config = Arc::new(preset::default_config().start_and_stay_in(Phase::phase));

    rt.block_on(async {
        run_case::<preset>(&config, case, false).await;
    });
}

// Fast Confirmation Rule spec-test vectors (added in `consensus-specs` v1.7.0-alpha.9).
// Per the release layout, FCR vectors exist only under `tests/minimal/<phase>/fast_confirmation/`;
// mainnet presets are not generated. See `tests/formats/fast_confirmation/README.md`.
#[duplicate_item(
    glob                                                                                function_name                     preset    phase;
    ["consensus-spec-tests/tests/minimal/altair/fast_confirmation/*/*/*"]               [altair_minimal_fcr]              [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/bellatrix/fast_confirmation/*/*/*"]            [bellatrix_minimal_fcr]           [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/capella/fast_confirmation/*/*/*"]              [capella_minimal_fcr]             [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/deneb/fast_confirmation/*/*/*"]                [deneb_minimal_fcr]               [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/electra/fast_confirmation/*/*/*"]              [electra_minimal_fcr]             [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/fulu/fast_confirmation/*/*/*"]                 [fulu_minimal_fcr]                [Minimal] [Fulu];
    ["consensus-spec-tests/tests/minimal/gloas/fast_confirmation/*/*/*"]                [gloas_minimal_fcr]               [Minimal] [Gloas];
)]
#[test_resources(glob)]
fn function_name(case: Case<'_>) {
    let rt = tokio::runtime::Runtime::new().expect("Tokio runtime starts successfully in tests");
    let config = Arc::new(preset::default_config().start_and_stay_in(Phase::phase));

    rt.block_on(async {
        run_case::<preset>(&config, case, true).await;
    });
}

#[expect(clippy::too_many_lines)]
async fn run_case<P: Preset>(config: &Arc<Config>, case: Case<'_>, fast_confirmation_rule: bool) {
    let anchor_block = case
        .ssz::<_, BeaconBlock<P>>(config.as_ref(), "anchor_block")
        .with_zero_signature()
        .pipe(Arc::new);

    let anchor_state = case.ssz::<_, Arc<BeaconState<P>>>(config.as_ref(), "anchor_state");
    let meta = case.meta();
    let steps = case.yaml::<Vec<Step>>("steps");
    let genesis_time = anchor_state.genesis_time();
    let pubkey_cache = Arc::new(PubkeyCache::default());

    let tick_at_time = |time| {
        Tick::at_time::<P>(config, time, genesis_time)
            .expect("configurations used in tests have valid values of SECONDS_PER_SLOT")
    };

    let trust_all_signatures = matches!(case.meta().bls_setting, BlsSetting::Ignored);

    let mut context = Context::<P>::new(
        config.clone_arc(),
        pubkey_cache,
        anchor_block,
        anchor_state,
        false,
        fast_confirmation_rule,
        trust_all_signatures,
        fast_confirmation_rule,
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
                    if fast_confirmation_rule {
                        context.on_fcr_test_attestation(attestation, meta.bls_setting);
                    } else {
                        context.on_valid_test_attestation(attestation, meta.bls_setting);
                    }
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
                    .map(SszList::len_usize)
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
                        context.on_block_with_reconstructing_data_columns(&block);
                    } else {
                        context.on_block_with_missing_blobs(&block, expected_blob_count);
                    }
                } else if valid {
                    if fast_confirmation_rule {
                        context.on_valid_test_block(&block, meta.bls_setting);
                    } else {
                        context.on_valid_block(&block);
                    }
                } else if fast_confirmation_rule {
                    context.on_invalid_test_block(&block, meta.bls_setting);
                } else {
                    context.on_invalid_block(&block);
                }

                // FCR spec-test path: the pyspec test generator's `add_block` is atomic
                // (see `consensus-specs/tests/core/pyspec/.../helpers/fork_choice.py`) — it
                // calls `spec.on_block` directly and emits no `payload_status` step. Grandine
                // however defaults post-merge blocks to `PayloadStatus::Optimistic`
                // (`initial_payload_status` in `store.rs`) until the EL confirms. Since
                // `is_one_confirmed` MUST reject non-VALID blocks per the optimistic-sync spec,
                // we promote the payload to VALID here so the FCR check logic can see the
                // same world the pyspec does. Gated on `fast_confirmation_rule` so this does
                // not affect existing fork_choice tests.
                if fast_confirmation_rule
                    && valid
                    && let Some(payload) = block
                        .message()
                        .body()
                        .with_execution_payload()
                        .map(types::traits::BlockBodyWithExecutionPayload::execution_payload)
                {
                    let payload_status = PayloadStatusV1 {
                        status: PayloadValidationStatus::Valid,
                        latest_valid_hash: Some(payload.block_hash()),
                        validation_error: None,
                    };
                    context.on_notified_new_payload(
                        beacon_block_root,
                        payload.block_hash(),
                        payload_status,
                    );
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
            Step::PayloadAttestation {
                payload_attestation_message,
                valid,
            } => {
                let message = case.ssz::<_, Arc<PayloadAttestationMessage>>(
                    config.as_ref(),
                    payload_attestation_message,
                );

                if valid {
                    context.on_valid_payload_attestation_message(message);
                } else {
                    context.on_invalid_payload_attestation_message(message);
                }
            }
            Step::PayloadStatus(payload_status_with_block_hash) => {
                last_payload_status = Some(payload_status_with_block_hash);
            }
            Step::AttesterSlashing {
                attester_slashing: file_name,
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

                context.on_attester_slashing(attester_slashing);
            }
            Step::Checks { checks } => {
                let Checks {
                    head,
                    time,
                    genesis_time,
                    justified_checkpoint,
                    finalized_checkpoint,
                    proposer_boost_root,
                    payload_timeliness_vote,
                    payload_data_availability_vote,
                    previous_epoch_observed_justified_checkpoint,
                    current_epoch_observed_justified_checkpoint,
                    previous_epoch_greatest_unrealized_checkpoint,
                    previous_slot_head,
                    current_slot_head,
                    confirmed_root,
                    safe_execution_block_hash: _,
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

                if let Some(PtcVotes { block_root, votes }) = payload_timeliness_vote {
                    context.assert_payload_timeliness_vote(block_root, &votes);
                }

                if let Some(PtcVotes { block_root, votes }) = payload_data_availability_vote {
                    context.assert_payload_data_availability_vote(block_root, &votes);
                }

                // FCR checks — only populated by `fast_confirmation/*` test vectors.
                // Each `checks:` block with FCR fields corresponds to one explicit
                // `on_fast_confirmation()` call in the pyspec. In FCR spec-test mode, FCR does
                // NOT run automatically on tick, so we trigger it here to match pyspec exactly.
                let has_fcr_checks = fast_confirmation_rule
                    && (confirmed_root.is_some()
                        || previous_epoch_observed_justified_checkpoint.is_some());
                if has_fcr_checks {
                    context.run_fast_confirmation();
                }

                if let Some(checkpoint) = previous_epoch_observed_justified_checkpoint {
                    context.assert_fcr_previous_epoch_observed_justified_checkpoint(checkpoint);
                }

                if let Some(checkpoint) = current_epoch_observed_justified_checkpoint {
                    context.assert_fcr_current_epoch_observed_justified_checkpoint(checkpoint);
                }

                if let Some(checkpoint) = previous_epoch_greatest_unrealized_checkpoint {
                    context.assert_fcr_previous_epoch_greatest_unrealized_checkpoint(checkpoint);
                }

                if let Some(root) = previous_slot_head {
                    context.assert_fcr_previous_slot_head(root);
                }

                if let Some(root) = current_slot_head {
                    context.assert_fcr_current_slot_head(root);
                }

                if let Some(root) = confirmed_root {
                    context.assert_fcr_confirmed_root(root);
                }
            }
        }
    }
}
