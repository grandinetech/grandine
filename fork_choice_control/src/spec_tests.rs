use std::{path::PathBuf, sync::Arc};

use clock::Tick;
use duplicate::duplicate_item;
use execution_engine::{PayloadStatusV1, PayloadValidationStatus};
use helper_functions::misc;
use serde::Deserialize;
use spec_test_utils::Case;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use tap::Pipe as _;
use test_generator::test_resources;
use types::{
    combined::{Attestation, AttesterSlashing, BeaconBlock, BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::primitives::{Blob, KzgProof},
    nonstandard::{Phase, TimedPowBlock},
    phase0::{
        containers::Checkpoint,
        primitives::{ExecutionBlockHash, Slot, UnixSeconds, H256},
    },
    preset::{Mainnet, Minimal, Preset},
    traits::{BeaconState as _, PostDenebBeaconBlockBody, SignedBeaconBlock as _},
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
    },
    Block {
        block: PathBuf,
        blobs: Option<PathBuf>,
        proofs: Option<Vec<KzgProof>>,
        #[serde(default = "serde_aux::field_attributes::bool_true")]
        valid: bool,
    },
    MergeBlock {
        pow_block: PathBuf,
    },
    PayloadStatus {
        block_hash: ExecutionBlockHash,
        payload_status: PayloadStatus,
    },
    AttesterSlashing {
        attester_slashing: PathBuf,
    },
    Checks {
        checks: Box<Checks>,
    },
}

// `PayloadStatusV1` is deserialized from data containing keys in `camelCase`,
// whereas `consensus-spec-tests` uses `snake_case`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadStatus {
    status: PayloadValidationStatus,
    latest_valid_hash: Option<ExecutionBlockHash>,
    validation_error: Option<String>,
}

impl From<PayloadStatus> for PayloadStatusV1 {
    fn from(payload_status: PayloadStatus) -> Self {
        let PayloadStatus {
            status,
            latest_valid_hash,
            validation_error,
        } = payload_status;

        Self {
            status,
            latest_valid_hash,
            validation_error,
        }
    }
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadCheck {
    slot: Slot,
    root: H256,
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
    glob                                                                            function_name                      preset    phase;
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/ex_ante/*/*"]           [altair_mainnet_ex_ante]           [Mainnet] [Altair];
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/get_head/*/*"]          [altair_mainnet_get_head]          [Mainnet] [Altair];
    ["consensus-spec-tests/tests/mainnet/altair/fork_choice/on_block/*/*"]          [altair_mainnet_on_block]          [Mainnet] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/ex_ante/*/*"]           [altair_minimal_ex_ante]           [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/get_head/*/*"]          [altair_minimal_get_head]          [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/on_block/*/*"]          [altair_minimal_on_block]          [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/reorg/*/*"]             [altair_minimal_reorg]             [Minimal] [Altair];
    ["consensus-spec-tests/tests/minimal/altair/fork_choice/withholding/*/*"]       [altair_minimal_withholding]       [Minimal] [Altair];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/ex_ante/*/*"]        [bellatrix_mainnet_ex_ante]        [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/get_head/*/*"]       [bellatrix_mainnet_get_head]       [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/on_block/*/*"]       [bellatrix_mainnet_on_block]       [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/fork_choice/on_merge_block/*/*"] [bellatrix_mainnet_on_merge_block] [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/ex_ante/*/*"]        [bellatrix_minimal_ex_ante]        [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/get_head/*/*"]       [bellatrix_minimal_get_head]       [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/on_block/*/*"]       [bellatrix_minimal_on_block]       [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/on_merge_block/*/*"] [bellatrix_minimal_on_merge_block] [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/reorg/*/*"]          [bellatrix_minimal_reorg]          [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/fork_choice/withholding/*/*"]    [bellatrix_minimal_withholding]    [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/bellatrix/sync/*/*/*"]                     [bellatrix_sync_mainnet]           [Mainnet] [Bellatrix];
    ["consensus-spec-tests/tests/minimal/bellatrix/sync/*/*/*"]                     [bellatrix_sync_minimal]           [Minimal] [Bellatrix];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/ex_ante/*/*"]          [capella_mainnet_ex_ante]          [Mainnet] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/get_head/*/*"]         [capella_mainnet_get_head]         [Mainnet] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/fork_choice/on_block/*/*"]         [capella_mainnet_on_block]         [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/ex_ante/*/*"]          [capella_minimal_ex_ante]          [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/get_head/*/*"]         [capella_minimal_get_head]         [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/on_block/*/*"]         [capella_minimal_on_block]         [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/reorg/*/*"]            [capella_minimal_reorg]            [Minimal] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/fork_choice/withholding/*/*"]      [capella_minimal_withholding]      [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/capella/sync/*/*/*"]                       [capella_sync_mainnet]             [Mainnet] [Capella];
    ["consensus-spec-tests/tests/minimal/capella/sync/*/*/*"]                       [capella_sync_minimal]             [Minimal] [Capella];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/ex_ante/*/*"]            [deneb_mainnet_ex_ante]            [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/get_head/*/*"]           [deneb_mainnet_get_head]           [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/fork_choice/on_block/*/*"]           [deneb_mainnet_on_block]           [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/ex_ante/*/*"]            [deneb_minimal_ex_ante]            [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/get_head/*/*"]           [deneb_minimal_get_head]           [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/on_block/*/*"]           [deneb_minimal_on_block]           [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/reorg/*/*"]              [deneb_minimal_reorg]              [Minimal] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/fork_choice/withholding/*/*"]        [deneb_minimal_withholding]        [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/deneb/sync/*/*/*"]                         [deneb_sync_mainnet]               [Mainnet] [Deneb];
    ["consensus-spec-tests/tests/minimal/deneb/sync/*/*/*"]                         [deneb_sync_minimal]               [Minimal] [Deneb];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/ex_ante/*/*"]          [electra_mainnet_ex_ante]          [Mainnet] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/get_head/*/*"]         [electra_mainnet_get_head]         [Mainnet] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/fork_choice/on_block/*/*"]         [electra_mainnet_on_block]         [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/ex_ante/*/*"]          [electra_minimal_ex_ante]          [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/get_head/*/*"]         [electra_minimal_get_head]         [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/on_block/*/*"]         [electra_minimal_on_block]         [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/reorg/*/*"]            [electra_minimal_reorg]            [Minimal] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/fork_choice/withholding/*/*"]      [electra_minimal_withholding]      [Minimal] [Electra];
    ["consensus-spec-tests/tests/mainnet/electra/sync/*/*/*"]                       [electra_sync_mainnet]             [Mainnet] [Electra];
    ["consensus-spec-tests/tests/minimal/electra/sync/*/*/*"]                       [electra_sync_minimal]             [Minimal] [Electra];
)]
#[test_resources(glob)]
fn function_name(case: Case) {
    let config = Arc::new(preset::default_config().start_and_stay_in(Phase::phase));
    run_case::<preset>(&config, case);
}

#[allow(clippy::too_many_lines)]
fn run_case<P: Preset>(config: &Arc<Config>, case: Case) {
    let anchor_block = case
        .ssz::<_, BeaconBlock<P>>(config.as_ref(), "anchor_block")
        .with_zero_signature()
        .pipe(Arc::new);

    let anchor_state = case.ssz::<_, Arc<BeaconState<P>>>(config.as_ref(), "anchor_state");
    let steps = case.yaml::<Vec<Step>>("steps");
    let genesis_time = anchor_state.genesis_time();

    let tick_at_time = |time| {
        Tick::at_time(config, time, genesis_time)
            .expect("configurations used in tests have valid values of SECONDS_PER_SLOT")
    };

    let mut context = Context::<P>::new(config.clone_arc(), anchor_block, anchor_state, false);

    for step in steps {
        match step {
            Step::Tick { tick } => {
                let tick = tick_at_time(tick);
                context.on_tick(tick);
            }
            Step::Attestation { attestation } => {
                let attestation = case.ssz::<_, Attestation<P>>(config, attestation);
                context.on_test_attestation(attestation);
            }
            Step::Block {
                block,
                blobs,
                proofs,
                valid,
            } => {
                type BlobBundle<P> = ContiguousList<Blob<P>, <P as Preset>::MaxBlobsPerBlock>;

                let block = case.ssz::<_, Arc<SignedBeaconBlock<P>>>(config.as_ref(), block);

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

                let expected_blob_count = block
                    .message()
                    .body()
                    .post_deneb()
                    .map(PostDenebBeaconBlockBody::blob_kzg_commitments)
                    .map(|contiguous_list| contiguous_list.len())
                    .unwrap_or_default();

                for blob_sidecar in blob_sidecars {
                    context.on_blob_sidecar(blob_sidecar);
                }

                if !valid && expected_blob_count > 0 {
                    context.on_block_with_missing_blobs(&block, expected_blob_count);
                } else if valid {
                    context.on_valid_block(&block);
                } else {
                    context.on_invalid_block(&block);
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
            Step::PayloadStatus {
                block_hash,
                payload_status,
            } => {
                context.on_notified_new_payload(block_hash, payload_status.into());
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
                    Phase::Electra => AttesterSlashing::Electra(case.ssz(config, file_name)),
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
                } = *checks;

                if let Some(HeadCheck { slot, root }) = head {
                    context.assert_head(slot, root);
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
