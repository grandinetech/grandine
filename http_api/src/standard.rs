//! Implementation of the [Eth Beacon Node API].
//!
//! [Eth Beacon Node API]: https://ethereum.github.io/beacon-APIs/

// This makes `http_api::routing` less messy at the cost of coupling to `axum` even more.
#![allow(clippy::unused_async)]

use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, ensure, Error as AnyhowError, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse as _, Response, Sse,
    },
    Json,
};
use block_producer::{BlockBuildOptions, BlockProducer, ProposerData, ValidatorBlindedBlock};
use bls::{PublicKeyBytes, SignatureBytes};
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use enum_iterator::Sequence as _;
use eth1_api::ApiController;
use eth2_libp2p::PeerId;
use fork_choice_control::{ForkChoiceContext, ForkTip, Wait};
use futures::{
    channel::mpsc::UnboundedSender,
    stream::{FuturesOrdered, FuturesUnordered, Stream, StreamExt as _},
};
use genesis::AnchorCheckpointProvider;
use helper_functions::{accessors, misc};
use http_api_utils::{BlockId, StateId};
use itertools::{izip, Either, Itertools as _};
use liveness_tracker::ApiToLiveness;
use log::{debug, info, warn};
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, Origin, PoolAdditionOutcome, SyncCommitteeAggPool,
};
use p2p::{
    ApiToP2p, BeaconCommitteeSubscription, NetworkConfig, NodeIdentity, NodePeer, NodePeerCount,
    NodePeersQuery, SyncCommitteeSubscription, ToSubnetService,
};
use prometheus_metrics::Metrics;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{As, DisplayFromStr};
use ssz::{ContiguousList, SszHash as _};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    capella::containers::{SignedBlsToExecutionChange, Withdrawal},
    combined::{BeaconBlock, BeaconState, SignedBeaconBlock, SignedBlindedBeaconBlock},
    config::Config as ChainConfig,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::BlobIndex,
    },
    nonstandard::{
        BlockRewards, Phase, RelativeEpoch, ValidationOutcome, WithBlobsAndMev, WithStatus,
        WEI_IN_GWEI,
    },
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        containers::{
            Attestation, AttestationData, AttesterSlashing, Checkpoint, Fork, ProposerSlashing,
            SignedAggregateAndProof, SignedBeaconBlockHeader, SignedVoluntaryExit, Validator,
        },
        primitives::{
            ChainId, CommitteeIndex, Epoch, ExecutionAddress, Gwei, Slot, SubnetId, Uint256,
            UnixSeconds, ValidatorIndex, Version, H256,
        },
    },
    preset::{Preset, SyncSubcommitteeSize},
    traits::{BeaconBlock as _, BeaconState as _, SignedBeaconBlock as _},
};
use validator::{ApiToValidator, ValidatorConfig};

use crate::{
    block_id,
    error::{Error, IndexedError},
    events::{EventChannels, Topic},
    extractors::{EthJson, EthJsonOrSsz, EthPath, EthQuery},
    full_config::FullConfig,
    misc::{APIBlock, BackSyncedStatus, BroadcastValidation, SignedAPIBlock, SyncedStatus},
    response::{EthResponse, JsonOrSsz},
    state_id,
    validator_status::{
        ValidatorId, ValidatorIdQuery, ValidatorIdsAndStatuses, ValidatorIdsAndStatusesBody,
        ValidatorIdsAndStatusesQuery, ValidatorStatus,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobSidecarsQuery {
    indices: Option<Vec<BlobIndex>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCommitteesQuery {
    epoch: Option<Epoch>,
    index: Option<ValidatorIndex>,
    slot: Option<Slot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSyncCommitteesQuery {
    epoch: Option<Epoch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRandaoQuery {
    epoch: Option<Epoch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeadersQuery {
    slot: Option<Slot>,
    parent_root: Option<H256>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolAttestationQuery {
    slot: Slot,
    committee_index: CommitteeIndex,
}

#[derive(Deserialize)]
// Allow custom fields in `ValidatorBlockQuery`.
// This is required for Lodestar interoperability.
// #[serde(deny_unknown_fields)]
pub struct ValidatorBlockQuery {
    randao_reveal: SignatureBytes,
    graffiti: Option<H256>,
    #[serde(default, with = "serde_utils::bool_as_empty_string")]
    skip_randao_verification: bool,
}

#[derive(Deserialize)]
// Allow custom fields in `ValidatorBlockQueryV3`.
// This is required for Lodestar interoperability.
// #[serde(deny_unknown_fields)]
pub struct ValidatorBlockQueryV3 {
    randao_reveal: SignatureBytes,
    graffiti: Option<H256>,
    #[serde(default, with = "serde_utils::bool_as_empty_string")]
    skip_randao_verification: bool,
    builder_boost_factor: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCommitteeContributionQuery {
    slot: Slot,
    subcommittee_index: SubcommitteeIndex,
    beacon_block_root: H256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateAttestationQuery {
    attestation_data_root: H256,
    slot: Slot,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationDataQuery {
    committee_index: CommitteeIndex,
    slot: Slot,
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(
        default,
        deserialize_with = "serde_aux::field_attributes::deserialize_vec_from_string_or_vec"
    )]
    topics: Vec<Topic>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedWithdrawalsQuery {
    proposal_slot: Option<Slot>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct PublishBlockQuery {
    broadcast_validation: Option<BroadcastValidation>,
}

#[allow(clippy::struct_field_names)]
#[derive(Serialize)]
pub struct GetGenesisResponse {
    #[serde(with = "serde_utils::string_or_native")]
    genesis_time: UnixSeconds,
    genesis_validators_root: H256,
    genesis_fork_version: Version,
}

#[derive(Serialize)]
pub struct RootResponse {
    root: H256,
}

#[derive(Serialize)]
pub struct BlockRewardsResponse {
    #[serde(with = "serde_utils::string_or_native")]
    proposer_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    total: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    attestations: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    sync_aggregate: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    proposer_slashings: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    attester_slashings: Gwei,
}

#[derive(Serialize)]
pub struct SyncCommitteeRewardsResponse {
    #[serde(with = "serde_utils::string_or_native")]
    validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    reward: i64,
}

#[derive(Serialize)]
pub struct StateFinalityCheckpointsResponse {
    previous_justified: Checkpoint,
    current_justified: Checkpoint,
    finalized: Checkpoint,
}

#[derive(Serialize)]
pub struct StateRandaoResponse {
    randao: H256,
}

#[derive(Serialize)]
pub struct StateValidatorResponse {
    #[serde(with = "serde_utils::string_or_native")]
    balance: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    index: ValidatorIndex,
    status: ValidatorStatus,
    validator: Validator,
}

#[derive(Serialize)]
pub struct StateCommitteeResponse {
    #[serde(with = "serde_utils::string_or_native")]
    index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    #[serde(with = "As::<Vec<DisplayFromStr>>")]
    validators: Vec<ValidatorIndex>,
}

#[derive(Default, Serialize)]
struct StateSyncCommitteeResponse<'indices> {
    #[serde(with = "As::<Vec<DisplayFromStr>>")]
    validators: Vec<ValidatorIndex>,
    #[serde(with = "As::<Vec<&[DisplayFromStr]>>")]
    validator_aggregates: Vec<&'indices [ValidatorIndex]>,
}

#[derive(Serialize)]
pub struct StateValidatorBalanceResponse {
    #[serde(with = "serde_utils::string_or_native")]
    index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    balance: Gwei,
}

#[derive(Serialize)]
pub struct BlockHeadersResponse {
    root: H256,
    canonical: bool,
    header: SignedBeaconBlockHeader,
}

#[derive(Serialize)]
pub struct DepositContractResponse {
    address: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    chain_id: ChainId,
}

#[derive(Serialize)]
pub struct MetaPeersResponse {
    // The absence of `#[serde(with = "serde_utils::string_or_native")]` is intentional.
    // The `count` field is supposed to contain a number.
    count: usize,
}

#[derive(Serialize)]
pub struct NodePeerCountResponse {
    #[serde(with = "serde_utils::string_or_native")]
    connected: u64,
    #[serde(with = "serde_utils::string_or_native")]
    connecting: u64,
    #[serde(with = "serde_utils::string_or_native")]
    disconnected: u64,
    #[serde(with = "serde_utils::string_or_native")]
    disconnecting: u64,
}

impl From<NodePeerCount> for NodePeerCountResponse {
    fn from(node_peer_count: NodePeerCount) -> Self {
        let NodePeerCount {
            connected,
            connecting,
            disconnected,
            disconnecting,
        } = node_peer_count;

        Self {
            connected,
            connecting,
            disconnected,
            disconnecting,
        }
    }
}

#[derive(Serialize)]
struct NodeVersionResponse<'version> {
    version: Option<&'version str>,
}

// TODO(Grandine Team): `NodeSyncingResponse` should have an `el_offline` field.
//                      It was added in Eth Beacon Node API version 2.4.0.
//                      See <https://ethereum.github.io/beacon-APIs/#/Node/getSyncingStatus>.
#[derive(Serialize)]
pub struct NodeSyncingResponse {
    #[serde(with = "serde_utils::string_or_native")]
    head_slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    sync_distance: Slot,
    is_syncing: bool,
    is_optimistic: bool,
}

#[derive(Serialize)]
pub struct ValidatorAttesterDutyResponse {
    #[serde(with = "serde_utils::string_or_native")]
    committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::string_or_native")]
    committee_length: usize,
    #[serde(with = "serde_utils::string_or_native")]
    committees_at_slot: u64,
    pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    validator_committee_index: usize,
    #[serde(with = "serde_utils::string_or_native")]
    validator_index: ValidatorIndex,
}

#[derive(Serialize)]
pub struct ValidatorProposerDutyResponse {
    pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    validator_index: ValidatorIndex,
    #[serde(with = "serde_utils::string_or_native")]
    slot: Slot,
}

#[derive(Serialize)]
pub struct ValidatorSyncDutyResponse {
    pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::string_or_native")]
    validator_index: ValidatorIndex,
    #[serde(with = "As::<Vec<DisplayFromStr>>")]
    validator_sync_committee_indices: Vec<usize>,
}

#[derive(Serialize)]
pub struct ValidatorLivenessResponse {
    #[serde(with = "serde_utils::string_or_native")]
    index: ValidatorIndex,
    is_live: bool,
}

/// `GET /eth/v1/beacon/genesis`
pub async fn genesis<P: Preset>(
    State(chain_config): State<Arc<ChainConfig>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
) -> Result<EthResponse<GetGenesisResponse>, Error> {
    let anchor_state = anchor_checkpoint_provider.checkpoint().value.state;

    let response = GetGenesisResponse {
        genesis_time: anchor_state.genesis_time(),
        genesis_validators_root: anchor_state.genesis_validators_root(),
        genesis_fork_version: chain_config.genesis_fork_version,
    };

    Ok(EthResponse::json(response))
}

/// `GET /eth/v1/builder/states/{state_id}/expected_withdrawals`
pub async fn expected_withdrawals<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(query): EthQuery<ExpectedWithdrawalsQuery>,
) -> Result<EthResponse<Vec<Withdrawal>>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let proposal_slot = query.proposal_slot.unwrap_or_else(|| state.slot() + 1);

    // If `state` is a preprocessed state (i.e., `state.latest_block_header().slot < state.slot()`),
    // it is possible to compute withdrawals even when `proposal_slot` is equal to `state.slot()`.
    // We return an error instead to match the behavior of Lighthouse. Note that
    // `Snapshot::state_at_slot` returning preprocessed states was also based on Lighthouse.
    if proposal_slot <= state.slot() {
        return Err(Error::ProposalSlotNotLaterThanStateSlot);
    }

    let state = (state.slot() > GENESIS_SLOT)
        .then(|| {
            let block_root = accessors::latest_block_root(&state);
            controller.preprocessed_state_post_block(block_root, proposal_slot)
        })
        .transpose()?
        .unwrap_or(state);

    let state = state.post_capella().ok_or(Error::StatePreCapella)?;
    let expected_withdrawals = transition_functions::capella::get_expected_withdrawals(state)?;

    Ok(EthResponse::json(expected_withdrawals)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/root`
pub async fn state_root<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
) -> Result<EthResponse<RootResponse>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let root = state.hash_tree_root();

    Ok(EthResponse::json(RootResponse { root })
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/fork`
pub async fn state_fork<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
) -> Result<EthResponse<Fork>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    Ok(EthResponse::json(state.fork())
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints`
pub async fn state_finality_checkpoints<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
) -> Result<EthResponse<StateFinalityCheckpointsResponse>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let response = StateFinalityCheckpointsResponse {
        previous_justified: state.previous_justified_checkpoint(),
        current_justified: state.current_justified_checkpoint(),
        finalized: state.finalized_checkpoint(),
    };

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/validators`
pub async fn get_state_validators<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(ids_and_statuses): EthQuery<ValidatorIdsAndStatusesQuery>,
) -> Result<EthResponse<Vec<StateValidatorResponse>>, Error> {
    state_validators(
        &controller,
        &anchor_checkpoint_provider,
        state_id,
        &ids_and_statuses,
    )
}

/// `POST /eth/v1/beacon/states/{state_id}/validators`
pub async fn post_state_validators<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthJson(ids_and_statuses): EthJson<ValidatorIdsAndStatusesBody>,
) -> Result<EthResponse<Vec<StateValidatorResponse>>, Error> {
    state_validators(
        &controller,
        &anchor_checkpoint_provider,
        state_id,
        &ids_and_statuses,
    )
}

/// `GET /eth/v1/beacon/states/{state_id}/validators/{validator_id}`
pub async fn state_validator<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath((state_id, validator_id)): EthPath<(StateId, ValidatorId)>,
) -> Result<EthResponse<StateValidatorResponse>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let validator_index = validator_id
        .validator_index(&state)
        .ok_or(Error::ValidatorNotFound)?;

    let validator = state
        .validators()
        .get(validator_index)
        .map_err(AnyhowError::new)?;

    let balance = state
        .balances()
        .get(validator_index)
        .copied()
        .expect("list of validators and list of balances should have the same length");

    let response = StateValidatorResponse {
        balance,
        index: validator_index,
        status: ValidatorStatus::new(validator, &state),
        validator: validator.clone(),
    };

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/validator_balances`
pub async fn state_validator_balances<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(query): EthQuery<ValidatorIdQuery>,
) -> Result<EthResponse<Vec<StateValidatorBalanceResponse>>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let balances = izip!(
        0..,
        state.validators(),
        state.balances().into_iter().copied(),
    )
    .filter(|(index, validator, _)| {
        query.id.is_empty()
            || query.id.iter().any(|validator_id| match validator_id {
                ValidatorId::ValidatorIndex(validator_index) => index == validator_index,
                ValidatorId::PublicKey(pubkey) => validator.pubkey.as_bytes() == pubkey,
            })
    })
    .map(|(index, _, balance)| StateValidatorBalanceResponse { index, balance })
    .collect();

    Ok(EthResponse::json(balances)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/committees`
pub async fn state_committees<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(query): EthQuery<StateCommitteesQuery>,
) -> Result<EthResponse<Vec<StateCommitteeResponse>>, Error> {
    let WithStatus {
        value: mut state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let state_epoch = misc::compute_epoch_at_slot::<P>(state.slot());
    let epoch = query.epoch.unwrap_or(state_epoch);

    let slots = match query.slot {
        Some(slot) => {
            if misc::compute_epoch_at_slot::<P>(slot) != epoch {
                return Err(Error::SlotNotInEpoch);
            }
            Either::Left(core::iter::once(slot))
        }
        None => Either::Right(misc::slots_in_epoch::<P>(epoch)),
    };

    // TODO(Grandine Team): Optimize state lookup.
    //                      The state is looked up twice, first in `StateId::state` above,
    //                      then in `Controller::state_at_slot`.
    //                      That means twice the amount of database lookups and state transitions.
    if epoch == accessors::get_next_epoch(&state)
        || epoch == misc::compute_epoch_at_slot::<P>(controller.slot()) + 1
    {
        let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        state = controller
            .state_at_slot(start_slot)?
            .ok_or(Error::StateNotFound)?
            .value;
    }

    let relative_epoch = accessors::relative_epoch(&state, epoch)?;
    let committee_count_per_slot = accessors::get_committee_count_per_slot(&state, relative_epoch);

    let indices = query
        .index
        .map(core::iter::once)
        .map(Either::Left)
        .unwrap_or_else(|| Either::Right(0..committee_count_per_slot));

    let responses = slots
        .cartesian_product(indices)
        .map(|(slot, index)| {
            let committee = accessors::beacon_committee(&state, slot, index)?;

            Ok(StateCommitteeResponse {
                index,
                slot,
                validators: committee.into_iter().collect(),
            })
        })
        .collect::<Result<_>>()?;

    Ok(EthResponse::json(responses)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/states/{state_id}/sync_committees`
pub async fn state_sync_committees<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(query): EthQuery<StateSyncCommitteesQuery>,
) -> Result<Response, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let Some(state) = state.post_altair() else {
        return Ok(EthResponse::json(StateSyncCommitteeResponse::default())
            .execution_optimistic(optimistic)
            .finalized(finalized)
            .into_response());
    };

    let state_epoch = misc::compute_epoch_at_slot::<P>(state.slot());
    let state_period = misc::sync_committee_period::<P>(state_epoch);
    let requested_epoch = query.epoch.unwrap_or(state_epoch);
    let requested_period = misc::sync_committee_period::<P>(requested_epoch);

    let committee = if requested_period == state_period {
        state.current_sync_committee()
    } else if requested_period == state_period + 1 {
        state.next_sync_committee()
    } else {
        return Err(Error::EpochNotInSyncCommitteePeriod);
    };

    let validator_indices = committee
        .pubkeys
        .iter()
        .filter_map(|pubkey| accessors::index_of_public_key(state, pubkey.to_bytes()))
        .collect_vec();

    let validators = validator_indices.clone();

    let validator_aggregates = validator_indices
        .chunks_exact(SyncSubcommitteeSize::<P>::USIZE)
        .collect();

    let response = StateSyncCommitteeResponse {
        validators,
        validator_aggregates,
    };

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized)
        .into_response())
}

/// `GET /eth/v1/beacon/states/{state_id}/randao`
pub async fn state_randao<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    EthQuery(query): EthQuery<StateRandaoQuery>,
) -> Result<EthResponse<StateRandaoResponse>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    // If `epoch` is in the future, return the RANDAO mix for the current epoch.
    // This matches how RANDAO mixes are updated during epoch transitions.
    // RANDAO mixes for future epochs are unstable, but so is the one for the current epoch.
    let state_epoch = accessors::get_current_epoch(&state);
    let epoch = query.epoch.unwrap_or(state_epoch).min(state_epoch);
    let difference = state_epoch - epoch;

    if difference > P::EpochsPerHistoricalVector::U64 {
        return Err(Error::EpochOutOfRangeForStateRandao);
    };

    let randao = accessors::get_randao_mix(&state, epoch);
    let response = StateRandaoResponse { randao };

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

// TODO(Grandine Team): Always returning the header of a single block appears to be incorrect.
//                      The shape of the response (an array) and the wording of [the specification]
//                      imply the endpoint should return headers for all matching blocks, not just the
//                      canonical one. [Lighthouse] and [Nimbus] also return only canonical headers,
//                      but the other 3 clients can return multiple.
//
//                      [the specification]: https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders
//                      [Lighthouse]:        https://github.com/sigp/lighthouse/blob/441fc1691b69f9edc4bbdc6665f3efab16265c9b/beacon_node/http_api/src/lib.rs#L1129-L1136
//                      [Nimbus]:            https://github.com/status-im/nimbus-eth2/blob/d19ffcaa0d9505d81a83d7be0049154cae871c7b/beacon_chain/rpc/rest_beacon_api.nim#L781-L822
/// `GET /eth/v1/beacon/headers`
pub async fn block_headers<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    EthQuery(query): EthQuery<BlockHeadersQuery>,
) -> Result<EthResponse<[BlockHeadersResponse; 1]>, Error> {
    let opt_block_by_slot = |slot| -> Result<_> {
        if let Some(root) = controller.block_root_by_slot(slot)? {
            if let Some(with_status) = controller.block_by_root(root)? {
                return Ok(Some((root, with_status)));
            }
        }

        Ok(None)
    };

    let block_result = match query {
        // Default to blocks at the same slot as the head rather than the head directly.
        // [The specification] refers to the "head slot" and "blocks" (plural).
        // Lighthouse looks up the head directly, but the other 4 implementations use its slot.
        // This currently makes no difference because we never return multiple headers.
        //
        // [The specification]: https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders
        BlockHeadersQuery {
            slot: None,
            parent_root: None,
        } => opt_block_by_slot(controller.head_slot())?,
        BlockHeadersQuery {
            slot: Some(slot),
            parent_root: None,
        } => opt_block_by_slot(slot)?,
        BlockHeadersQuery {
            slot: None,
            parent_root: Some(parent_root),
        } => controller
            .block_by_root(parent_root)?
            .and_then(|parent_block| parent_block.value.message().slot().checked_add(1))
            .map(opt_block_by_slot)
            .transpose()?
            .flatten()
            .filter(|(_, with_status)| with_status.value.message().parent_root() == parent_root),
        BlockHeadersQuery {
            slot: Some(slot),
            parent_root: Some(parent_root),
        } => opt_block_by_slot(slot)?
            .filter(|(_, with_status)| with_status.value.message().parent_root() == parent_root),
    };

    let (root, with_status) = block_result.ok_or(Error::BlockNotFound)?;

    let WithStatus {
        value: block,
        optimistic,
        finalized,
    } = with_status;

    let response = BlockHeadersResponse {
        root,
        canonical: true,
        header: block.to_header(),
    };

    Ok(EthResponse::json([response])
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/headers/{block_id}`
pub async fn block_id_headers<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
) -> Result<EthResponse<BlockHeadersResponse>, Error> {
    let root = block_id::block_root(block_id, &controller, &anchor_checkpoint_provider)?.value;

    let WithStatus {
        value: block,
        optimistic,
        finalized,
    } = controller
        .block_by_root(root)?
        .ok_or(Error::BlockNotFound)?;

    let response = BlockHeadersResponse {
        root,
        // TODO(Grandine Team): The block may be non-canonical if `block_id` is `BlockId::Root(_)`.
        canonical: true,
        header: block.to_header(),
    };

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v2/beacon/blocks/{block_id}`
pub async fn block<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
    headers: HeaderMap,
) -> Result<EthResponse<Arc<SignedBeaconBlock<P>>, (), JsonOrSsz>, Error> {
    let WithStatus {
        value: block,
        optimistic,
        finalized,
    } = block_id::block(block_id, &controller, &anchor_checkpoint_provider)?;

    let version = block.phase();

    Ok(EthResponse::json_or_ssz(block, &headers)?
        .execution_optimistic(optimistic)
        .finalized(finalized)
        .version(version))
}

/// `GET /eth/v1/beacon/blocks/{block_id}/root`
pub async fn block_root<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
) -> Result<EthResponse<RootResponse>, Error> {
    let WithStatus {
        value: root,
        optimistic,
        finalized,
    } = block_id::block_root(block_id, &controller, &anchor_checkpoint_provider)?;

    Ok(EthResponse::json(RootResponse { root })
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/blocks/{block_id}/attestations`
pub async fn block_attestations<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
) -> Result<Response, Error> {
    let WithStatus {
        value: block,
        optimistic,
        finalized,
    } = block_id::block(block_id, &controller, &anchor_checkpoint_provider)?;

    block
        .message()
        .body()
        .attestations()
        .pipe(EthResponse::json)
        .execution_optimistic(optimistic)
        .finalized(finalized)
        .into_response()
        .pipe(Ok)
}

/// `GET /eth/v1/beacon/blob_sidecars/{block_id}`
pub async fn blob_sidecars<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
    EthQuery(query): EthQuery<BlobSidecarsQuery>,
    headers: HeaderMap,
) -> Result<
    EthResponse<ContiguousList<Arc<BlobSidecar<P>>, P::MaxBlobsPerBlock>, (), JsonOrSsz>,
    Error,
> {
    let block_root =
        block_id::block_root(block_id, &controller, &anchor_checkpoint_provider)?.value;
    let blob_identifiers = query
        .indices
        .unwrap_or_else(|| (0..P::MaxBlobsPerBlock::U64).collect())
        .into_iter()
        .map(|index| {
            ensure!(
                index < P::MaxBlobsPerBlock::U64,
                Error::InvalidBlobIndex(index)
            );

            Ok(BlobIdentifier { block_root, index })
        })
        .collect::<Result<Vec<_>>>()?;

    let blob_sidecars = controller.blob_sidecars_by_ids(blob_identifiers)?;
    let blob_sidecars =
        ContiguousList::try_from_iter(blob_sidecars.into_iter()).map_err(AnyhowError::new)?;

    Ok(EthResponse::json_or_ssz(blob_sidecars, &headers)?)
}

/// `POST /eth/v1/beacon/blocks`
pub async fn publish_block<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJsonOrSsz(signed_api_block): EthJsonOrSsz<Box<SignedAPIBlock<P>>>,
) -> Result<StatusCode, Error> {
    let (signed_beacon_block, proofs, blobs) = signed_api_block.split();

    let blob_sidecars =
        misc::construct_blob_sidecars(&signed_beacon_block, blobs.into_iter(), proofs.into_iter())?;

    publish_signed_block(
        Arc::new(signed_beacon_block),
        blob_sidecars,
        controller,
        api_to_p2p_tx,
    )
    .await
}

/// `POST /eth/v1/beacon/blinded_blocks`
pub async fn publish_blinded_block<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJsonOrSsz(signed_blinded_block): EthJsonOrSsz<Box<SignedBlindedBeaconBlock<P>>>,
) -> Result<StatusCode, Error> {
    let execution_payload = block_producer
        .publish_signed_blinded_block(&signed_blinded_block)
        .await;

    let WithBlobsAndMev {
        value: execution_payload,
        proofs,
        blobs,
        ..
    } = execution_payload.ok_or(Error::ExecutionPayloadNotAvailable)?;

    let (message, signature) = signed_blinded_block.split();

    let signed_beacon_block = message
        .with_execution_payload(execution_payload)
        .map_err(AnyhowError::new)?
        .with_signature(signature)
        .pipe(Arc::new);

    let blob_sidecars = misc::construct_blob_sidecars(
        &signed_beacon_block,
        blobs.unwrap_or_default().into_iter(),
        proofs.unwrap_or_default().into_iter(),
    )?;

    publish_signed_block(
        signed_beacon_block,
        blob_sidecars,
        controller,
        api_to_p2p_tx,
    )
    .await
}

/// `POST /eth/v2/beacon/blinded_blocks`
pub async fn publish_blinded_block_v2<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthQuery(query): EthQuery<PublishBlockQuery>,
    EthJsonOrSsz(signed_blinded_block): EthJsonOrSsz<Box<SignedBlindedBeaconBlock<P>>>,
) -> Result<StatusCode, Error> {
    let execution_payload = block_producer
        .publish_signed_blinded_block(&signed_blinded_block)
        .await;

    let WithBlobsAndMev {
        value: execution_payload,
        proofs,
        blobs,
        ..
    } = execution_payload.ok_or(Error::ExecutionPayloadNotAvailable)?;

    let (message, signature) = signed_blinded_block.split();

    let signed_beacon_block = message
        .with_execution_payload(execution_payload)
        .map_err(AnyhowError::new)?
        .with_signature(signature)
        .pipe(Arc::new);

    let blob_sidecars = misc::construct_blob_sidecars(
        &signed_beacon_block,
        blobs.unwrap_or_default().into_iter(),
        proofs.unwrap_or_default().into_iter(),
    )?;

    publish_signed_block_v2(
        signed_beacon_block,
        blob_sidecars,
        query.broadcast_validation.unwrap_or_default(),
        controller,
        api_to_p2p_tx,
    )
    .await
}

/// `POST /eth/v2/beacon/blocks`
pub async fn publish_block_v2<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthQuery(query): EthQuery<PublishBlockQuery>,
    EthJsonOrSsz(signed_api_block): EthJsonOrSsz<Box<SignedAPIBlock<P>>>,
) -> Result<StatusCode, Error> {
    let (signed_beacon_block, proofs, blobs) = signed_api_block.split();

    let blob_sidecars =
        misc::construct_blob_sidecars(&signed_beacon_block, blobs.into_iter(), proofs.into_iter())?;

    publish_signed_block_v2(
        Arc::new(signed_beacon_block),
        blob_sidecars,
        query.broadcast_validation.unwrap_or_default(),
        controller,
        api_to_p2p_tx,
    )
    .await
}

/// `GET /eth/v1/beacon/rewards/blocks/{block_id}`
pub async fn block_rewards<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
) -> Result<EthResponse<BlockRewardsResponse>, Error> {
    let WithStatus {
        value: signed_block,
        optimistic,
        finalized,
    } = block_id::block(block_id, &controller, &anchor_checkpoint_provider)?;

    let block: BeaconBlock<P> = Arc::unwrap_or_clone(signed_block).into();
    let block_slot = block.slot();

    let block_rewards = (block_slot > GENESIS_SLOT)
        .then(|| {
            let parent_root = block.parent_root();

            let state = controller.preprocessed_state_post_block(parent_root, block_slot)?;

            controller
                .block_processor()
                .process_trusted_block_with_report(state, &block)
        })
        .transpose()?
        .and_then(|(_, rewards)| rewards)
        .unwrap_or_default();

    let BlockRewards {
        total,
        attestations,
        sync_aggregate,
        proposer_slashings,
        attester_slashings,
    } = block_rewards;

    let rewards_response = BlockRewardsResponse {
        proposer_index: block.proposer_index(),
        total,
        attestations,
        sync_aggregate,
        proposer_slashings,
        attester_slashings,
    };

    Ok(EthResponse::json(rewards_response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `POST /eth/v1/beacon/rewards/sync_committee/{block_id}`
pub async fn sync_committee_rewards<P: Preset, W: Wait>(
    State(chain_config): State<Arc<ChainConfig>>,
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(block_id): EthPath<BlockId>,
    EthJson(validator_ids): EthJson<Vec<ValidatorId>>,
) -> Result<EthResponse<Vec<SyncCommitteeRewardsResponse>>, Error> {
    let WithStatus {
        value: block,
        optimistic,
        finalized,
    } = block_id::block(block_id, &controller, &anchor_checkpoint_provider)?;

    let block_slot = block.message().slot();

    if block_slot == GENESIS_SLOT || block.phase() < Phase::Altair {
        return Ok(EthResponse::json(vec![])
            .execution_optimistic(optimistic)
            .finalized(finalized));
    }

    let parent_root = block.message().parent_root();

    let mut state = controller.preprocessed_state_post_block(parent_root, block_slot)?;

    let sync_committee_deltas = transition_functions::combined::state_transition_for_report(
        &chain_config,
        state.make_mut(),
        &block,
    )?
    .sync_committee_deltas;

    let response = if validator_ids.is_empty() {
        sync_committee_deltas.into_iter().pipe(Either::Left)
    } else {
        validator_ids
            .into_iter()
            .filter_map(|validator_id| {
                let validator_index = validator_id.validator_index(&state)?;
                let delta = *sync_committee_deltas.get(&validator_index)?;
                Some((validator_index, delta))
            })
            .pipe(Either::Right)
    }
    .map(|(validator_index, delta)| {
        Ok(SyncCommitteeRewardsResponse {
            validator_index,
            reward: delta.try_into()?,
        })
    })
    .collect::<Result<_>>()?;

    Ok(EthResponse::json(response)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

/// `GET /eth/v1/beacon/pool/attestations`
pub async fn pool_attestations<P: Preset, W: Wait>(
    State(attestation_agg_pool): State<Arc<AttestationAggPool<P, W>>>,
    EthQuery(query): EthQuery<PoolAttestationQuery>,
) -> Result<EthResponse<Vec<Attestation<P>>>, Error> {
    let PoolAttestationQuery {
        slot,
        committee_index,
    } = query;

    let epoch = misc::compute_epoch_at_slot::<P>(slot);

    let aggregates = attestation_agg_pool
        .aggregate_attestations_by_epoch(epoch)
        .await;

    let singular_attestations = attestation_agg_pool
        .singular_attestations_by_epoch(epoch)
        .await;

    let attestations = aggregates
        .iter()
        .chain(singular_attestations.iter().map(Arc::as_ref))
        .filter(|attestation| attestation.data.index == committee_index)
        .filter(|attestation| attestation.data.slot == slot)
        .cloned()
        .collect();

    Ok(EthResponse::json(attestations))
}

/// `POST /eth/v1/beacon/pool/proposer_slashings`
pub async fn submit_pool_proposer_slashing<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(proposer_slashing): EthJson<Box<ProposerSlashing>>,
) -> Result<(), Error> {
    let outcome = block_producer
        .handle_external_proposer_slashing(*proposer_slashing)
        .await?;

    if outcome.is_publishable() {
        ApiToP2p::PublishProposerSlashing(proposer_slashing).send(&api_to_p2p_tx);
    }

    if let PoolAdditionOutcome::Reject(_, error) = outcome {
        return Err(Error::InvalidProposerSlashing(error));
    }

    Ok(())
}

/// `GET /eth/v1/beacon/pool/proposer_slashings`
pub async fn pool_proposer_slashings<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
) -> Result<EthResponse<Vec<ProposerSlashing>>, Error> {
    let data = block_producer.get_proposer_slashings().await;

    Ok(EthResponse::json(data))
}

/// `POST /eth/v1/beacon/pool/voluntary_exits`
pub async fn submit_pool_voluntary_exit<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(signed_voluntary_exit): EthJson<Box<SignedVoluntaryExit>>,
) -> Result<(), Error> {
    let outcome = block_producer
        .handle_external_voluntary_exit(*signed_voluntary_exit)
        .await?;

    if outcome.is_publishable() {
        ApiToP2p::PublishVoluntaryExit(signed_voluntary_exit).send(&api_to_p2p_tx);
    }

    if let PoolAdditionOutcome::Reject(_, error) = outcome {
        return Err(Error::InvalidSignedVoluntaryExit(error));
    }

    Ok(())
}

/// `GET /eth/v1/beacon/pool/voluntary_exits`
pub async fn pool_voluntary_exits<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
) -> Result<EthResponse<Vec<SignedVoluntaryExit>>, Error> {
    let data = block_producer.get_voluntary_exits().await;

    Ok(EthResponse::json(data))
}

/// `POST /eth/v1/beacon/pool/attester_slashings`
pub async fn submit_pool_attester_slashing<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(attester_slashing): EthJson<Box<AttesterSlashing<P>>>,
) -> Result<(), Error> {
    let outcome = block_producer
        .handle_external_attester_slashing(*attester_slashing.clone())
        .await?;

    if outcome.is_publishable() {
        ApiToP2p::PublishAttesterSlashing(attester_slashing).send(&api_to_p2p_tx);
    }

    if let PoolAdditionOutcome::Reject(_, error) = outcome {
        return Err(Error::InvalidAttesterSlashing(error));
    }

    Ok(())
}

/// `GET /eth/v1/beacon/pool/attester_slashings`
pub async fn pool_attester_slashings<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
) -> Result<EthResponse<Vec<AttesterSlashing<P>>>, Error> {
    let data = block_producer.get_attester_slashings().await;

    Ok(EthResponse::json(data))
}

/// `POST /eth/v1/beacon/pool/attestations`
pub async fn submit_pool_attestations<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(attestations): EthJson<Vec<Arc<Attestation<P>>>>,
) -> Result<(), Error> {
    let grouped_by_target = attestations
        .into_iter()
        .enumerate()
        .chunk_by(|(_, attestation)| attestation.data.target);

    let (targets, target_attestations): (Vec<_>, Vec<_>) = grouped_by_target
        .into_iter()
        .map(|(target, attestations)| (target, attestations.collect_vec()))
        .unzip();

    let (successes, failures): (Vec<_>, Vec<_>) = targets
        .into_iter()
        .map(|target| {
            if controller.head_block_root().value == target.root {
                let state = controller.preprocessed_state_at_current_slot()?;

                if accessors::get_current_epoch(&state) == target.epoch {
                    return Ok(state);
                }
            }

            controller
                .checkpoint_state(target)?
                .ok_or(Error::TargetStateNotFound)
        })
        .zip(target_attestations)
        .flat_map(|(target_state_result, attestations)| {
            let target_state = target_state_result
                .map_err(|error| {
                    warn!("attestations submitted to beacon node were rejected: {error}");
                    error
                })
                .ok();

            let controller = controller.clone_arc();

            attestations.into_iter().map(move |(index, attestation)| {
                submit_attestation_to_pool(
                    controller.clone_arc(),
                    index,
                    attestation,
                    target_state.clone(),
                )
            })
        })
        .collect::<FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .partition_result();

    // Send messages after validating all attestations to make their order deterministic.
    // Doing it above wouldn't work because `FuturesOrdered` polls futures concurrently.
    //
    // Send messages before reporting failures to be consistent with `submit_pool_sync_committees`.
    // By this point votes from accepted attestations have already been included in fork choice.
    for (attestation, subnet_id, validation_outcome) in successes {
        if validation_outcome == ValidationOutcome::Accept {
            ApiToP2p::PublishSingularAttestation(attestation, subnet_id).send(&api_to_p2p_tx);
        }
    }

    if !failures.is_empty() {
        return Err(Error::InvalidAttestations(failures));
    }

    Ok(())
}

/// `POST /eth/v1/beacon/pool/sync_committees`
pub async fn submit_pool_sync_committees<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(sync_committee_agg_pool): State<Arc<SyncCommitteeAggPool<P, W>>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(json_vec): EthJson<Vec<Value>>,
) -> Result<(), Error> {
    let state = controller.preprocessed_state_at_current_slot()?;

    let Some(state) = state.post_altair() else {
        return Ok(());
    };

    let (messages_with_subnets, failures): (Vec<_>, Vec<_>) = json_vec
        .into_iter()
        .enumerate()
        .map(|(index, json)| {
            let run = || {
                let message = serde_json::from_value::<SyncCommitteeMessage>(json)?;
                let validator_index = message.validator_index;
                let subnets = misc::compute_subnets_for_sync_committee(state, validator_index)?;
                Ok((index, message, subnets))
            };

            run().map_err(|error| IndexedError { index, error })
        })
        .partition_result();

    if !failures.is_empty() {
        return Err(Error::InvalidSyncCommitteeMessages(failures));
    }

    let messages = messages_with_subnets
        .into_iter()
        .flat_map(|(index, message, subnets)| {
            core::iter::zip(subnets, 0..)
                .filter(|(in_subnet, _)| *in_subnet)
                .map(move |(_, subnet_id)| (index, message, subnet_id))
        });

    let mut failures = vec![];

    for (index, message, subnet_id) in messages {
        match sync_committee_agg_pool
            .handle_external_message(message, subnet_id, Origin::Api)
            .await
        {
            Ok(ValidationOutcome::Accept) => {
                ApiToP2p::PublishSyncCommitteeMessage(Box::new((subnet_id, message)))
                    .send(&api_to_p2p_tx);
            }
            Ok(ValidationOutcome::Ignore(_)) => {}
            Err(error) => {
                debug!(
                    "external sync committee message rejected \
                     (error: {error}, message: {message:?}, subnet_id: {subnet_id})",
                );
                failures.push(IndexedError { index, error });
            }
        }
    }

    if !failures.is_empty() {
        return Err(Error::InvalidSyncCommitteeMessages(failures));
    }

    Ok(())
}

/// `GET /eth/v1/beacon/pool/bls_to_execution_changes`
pub async fn pool_bls_to_execution_changes(
    State(bls_to_execution_change_pool): State<Arc<BlsToExecutionChangePool>>,
) -> Result<EthResponse<Vec<SignedBlsToExecutionChange>>, Error> {
    let data = bls_to_execution_change_pool
        .signed_bls_to_execution_changes()
        .await?;

    Ok(EthResponse::json(data))
}

/// `POST /eth/v1/beacon/pool/bls_to_execution_change`
pub async fn submit_pool_bls_to_execution_change(
    State(bls_to_execution_change_pool): State<Arc<BlsToExecutionChangePool>>,
    EthJson(json_vec): EthJson<Vec<Value>>,
) -> Result<(), Error> {
    let (signed_bls_to_execution_changes, failures): (Vec<_>, Vec<_>) = json_vec
        .into_iter()
        .enumerate()
        .map(|(index, json)| {
            serde_json::from_value(json)
                .map(|address_change| (index, address_change))
                .map_err(AnyhowError::new)
                .map_err(|error| IndexedError { index, error })
        })
        .partition_result();

    if !failures.is_empty() {
        return Err(Error::InvalidSignedBlsToExecutionChanges(failures));
    }

    let mut failures = vec![];

    for (index, signed_bls_to_execution_change) in signed_bls_to_execution_changes {
        let outcome = bls_to_execution_change_pool
            .handle_external_signed_bls_to_execution_change(
                signed_bls_to_execution_change,
                Origin::Api,
            )
            .await?;

        if let PoolAdditionOutcome::Reject(_, error) = outcome {
            failures.push(IndexedError { index, error });
        }
    }

    if !failures.is_empty() {
        return Err(Error::InvalidSignedBlsToExecutionChanges(failures));
    }

    Ok(())
}

/// `GET /eth/v1/config/fork_schedule`
pub async fn fork_schedule<P: Preset>(
    State(chain_config): State<Arc<ChainConfig>>,
) -> EthResponse<Vec<Fork>> {
    Phase::first()
        .into_iter()
        .chain(enum_iterator::all())
        .filter(|phase| chain_config.is_phase_enabled::<P>(*phase))
        .tuple_windows()
        .map(|(previous_phase, current_phase)| Fork {
            previous_version: chain_config.version(previous_phase),
            current_version: chain_config.version(current_phase),
            epoch: chain_config.fork_epoch(current_phase),
        })
        .collect_vec()
        .pipe(EthResponse::json)
}

/// `GET /eth/v1/config/spec`
pub async fn config_spec<P: Preset>(
    State(chain_config): State<Arc<ChainConfig>>,
) -> EthResponse<FullConfig> {
    EthResponse::json(FullConfig::new::<P>(chain_config))
}

/// `GET /eth/v1/config/deposit_contract`
pub async fn deposit_contract(
    State(chain_config): State<Arc<ChainConfig>>,
) -> EthResponse<DepositContractResponse> {
    EthResponse::json(DepositContractResponse {
        address: chain_config.deposit_contract_address,
        chain_id: chain_config.deposit_chain_id,
    })
}

/// `GET /eth/v1/debug/fork_choice`
pub async fn debug_fork_choice<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
) -> Json<ForkChoiceContext> {
    // The use of `Json` instead of `EthResponse` is intentional.
    // This endpoint is supposed to return a bare object.
    Json(controller.fork_choice_context())
}

/// `GET /eth/v2/debug/beacon/states/{state_id}`
pub async fn beacon_state<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(state_id): EthPath<StateId>,
    headers: HeaderMap,
) -> Result<EthResponse<Arc<BeaconState<P>>, (), JsonOrSsz>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, &controller, &anchor_checkpoint_provider)?;

    let version = state.phase();

    Ok(EthResponse::json_or_ssz(state, &headers)?
        .execution_optimistic(optimistic)
        .finalized(finalized)
        .version(version))
}

/// `GET /eth/v2/debug/beacon/heads`
pub async fn beacon_heads<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
) -> EthResponse<Vec<ForkTip>> {
    EthResponse::json(controller.fork_tips())
}

/// `GET /eth/v1/events`
pub async fn beacon_events(
    State(event_channels): State<Arc<EventChannels>>,
    EthQuery(events): EthQuery<EventsQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, BroadcastStreamRecvError>>>, Error> {
    let EventsQuery { topics } = events;

    if topics.is_empty() {
        return Err(Error::EventTopicsEmpty);
    }

    topics
        .into_iter()
        .map(|topic| event_channels.receiver_for(topic))
        .map(BroadcastStream::new)
        .pipe(futures::stream::select_all)
        .pipe(Sse::new)
        .keep_alive(KeepAlive::default())
        .pipe(Ok)
}

/// `GET /eth/v1/node/identity`
pub async fn node_identity<P: Preset>(
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
) -> Result<EthResponse<NodeIdentity>, Error> {
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToP2p::RequestIdentity(sender).send(&api_to_p2p_tx);

    let identity = receiver.await?;

    Ok(EthResponse::json(identity))
}

/// `GET /eth/v1/node/peers`
pub async fn node_peers<P: Preset>(
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthQuery(query): EthQuery<NodePeersQuery>,
) -> Result<EthResponse<Vec<NodePeer>, MetaPeersResponse>, Error> {
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToP2p::RequestPeers(query, sender).send(&api_to_p2p_tx);

    let peers = receiver.await?;
    let meta = MetaPeersResponse { count: peers.len() };

    Ok(EthResponse::json(peers).meta(meta))
}

/// `GET /eth/v1/node/peers/{peer_id}`
pub async fn node_peer<P: Preset>(
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthPath(peer_id): EthPath<PeerId>,
) -> Result<EthResponse<NodePeer>, Error> {
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToP2p::RequestPeer(peer_id, sender).send(&api_to_p2p_tx);

    let data = receiver.await?.ok_or(Error::PeerNotFound)?;

    Ok(EthResponse::json(data))
}

/// `GET /eth/v1/node/peer_count`
pub async fn node_peer_count<P: Preset>(
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
) -> Result<EthResponse<NodePeerCountResponse>, Error> {
    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToP2p::RequestPeerCount(sender).send(&api_to_p2p_tx);

    let data = receiver.await?;

    Ok(EthResponse::json(data.into()))
}

/// `GET /eth/v1/node/version`
pub async fn node_version(State(network_config): State<Arc<NetworkConfig>>) -> Response {
    let data = NodeVersionResponse {
        version: network_config.identify_agent_version.as_deref(),
    };

    EthResponse::json(data).into_response()
}

/// `GET /eth/v1/node/syncing`
pub async fn node_syncing_status<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(is_synced): State<Arc<SyncedStatus>>,
    State(is_back_synced): State<Arc<BackSyncedStatus>>,
) -> EthResponse<NodeSyncingResponse> {
    let snapshot = controller.snapshot();
    let head_slot = snapshot.head_slot();
    let is_synced = is_synced.get();
    let is_back_synced = is_back_synced.get();

    EthResponse::json(NodeSyncingResponse {
        head_slot,
        sync_distance: is_synced
            .then_some(0)
            .unwrap_or_else(|| controller.slot() - head_slot),
        is_syncing: !(is_synced && is_back_synced),
        is_optimistic: snapshot.is_optimistic(),
    })
}

/// `GET /eth/v1/node/health`
pub async fn node_health(
    State(is_synced): State<Arc<SyncedStatus>>,
    State(is_back_synced): State<Arc<BackSyncedStatus>>,
) -> StatusCode {
    if is_synced.get() && is_back_synced.get() {
        StatusCode::OK
    } else {
        StatusCode::PARTIAL_CONTENT
    }
}

/// `POST /eth/v1/validator/duties/attester/{epoch}`
pub async fn validator_attester_duties<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    EthPath(epoch): EthPath<Epoch>,
    EthJson(validator_indices): EthJson<Vec<ValidatorIndex>>,
) -> Result<EthResponse<Vec<ValidatorAttesterDutyResponse>>, Error> {
    let head_state = controller.head_state();

    let (state, relative_epoch) = match accessors::relative_epoch(&head_state.value, epoch) {
        Ok(relative_epoch) => (head_state, relative_epoch),
        Err(_) => (
            controller.preprocessed_state_at_epoch(epoch)?,
            RelativeEpoch::Current,
        ),
    };

    let WithStatus {
        value: state,
        optimistic,
        // `duties` responses are not supposed to contain a `finalized` field.
        finalized: _,
    } = state;

    // Unlike `GET /eth/v1/validator/duties/proposer/{epoch}`,
    // this endpoint is supposed to return the dependent root for the previous epoch.
    let previous_epoch = epoch.saturating_sub(1).max(GENESIS_EPOCH);
    let dependent_root = controller.dependent_root(&state, previous_epoch)?;

    let indices = validator_indices
        .into_iter()
        .collect::<HashSet<ValidatorIndex>>();

    let committees_at_slot = accessors::get_committee_count_per_slot(&state, relative_epoch);

    let response = misc::slots_in_epoch::<P>(epoch)
        .map(|slot| {
            accessors::beacon_committees(&state, slot)?
                .zip(0..)
                .flat_map(|(committee, committee_index)| {
                    let state = &state;

                    committee
                        .into_iter()
                        .enumerate()
                        .filter(|(_, validator_index)| indices.contains(validator_index))
                        .map(move |(validator_committee_index, validator_index)| {
                            let pubkey = accessors::public_key(state, validator_index)?.to_bytes();

                            Ok(ValidatorAttesterDutyResponse {
                                committee_index,
                                committee_length: committee.len(),
                                committees_at_slot,
                                pubkey,
                                slot,
                                validator_committee_index,
                                validator_index,
                            })
                        })
                })
                .collect::<Result<Vec<_>>>()
        })
        .flatten_ok()
        .try_collect()
        .map_err(Error::Internal)?;

    Ok(EthResponse::json(response)
        .dependent_root(dependent_root)
        .execution_optimistic(optimistic))
}

/// `GET /eth/v1/validator/duties/proposer/{epoch}`
pub async fn validator_proposer_duties<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    EthPath(epoch): EthPath<Epoch>,
) -> Result<EthResponse<Vec<ValidatorProposerDutyResponse>>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        // `duties` responses are not supposed to contain a `finalized` field.
        finalized: _,
    } = controller.preprocessed_state_at_epoch(epoch)?;

    let dependent_root = controller.dependent_root(&state, epoch)?;

    let response = misc::slots_in_epoch::<P>(epoch)
        .map(|slot| {
            let validator_index = accessors::get_beacon_proposer_index_at_slot(&state, slot)?;
            let pubkey = accessors::public_key(&state, validator_index)?.to_bytes();

            Ok(ValidatorProposerDutyResponse {
                pubkey,
                validator_index,
                slot,
            })
        })
        .try_collect()
        .map_err(Error::Internal)?;

    Ok(EthResponse::json(response)
        .dependent_root(dependent_root)
        .execution_optimistic(optimistic))
}

// TODO(Grandine Team): This returns incorrect duties if called before Altair.
//                      From the [Altair Honest Validator specification]:
//                      > *Note*: The first sync committee from phase 0 to the Altair fork
//                      > will not be known until the fork happens
//
//                      [Altair Honest Validator specification]: https://github.com/ethereum/consensus-specs/blob/0b76c8367ed19014d104e3fbd4718e73f459a748/specs/altair/validator.md#sync-committee-subnet-stability
/// `POST /eth/v1/validator/duties/sync/{epoch}`
pub async fn validator_sync_committee_duties<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(anchor_checkpoint_provider): State<AnchorCheckpointProvider<P>>,
    EthPath(epoch): EthPath<Epoch>,
    EthJson(validator_indices): EthJson<Vec<ValidatorIndex>>,
) -> Result<EthResponse<Vec<ValidatorSyncDutyResponse>>, Error> {
    let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);

    let WithStatus {
        value: state,
        optimistic,
        // `duties` responses are not supposed to contain a `finalized` field.
        finalized: _,
    } = state_id::state(
        &StateId::Slot(start_slot),
        &controller,
        &anchor_checkpoint_provider,
    )?;

    let Some(state) = state.post_altair() else {
        return Ok(EthResponse::json(vec![]).execution_optimistic(optimistic));
    };

    let requested_period = misc::sync_committee_period::<P>(epoch);
    let state_epoch = misc::compute_epoch_at_slot::<P>(state.slot());
    let state_period = misc::sync_committee_period::<P>(state_epoch);

    let committee = if requested_period == state_period {
        state.current_sync_committee()
    } else if requested_period == state_period + 1 {
        state.next_sync_committee()
    } else {
        return Err(Error::EpochNotInSyncCommitteePeriod);
    };

    let duties = validator_indices
        .into_iter()
        .map(|validator_index| {
            let validator_pubkey = accessors::public_key(state, validator_index)?;

            let validator_sync_committee_indices = committee
                .pubkeys
                .iter()
                .enumerate()
                .filter_map(|(index, pubkey)| (pubkey == validator_pubkey).then_some(index))
                .collect_vec();

            if validator_sync_committee_indices.is_empty() {
                return Ok(None);
            }

            Ok(Some(ValidatorSyncDutyResponse {
                pubkey: validator_pubkey.to_bytes(),
                validator_index,
                validator_sync_committee_indices,
            }))
        })
        .filter_map(Result::transpose)
        .collect::<Result<_>>()?;

    Ok(EthResponse::json(duties).execution_optimistic(optimistic))
}

/// `GET /eth/v1/validator/aggregate_attestation`
pub async fn validator_aggregate_attestation<P: Preset, W: Wait>(
    State(attestation_agg_pool): State<Arc<AttestationAggPool<P, W>>>,
    EthQuery(query): EthQuery<AggregateAttestationQuery>,
) -> Result<EthResponse<Attestation<P>>, Error> {
    let AggregateAttestationQuery {
        attestation_data_root,
        slot,
    } = query;

    let epoch = misc::compute_epoch_at_slot::<P>(slot);

    let attestation = attestation_agg_pool
        .best_aggregate_attestation_by_data_root(attestation_data_root, epoch)
        .await
        .ok_or(Error::AttestationNotFound)?;

    Ok(EthResponse::json(attestation))
}

/// `GET /eth/v1/validator/blinded_blocks/{slot}`
pub async fn validator_blinded_block<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(controller): State<ApiController<P, W>>,
    EthPath(slot): EthPath<Slot>,
    EthQuery(query): EthQuery<ValidatorBlockQuery>,
) -> Result<EthResponse<ValidatorBlindedBlock<P>>, Error> {
    let ValidatorBlockQuery {
        randao_reveal,
        graffiti,
        skip_randao_verification,
    } = query;

    if skip_randao_verification && !randao_reveal.is_empty() {
        return Err(Error::InvalidRandaoReveal);
    }

    let block_root = controller.head().value.block_root;
    let beacon_state = controller.preprocessed_state_post_block(block_root, slot)?;

    let Ok(proposer_index) = accessors::get_beacon_proposer_index(&beacon_state) else {
        // accessors::get_beacon_proposer_index can only fail if head state has no active validators.
        warn!("failed to produce blinded beacon block: head state has no active validators");
        return Err(Error::UnableToProduceBlindedBlock);
    };

    let graffiti = graffiti.unwrap_or_default();
    let public_key = accessors::public_key(&beacon_state, proposer_index)?;

    let block_build_context = block_producer.new_build_context(
        beacon_state.clone_arc(),
        block_root,
        proposer_index,
        BlockBuildOptions {
            graffiti,
            skip_randao_verification,
            ..BlockBuildOptions::default()
        },
    );

    let execution_payload_header_handle =
        block_build_context.get_execution_payload_header(public_key.to_bytes());

    let local_execution_payload_handle = block_build_context.get_local_execution_payload();

    let blinded_block = block_build_context
        .build_blinded_beacon_block(
            randao_reveal,
            execution_payload_header_handle,
            local_execution_payload_handle,
        )
        .await?
        .ok_or(Error::UnableToProduceBlindedBlock)?
        .0
        .value
        .into_blinded();

    let version = blinded_block.phase();

    Ok(EthResponse::json(blinded_block).version(version))
}

/// `GET /eth/v2/validator/blocks/{slot}`
pub async fn validator_block<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(controller): State<ApiController<P, W>>,
    EthPath(slot): EthPath<Slot>,
    EthQuery(query): EthQuery<ValidatorBlockQuery>,
    headers: HeaderMap,
) -> Result<EthResponse<APIBlock<BeaconBlock<P>, P>, (), JsonOrSsz>, Error> {
    let ValidatorBlockQuery {
        randao_reveal,
        graffiti,
        skip_randao_verification,
    } = query;

    if skip_randao_verification && !randao_reveal.is_empty() {
        return Err(Error::InvalidRandaoReveal);
    }

    let block_root = controller.head().value.block_root;
    let beacon_state = controller.preprocessed_state_post_block(block_root, slot)?;
    let proposer_index = accessors::get_beacon_proposer_index(&beacon_state)?;
    let graffiti = graffiti.unwrap_or_default();

    let block_build_context = block_producer.new_build_context(
        beacon_state.clone_arc(),
        block_root,
        proposer_index,
        BlockBuildOptions {
            graffiti,
            skip_randao_verification,
            ..BlockBuildOptions::default()
        },
    );

    let local_execution_payload_handle = block_build_context.get_local_execution_payload();

    let (beacon_block, _) = block_build_context
        .build_beacon_block(randao_reveal, local_execution_payload_handle)
        .await?
        .ok_or(Error::UnableToProduceBeaconBlock)?;

    let version = beacon_block.value.phase();

    Ok(EthResponse::json_or_ssz(beacon_block.into(), &headers)?.version(version))
}

/// `GET /eth/v3/validator/blocks/{slot}`
pub async fn validator_block_v3<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    State(controller): State<ApiController<P, W>>,
    EthPath(slot): EthPath<Slot>,
    EthQuery(query): EthQuery<ValidatorBlockQueryV3>,
    headers: HeaderMap,
) -> Result<EthResponse<APIBlock<ValidatorBlindedBlock<P>, P>, (), JsonOrSsz>, Error> {
    let ValidatorBlockQueryV3 {
        randao_reveal,
        graffiti,
        skip_randao_verification,
        builder_boost_factor,
    } = query;

    if skip_randao_verification && !randao_reveal.is_empty() {
        return Err(Error::InvalidRandaoReveal);
    }

    let block_root = controller.head().value.block_root;
    let beacon_state = controller.preprocessed_state_post_block(block_root, slot)?;

    let Ok(proposer_index) = accessors::get_beacon_proposer_index(&beacon_state) else {
        // accessors::get_beacon_proposer_index can only fail if head state has no active validators.
        warn!("failed to produce blinded beacon block: head state has no active validators");
        return Err(Error::UnableToProduceBeaconBlock);
    };

    let graffiti = graffiti.unwrap_or_default();
    let public_key = accessors::public_key(&beacon_state, proposer_index)?;

    let block_build_context = block_producer.new_build_context(
        beacon_state.clone_arc(),
        block_root,
        proposer_index,
        BlockBuildOptions {
            graffiti,
            skip_randao_verification,
            builder_boost_factor,
        },
    );

    let execution_payload_header_handle =
        block_build_context.get_execution_payload_header(public_key.to_bytes());

    let local_execution_payload_handle = block_build_context.get_local_execution_payload();

    let (validator_block, block_rewards) = block_build_context
        .build_blinded_beacon_block(
            randao_reveal,
            execution_payload_header_handle,
            local_execution_payload_handle,
        )
        .await?
        .ok_or(Error::UnableToProduceBeaconBlock)?;

    let mev = validator_block.mev;
    let version = validator_block.value.phase();
    let blinded = validator_block.value.is_blinded();

    // 'Uplift' validator block to signed beacon block for consensus reward calculation
    let signed_beacon_block = match validator_block.value.clone() {
        ValidatorBlindedBlock::BeaconBlock(beacon_block) => beacon_block.with_zero_signature(),
        ValidatorBlindedBlock::BlindedBeaconBlock {
            blinded_block,
            execution_payload,
        } => blinded_block
            .with_execution_payload(*execution_payload)
            .map_err(AnyhowError::new)?
            .with_zero_signature(),
    };

    let consensus_block_value = block_rewards
        .map(|rewards| Uint256::from_u64(rewards.total) * WEI_IN_GWEI)
        .or_else(|| {
            warn!(
                "unable to calculate block rewards for validator block {:?} at slot {slot}",
                signed_beacon_block.message().hash_tree_root(),
            );
            None
        });

    Ok(EthResponse::json_or_ssz(validator_block.into(), &headers)?
        .version(version)
        .consensus_block_value(consensus_block_value)
        .execution_payload_blinded(blinded)
        .execution_payload_value(mev.unwrap_or_default()))
}

/// `GET /eth/v1/validator/attestation_data`
pub async fn validator_attestation_data<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(metrics): State<Option<Arc<Metrics>>>,
    State(validator_config): State<Arc<ValidatorConfig>>,
    EthQuery(query): EthQuery<AttestationDataQuery>,
) -> Result<EthResponse<AttestationData>, Error> {
    let _timer = metrics.map(|metrics| metrics.validator_api_attestation_data_times.start_timer());

    let AttestationDataQuery {
        committee_index,
        slot,
    } = query;

    let WithStatus {
        value: head,
        optimistic,
        ..
    } = controller.head();

    let head_slot = head.slot();
    let max_empty_slots = validator_config.max_empty_slots;

    if head_slot + max_empty_slots < slot {
        return Err(Error::HeadFarBehind {
            head_slot,
            max_empty_slots,
            slot,
        });
    }

    let requested_epoch = misc::compute_epoch_at_slot::<P>(slot);

    let previous_epoch = misc::compute_epoch_at_slot::<P>(head_slot)
        .saturating_sub(1)
        .max(GENESIS_EPOCH);

    // Prevent DoS attacks by limiting how far in the past the attested block can be searched.
    if requested_epoch < previous_epoch {
        return Err(Error::EpochBeforePrevious);
    }

    let block_root;
    let mut state;
    let is_optimistic;

    if slot < head_slot {
        // Search for the latest canonical block before or at slot.
        let block = controller
            .block_by_slot(slot)?
            .ok_or(Error::BlockNotFound)?;

        block_root = block.value.root;
        state = controller
            .state_before_or_at_slot(block_root, slot)
            .ok_or(Error::StateNotFound)?;
        is_optimistic = block.optimistic;
    } else {
        block_root = head.block_root;
        state = controller.state_by_chain_link(&head);
        is_optimistic = optimistic;
    };

    if is_optimistic {
        return Err(Error::HeadIsOptimistic);
    }

    if state.slot() < slot {
        state = tokio::task::spawn_blocking(move || {
            controller.preprocessed_state_post_block(block_root, slot)
        })
        .await?
        .map_err(Error::UnableToProduceAttestation)?;
    };

    let target = Checkpoint {
        epoch: requested_epoch,
        root: accessors::epoch_boundary_block_root(&state, block_root),
    };

    let attestation_data = AttestationData {
        slot,
        index: committee_index,
        beacon_block_root: block_root,
        source: state.current_justified_checkpoint(),
        target,
    };

    Ok(EthResponse::json(attestation_data))
}

/// `POST /eth/v1/validator/beacon_committee_subscriptions`
pub async fn validator_subscribe_to_beacon_committee<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(subnet_service_tx): State<UnboundedSender<ToSubnetService>>,
    EthJson(subscriptions): EthJson<Vec<BeaconCommitteeSubscription>>,
) -> Result<(), Error> {
    let state = controller.preprocessed_state_at_current_slot()?;
    let (sender, receiver) = futures::channel::oneshot::channel();

    subscriptions.iter().try_for_each(|subscription| {
        let BeaconCommitteeSubscription {
            committees_at_slot,
            slot,
            ..
        } = *subscription;

        let epoch = misc::compute_epoch_at_slot::<P>(slot);
        let relative_epoch = accessors::relative_epoch(&state, epoch)?;
        let computed = accessors::get_committee_count_per_slot(&state, relative_epoch);
        let requested = committees_at_slot;

        ensure!(
            requested == computed,
            Error::CommitteesAtSlotMismatch {
                requested,
                computed,
            },
        );

        // TODO(Grandine Team): Some API clients do not set `validator_index`.
        //                      See <https://github.com/attestantio/vouch/issues/75>.
        // let committee = accessors::beacon_committee(&state, slot, committee_index)?;
        // ensure!(
        //     committee.into_iter().contains(&validator_index),
        //     Error::ValidatorNotInCommittee { validator_index },
        // );

        Ok(())
    })?;

    ToSubnetService::UpdateBeaconCommitteeSubscriptions(controller.slot(), subscriptions, sender)
        .send(&subnet_service_tx);

    receiver.await??;

    Ok(())
}

/// `POST /eth/v1/validator/sync_committee_subscriptions`
pub async fn validator_subscribe_to_sync_committees<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(subnet_service_tx): State<UnboundedSender<ToSubnetService>>,
    EthJson(subscriptions): EthJson<Vec<SyncCommitteeSubscription>>,
) -> Result<(), Error> {
    let current_epoch = misc::compute_epoch_at_slot::<P>(controller.slot());

    ToSubnetService::UpdateSyncCommitteeSubscriptions(current_epoch, subscriptions)
        .send(&subnet_service_tx);

    Ok(())
}

/// `GET /eth/v1/validator/sync_committee_contribution`
pub async fn validator_sync_committee_contribution<P: Preset, W: Wait>(
    State(sync_committee_agg_pool): State<Arc<SyncCommitteeAggPool<P, W>>>,
    EthQuery(query): EthQuery<SyncCommitteeContributionQuery>,
) -> Result<EthResponse<SyncCommitteeContribution<P>>, Error> {
    let SyncCommitteeContributionQuery {
        slot,
        beacon_block_root,
        subcommittee_index,
    } = query;

    let data = sync_committee_agg_pool
        .best_subcommittee_contribution(slot, beacon_block_root, subcommittee_index)
        .await;

    Ok(EthResponse::json(data))
}

/// `POST /eth/v1/validator/aggregate_and_proofs`
///
/// This deviates from [the specification] by returning errors as [`IndexedError`].
/// Lighthouse does the same thing.
///
/// [the specification]: https://ethereum.github.io/beacon-APIs/
// We box aggregates to reduce the size of various enums.
// It's probably faster to deserialize them directly into `Vec<Box<_>>`.
#[allow(clippy::vec_box)]
pub async fn validator_publish_aggregate_and_proofs<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_p2p_tx): State<UnboundedSender<ApiToP2p<P>>>,
    EthJson(aggregate_and_proofs): EthJson<Vec<Arc<SignedAggregateAndProof<P>>>>,
) -> Result<(), Error> {
    let (successes, failures): (Vec<_>, Vec<_>) = aggregate_and_proofs
        .into_iter()
        .enumerate()
        .map(|(index, aggregate_and_proof)| {
            let (sender, receiver) = futures::channel::oneshot::channel();

            controller.on_api_aggregate_and_proof(aggregate_and_proof.clone_arc(), sender);

            async move {
                let run = async {
                    let validation_outcome = receiver.await??;
                    Ok((aggregate_and_proof, validation_outcome))
                };

                run.await.map_err(|error| IndexedError { index, error })
            }
        })
        .collect::<FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .partition_result();

    // Send messages after validating all aggregates to make their order deterministic.
    // Doing it above wouldn't work because `FuturesOrdered` polls futures concurrently.
    //
    // Send messages before reporting failures to be consistent with `submit_pool_sync_committees`.
    // By this point votes from accepted aggregates have already been included in fork choice.
    for (aggregate_and_proof, validation_outcome) in successes {
        if validation_outcome == ValidationOutcome::Accept {
            ApiToP2p::PublishAggregateAndProof(aggregate_and_proof).send(&api_to_p2p_tx);
        }
    }

    if !failures.is_empty() {
        return Err(Error::InvalidAggregatesAndProofs(failures));
    }

    Ok(())
}

/// `POST /eth/v1/validator/contribution_and_proofs`
///
/// This deviates from [the specification] by returning errors as [`IndexedError`].
/// Lighthouse does the same thing.
///
/// [the specification]: https://ethereum.github.io/beacon-APIs/
pub async fn validator_publish_contributions_and_proofs<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_validator_tx): State<UnboundedSender<ApiToValidator<P>>>,
    EthJson(contributions_and_proofs): EthJson<Vec<SignedContributionAndProof<P>>>,
) -> Result<(), Error> {
    if controller.phase() < Phase::Altair {
        return Err(Error::CurrentSlotHasNoSyncCommittee);
    }

    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToValidator::SignedContributionsAndProofs(sender, contributions_and_proofs)
        .send(&api_to_validator_tx);

    let failures = receiver.await?.ok_or(Error::SlotHeadNotAvailable)?;

    if !failures.is_empty() {
        return Err(Error::InvalidContributionAndProofs(
            failures
                .into_iter()
                .map(|(index, error)| IndexedError { index, error })
                .collect_vec(),
        ));
    }

    Ok(())
}

/// `POST /eth/v1/validator/prepare_beacon_proposer`
pub async fn validator_prepare_beacon_proposer<P: Preset, W: Wait>(
    State(block_producer): State<Arc<BlockProducer<P, W>>>,
    EthJson(proposers): EthJson<Vec<ProposerData>>,
) -> Result<(), Error> {
    block_producer.add_new_prepared_proposers(proposers).await;

    Ok(())
}

/// `POST /eth/v1/validator/register_validator`
///
/// This deviates from [the specification] by returning errors as [`IndexedError`].
///
/// [the specification]: https://ethereum.github.io/beacon-APIs/
pub async fn validator_register_validator<P: Preset>(
    State(api_to_validator_tx): State<UnboundedSender<ApiToValidator<P>>>,
    EthJson(registrations): EthJson<Vec<SignedValidatorRegistrationV1>>,
) -> Result<(), Error> {
    let (sender, receiver) = futures::channel::oneshot::channel();
    ApiToValidator::SignedValidatorRegistrations(sender, registrations).send(&api_to_validator_tx);

    let failures = receiver.await?;

    if !failures.is_empty() {
        return Err(Error::InvalidValidatorSignatures(
            failures
                .into_iter()
                .map(|(index, error)| IndexedError { index, error })
                .collect_vec(),
        ));
    }

    Ok(())
}

/// `POST /eth/v1/validator/liveness/{epoch}`
pub async fn validator_liveness<P: Preset, W: Wait>(
    State(controller): State<ApiController<P, W>>,
    State(api_to_liveness_tx): State<Option<UnboundedSender<ApiToLiveness>>>,
    EthPath(epoch): EthPath<Epoch>,
    EthJson(validators): EthJson<Vec<ValidatorIndex>>,
) -> Result<EthResponse<Vec<ValidatorLivenessResponse>>, Error> {
    let api_to_liveness_tx = api_to_liveness_tx.ok_or(Error::LivenessTrackingNotEnabled)?;
    let state = controller.preprocessed_state_at_current_slot()?;

    accessors::attestation_epoch(&state, epoch).map_err(Error::InvalidEpoch)?;

    let (sender, receiver) = futures::channel::oneshot::channel();

    ApiToLiveness::CheckLiveness(sender, epoch, validators).send(&api_to_liveness_tx);

    let liveness_data = receiver
        .await??
        .into_iter()
        .map(|(index, is_live)| ValidatorLivenessResponse { index, is_live })
        .collect();

    Ok(EthResponse::json(liveness_data))
}

/// `POST /eth/v1/validator/beacon_committee_selections`
pub async fn validator_beacon_committee_selections() -> Error {
    Error::EndpointNotImplemented
}

/// `POST /eth/v1/validator/sync_committee_selections`
pub async fn validator_sync_committee_selections() -> Error {
    Error::EndpointNotImplemented
}

fn state_validators<P: Preset, W: Wait>(
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
    state_id: StateId,
    ids_and_statuses: &impl ValidatorIdsAndStatuses,
) -> Result<EthResponse<Vec<StateValidatorResponse>>, Error> {
    let WithStatus {
        value: state,
        optimistic,
        finalized,
    } = state_id::state(&state_id, controller, anchor_checkpoint_provider)?;

    let ids = ids_and_statuses
        .ids()
        .iter()
        .copied()
        .collect::<HashSet<_>>();

    let statuses = ids_and_statuses.statuses();

    let validators = izip!(
        0..,
        state.validators(),
        state.balances().into_iter().copied(),
    )
    .filter(|(index, validator, _)| {
        if !ids.is_empty() {
            let validator_index = ValidatorId::ValidatorIndex(*index);
            let validator_pubkey = ValidatorId::PublicKey(*validator.pubkey.as_bytes());

            let allowed_by_id = ids.contains(&validator_index) || ids.contains(&validator_pubkey);

            if !allowed_by_id {
                return false;
            }
        }

        if !statuses.is_empty() {
            let validator_status = ValidatorStatus::new(validator, &state);

            let allowed_by_status = statuses
                .iter()
                .any(|status| status.matches(validator_status));

            if !allowed_by_status {
                return false;
            }
        }

        true
    })
    .map(|(index, validator, balance)| StateValidatorResponse {
        index,
        balance,
        status: ValidatorStatus::new(validator, &state),
        validator: validator.clone(),
    })
    .collect();

    Ok(EthResponse::json(validators)
        .execution_optimistic(optimistic)
        .finalized(finalized))
}

async fn publish_signed_block<P: Preset, W: Wait>(
    block: Arc<SignedBeaconBlock<P>>,
    blob_sidecars: Vec<BlobSidecar<P>>,
    controller: ApiController<P, W>,
    api_to_p2p_tx: UnboundedSender<ApiToP2p<P>>,
) -> Result<StatusCode, Error> {
    let blob_sidecars = blob_sidecars.into_iter().map(Arc::new).collect_vec();

    submit_blob_sidecars(controller.clone_arc(), &blob_sidecars).await?;

    if let Some(status_code) = publish_beacon_block_with_gossip_checks(
        controller.clone_arc(),
        block.clone_arc(),
        &blob_sidecars,
        &api_to_p2p_tx,
    )
    .await?
    {
        return Ok(status_code);
    }

    let (sender, mut receiver) = futures::channel::mpsc::channel(1);

    controller.on_api_block(block.clone_arc(), sender);

    let status_code = match receiver.next().await.transpose() {
        Ok(Some(ValidationOutcome::Accept)) => StatusCode::OK,
        Ok(Some(ValidationOutcome::Ignore(_))) => {
            // We log only the root with `info!` because this is not an exceptional case.
            // Vouch submits blocks it constructs to all beacon nodes it is connected to.
            // The blocks often reach our application through gossip faster than through the API.
            let block_root = block.message().hash_tree_root();
            info!("block received through HTTP API was ignored (block root: {block_root:?})");
            StatusCode::ACCEPTED
        }
        Ok(None) => {
            warn!("received no block validation response for HTTP API (block: {block:?})");
            StatusCode::ACCEPTED
        }
        Err(error) => {
            warn!("received invalid block through HTTP API (block: {block:?}, error: {error})");
            StatusCode::ACCEPTED
        }
    };

    Ok(status_code)
}

async fn publish_beacon_block_with_gossip_checks<P: Preset, W: Wait>(
    controller: ApiController<P, W>,
    block: Arc<SignedBeaconBlock<P>>,
    blob_sidecars: &[Arc<BlobSidecar<P>>],
    api_to_p2p_tx: &UnboundedSender<ApiToP2p<P>>,
) -> Result<Option<StatusCode>, Error> {
    let (sender, mut receiver) = futures::channel::mpsc::channel(1);

    controller.on_api_block_for_gossip(block.clone_arc(), sender);

    match receiver.next().await.transpose() {
        Ok(Some(ValidationOutcome::Accept)) => {
            publish_block_to_network(block, blob_sidecars, api_to_p2p_tx);
        }
        Ok(Some(ValidationOutcome::Ignore(true))) => {
            publish_block_to_network(block, blob_sidecars, api_to_p2p_tx);
            return Ok(Some(StatusCode::ACCEPTED));
        }
        Ok(Some(ValidationOutcome::Ignore(false))) => {
            return Err(Error::UnableToPublishBlock);
        }
        Ok(None) => {
            warn!(
                "received no block validation response for gossip validation via HTTP API \
                (block: {block:?})"
            );

            return Err(Error::UnableToPublishBlock);
        }
        Err(error) => return Err(Error::InvalidBlock(error)),
    }

    Ok(None)
}

fn publish_block_to_network<P: Preset>(
    block: Arc<SignedBeaconBlock<P>>,
    blob_sidecars: &[Arc<BlobSidecar<P>>],
    api_to_p2p_tx: &UnboundedSender<ApiToP2p<P>>,
) {
    for blob_sidecar in blob_sidecars {
        ApiToP2p::PublishBlobSidecar(blob_sidecar.clone_arc()).send(api_to_p2p_tx);
    }

    ApiToP2p::PublishBeaconBlock(block).send(api_to_p2p_tx);
}

#[allow(clippy::too_many_arguments)]
async fn publish_signed_block_v2<P: Preset, W: Wait>(
    block: Arc<SignedBeaconBlock<P>>,
    blob_sidecars: Vec<BlobSidecar<P>>,
    broadcast_validation: BroadcastValidation,
    controller: ApiController<P, W>,
    api_to_p2p_tx: UnboundedSender<ApiToP2p<P>>,
) -> Result<StatusCode, Error> {
    let blob_sidecars = blob_sidecars.into_iter().map(Arc::new).collect_vec();

    submit_blob_sidecars(controller.clone_arc(), &blob_sidecars).await?;

    if broadcast_validation == BroadcastValidation::Gossip {
        if let Some(status_code) = publish_beacon_block_with_gossip_checks(
            controller.clone_arc(),
            block.clone_arc(),
            &blob_sidecars,
            &api_to_p2p_tx,
        )
        .await?
        {
            return Ok(status_code);
        }
    }

    let (sender, mut receiver) = futures::channel::mpsc::channel(1);

    controller.on_api_block(block.clone_arc(), sender);

    let status_code = match receiver.next().await.transpose() {
        Ok(Some(accept_or_ignore_status)) => {
            match accept_or_ignore_status {
                ValidationOutcome::Accept => match broadcast_validation {
                    BroadcastValidation::Gossip => StatusCode::OK,
                    BroadcastValidation::Consensus => {
                        publish_block_to_network(block, &blob_sidecars, &api_to_p2p_tx);
                        StatusCode::OK
                    }
                    BroadcastValidation::ConsensusAndEquivocation => {
                        if controller.exibits_equivocation(&block) {
                            return Err(Error::InvalidBlock(anyhow!("block exibits equivocation")));
                        }

                        publish_block_to_network(block, &blob_sidecars, &api_to_p2p_tx);
                        StatusCode::OK
                    }
                },
                ValidationOutcome::Ignore(publishable) => {
                    // We log only the root with `info!` because this is not an exceptional case.
                    // Vouch submits blocks it constructs to all beacon nodes it is connected to.
                    // The blocks often reach our application through gossip faster than through the API.
                    let block_root = block.message().hash_tree_root();

                    info!(
                        "block received through HTTP API was ignored (block root: {block_root:?})"
                    );

                    if broadcast_validation == BroadcastValidation::Gossip {
                        StatusCode::ACCEPTED
                    } else if publishable {
                        publish_block_to_network(block, &blob_sidecars, &api_to_p2p_tx);
                        StatusCode::ACCEPTED
                    } else {
                        return Err(Error::UnableToPublishBlock);
                    }
                }
            }
        }
        Ok(None) => {
            warn!("received no block validation response for HTTP API (block: {block:?})");

            if broadcast_validation == BroadcastValidation::Gossip {
                StatusCode::ACCEPTED
            } else {
                return Err(Error::UnableToPublishBlock);
            }
        }
        Err(error) => {
            warn!("received invalid block through HTTP API (block: {block:?}, error: {error})");

            if broadcast_validation == BroadcastValidation::Gossip {
                StatusCode::ACCEPTED
            } else {
                return Err(Error::InvalidBlock(error));
            }
        }
    };

    Ok(status_code)
}

async fn submit_attestation_to_pool<P: Preset, W: Wait>(
    controller: ApiController<P, W>,
    index: usize,
    attestation: Arc<Attestation<P>>,
    target_state: Option<Arc<BeaconState<P>>>,
) -> Result<(Arc<Attestation<P>>, SubnetId, ValidationOutcome), IndexedError> {
    let run = async {
        let AttestationData {
            slot,
            index: committee_index,
            beacon_block_root,
            target,
            ..
        } = attestation.data;

        ensure!(
            controller.block_by_root(beacon_block_root)?.is_some(),
            Error::MatchingAttestationHeadBlockNotFound,
        );

        let target_state = target_state.ok_or(Error::TargetStateNotFound)?;

        let relative_epoch = accessors::relative_epoch(&target_state, target.epoch)
            .map_err(|_| Error::TargetStateNotFound)?;

        let committees_per_slot =
            accessors::get_committee_count_per_slot(&target_state, relative_epoch);

        let subnet_id =
            misc::compute_subnet_for_attestation::<P>(committees_per_slot, slot, committee_index)?;

        let (sender, receiver) = futures::channel::oneshot::channel();

        controller.on_api_singular_attestation(attestation.clone_arc(), subnet_id, sender);

        let validation_outcome = receiver.await??;

        Ok((attestation, subnet_id, validation_outcome))
    };

    run.await.map_err(|error| IndexedError { index, error })
}

async fn submit_blob_sidecar<P: Preset, W: Wait>(
    controller: ApiController<P, W>,
    blob_sidecar: Arc<BlobSidecar<P>>,
) -> Result<ValidationOutcome> {
    let (sender, receiver) = futures::channel::oneshot::channel();

    controller.on_api_blob_sidecar(blob_sidecar.clone_arc(), Some(sender));

    receiver.await?
}

async fn submit_blob_sidecars<P: Preset, W: Wait>(
    controller: ApiController<P, W>,
    blob_sidecars: &[Arc<BlobSidecar<P>>],
) -> Result<(), Error> {
    let blob_sidecar_results: Result<Vec<_>> = blob_sidecars
        .iter()
        .map(|blob_sidecar| submit_blob_sidecar(controller.clone_arc(), blob_sidecar.clone_arc()))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect();

    match blob_sidecar_results {
        Ok(results) => {
            if results
                .iter()
                .any(|outcome| *outcome == ValidationOutcome::Ignore(false))
            {
                return Err(Error::UnableToPublishBlock);
            }
        }
        Err(error) => return Err(Error::InvalidBlock(error)),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::fmt::Display;

    use axum::{
        extract::Query,
        http::{header::CONTENT_TYPE, Request},
        Json, RequestExt as _, RequestPartsExt as _,
    };
    use hex_literal::hex;
    use mime::APPLICATION_JSON;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use ssz::BitList;
    use types::preset::Mainnet;

    use super::*;

    #[tokio::test]
    async fn test_deserialize_for_attestation() -> Result<()> {
        let attestations = [Attestation {
            aggregation_bits: BitList::full(true),
            ..Attestation::default()
        }];

        assert_eq!(
            extract_body::<Vec<Attestation<Mainnet>>>(&attestations).await?,
            attestations,
        );

        let mut attestations = serde_json::to_value(attestations)?;
        attestations[0]["aggregation_bits"] = json!("0x0000000000000000000000040000000008");

        // Note that the number of set aggregation bits is 1, not 2.
        // The bit in the last byte marks the end of the list.
        // Without it there would be no way to determine the length of the `BitList` in bits.
        // See the section about serializing bit lists in the SSZ specification:
        // <https://github.com/ethereum/consensus-specs/blob/d8e74090cf33864f1956a1ee12ba5a94d21a6ac4/ssz/simple-serialize.md#bitlistn>
        // The same applies to JSON and YAML, though for a slightly different reason.
        assert_eq!(
            extract_body::<Vec<Attestation<Mainnet>>>(&attestations).await?[0]
                .aggregation_bits
                .count_ones(),
            1,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_deserialize_for_state_validators_query() -> Result<()> {
        let pubkey1 = PublicKeyBytes(hex!("a6d2572f1f4b50f644cd2629e608edc049145df1e646dfb5f9c18b903efe4b5e78bb9c88ce53ff23819ce83a94735a7e"));
        let pubkey2 = PublicKeyBytes(hex!("a6d2572f1f4b50f644cd2629e608edc049145df1e646dfb5f9c18b903efe4b5e78bb9c88ce53ff23819ce83a94735a7a"));

        let index1 = 123;
        let index2 = 456;

        let status1 = ValidatorStatus::PendingInitialized;
        let status2 = ValidatorStatus::ActiveOngoing;

        assert_eq!(
            extract_query::<ValidatorIdsAndStatusesQuery>("").await?,
            ValidatorIdsAndStatusesQuery {
                id: vec![],
                status: vec![],
            },
        );

        assert_eq!(
            extract_query::<ValidatorIdsAndStatusesQuery>(format!("id={pubkey1:?},{pubkey2:?}"))
                .await?,
            ValidatorIdsAndStatusesQuery {
                id: vec![
                    ValidatorId::PublicKey(pubkey1),
                    ValidatorId::PublicKey(pubkey2),
                ],
                status: vec![],
            },
        );

        assert_eq!(
            extract_query::<ValidatorIdsAndStatusesQuery>(format!(
                "id={pubkey1:?},{pubkey2:?},{index1},{index2}&status={status1},{status2}",
            ))
            .await?,
            ValidatorIdsAndStatusesQuery {
                id: vec![
                    ValidatorId::PublicKey(pubkey1),
                    ValidatorId::PublicKey(pubkey2),
                    ValidatorId::ValidatorIndex(index1),
                    ValidatorId::ValidatorIndex(index2),
                ],
                status: vec![
                    ValidatorStatus::PendingInitialized,
                    ValidatorStatus::ActiveOngoing,
                ],
            }
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_deserialize_for_sync_committee_subscription() -> Result<()> {
        let subscriptions = [SyncCommitteeSubscription {
            validator_index: 1,
            sync_committee_indices: vec![2, 3, 4],
            until_epoch: 5,
        }];

        assert_eq!(
            extract_body::<Vec<SyncCommitteeSubscription>>(&subscriptions).await?,
            subscriptions,
        );

        let mut invalid_subscriptions = serde_json::to_value(subscriptions)?;
        invalid_subscriptions[0]["sync_committee_indices"] = json!([2, 3, 4]);

        extract_body::<Vec<SyncCommitteeSubscription>>(invalid_subscriptions)
            .await
            .expect_err("body should be invalid because sync_committee_indices are not strings");

        Ok(())
    }

    async fn extract_query<T: DeserializeOwned + 'static>(query: impl Display + Send) -> Result<T> {
        let (mut parts, ()) = Request::get(format!("/?{query}")).body(())?.into_parts();

        parts
            .extract()
            .await
            .map(|Query(query)| query)
            .map_err(Into::into)
    }

    async fn extract_body<T: DeserializeOwned + 'static>(body: impl Serialize + Send) -> Result<T> {
        let json = serde_json::to_string(&body)?;

        Request::get("/")
            .header(CONTENT_TYPE, APPLICATION_JSON.as_ref())
            .body(json.into())?
            .extract()
            .await
            .map(|Json(body)| body)
            .map_err(Into::into)
    }
}
