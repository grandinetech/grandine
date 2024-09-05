use core::{fmt::Display, future::Future, num::NonZeroU64, ops::Div as _};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Context as _, Error as AnyhowError, Result};
use bls::{AggregateSignature, PublicKeyBytes, SignatureBytes};
use builder_api::{combined::SignedBuilderBid, BuilderApi};
use cached::{Cached as _, SizedCache};
use dedicated_executor::{DedicatedExecutor, Job};
use eth1::Eth1Chain;
use eth1_api::{ApiController, Eth1ExecutionEngine};
use execution_engine::{
    ExecutionEngine as _, PayloadAttributesV1, PayloadAttributesV2, PayloadAttributesV3, PayloadId,
};
use features::Feature;
use fork_choice_control::Wait;
use futures::{
    lock::Mutex,
    stream::{FuturesOrdered, StreamExt as _},
};
use helper_functions::{accessors, misc, predicates};
use itertools::{Either, Itertools as _};
use keymanager::ProposerConfigs;
use log::{error, info, warn};
use nonzero_ext::nonzero;
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, PoolAdditionOutcome, PoolRejectionReason,
    SyncCommitteeAggPool,
};
use prometheus_metrics::Metrics;
use ssz::{BitVector, ContiguousList, SszHash};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tokio::task::JoinHandle;
use transition_functions::{capella, unphased};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::{
        consts::SyncCommitteeSubnetCount,
        containers::{
            BeaconBlock as AltairBeaconBlock, BeaconBlockBody as AltairBeaconBlockBody,
            SyncAggregate,
        },
    },
    bellatrix::containers::{
        BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
        ExecutionPayload as BellatrixExecutionPayload,
    },
    capella::containers::{
        BeaconBlock as CapellaBeaconBlock, BeaconBlockBody as CapellaBeaconBlockBody,
        ExecutionPayload as CapellaExecutionPayload, SignedBlsToExecutionChange,
    },
    combined::{
        BeaconBlock, BeaconState, BlindedBeaconBlock, ExecutionPayload, ExecutionPayloadHeader,
        SignedBlindedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::{
        containers::{
            BeaconBlock as DenebBeaconBlock, BeaconBlockBody as DenebBeaconBlockBody,
            ExecutionPayload as DenebExecutionPayload,
        },
        primitives::KzgCommitment,
    },
    nonstandard::{BlockRewards, Phase, WithBlobsAndMev},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_SLOT},
        containers::{
            Attestation, AttesterSlashing, BeaconBlock as Phase0BeaconBlock,
            BeaconBlockBody as Phase0BeaconBlockBody, Deposit, Eth1Data, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{
            DepositIndex, Epoch, ExecutionAddress, ExecutionBlockHash, Slot, Uint256,
            ValidatorIndex, H256,
        },
    },
    preset::{Preset, SyncSubcommitteeSize},
    traits::{BeaconState as _, PostBellatrixBeaconState},
};

use crate::{
    eth1_storage::Eth1Storage as _,
    misc::{PayloadIdEntry, ProposerData, ValidatorBlindedBlock},
};

const DEFAULT_BUILDER_BOOST_FACTOR: NonZeroU64 = nonzero!(100_u64);
const PAYLOAD_CACHE_SIZE: usize = 20;
const PAYLOAD_ID_CACHE_SIZE: usize = 10;

pub type ExecutionPayloadHeaderJoinHandle<P> = JoinHandle<Result<Option<SignedBuilderBid<P>>>>;
pub type LocalExecutionPayloadJoinHandle<P> =
    JoinHandle<Option<WithBlobsAndMev<ExecutionPayload<P>, P>>>;

pub struct BlockProducer<P: Preset, W: Wait> {
    producer_context: Arc<ProducerContext<P, W>>,
}

impl<P: Preset, W: Wait> BlockProducer<P, W> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposer_configs: Arc<ProposerConfigs>,
        builder_api: Option<Arc<BuilderApi>>,
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        eth1_chain: Eth1Chain,
        execution_engine: Arc<Eth1ExecutionEngine<P>>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let producer_context = Arc::new(ProducerContext {
            chain_config: controller.chain_config().clone_arc(),
            proposer_configs,
            builder_api,
            controller,
            dedicated_executor,
            eth1_chain,
            execution_engine,
            attestation_agg_pool,
            bls_to_execution_change_pool,
            sync_committee_agg_pool,
            prepared_proposers: Mutex::new(HashMap::new()),
            proposer_slashings: Mutex::new(vec![]),
            attester_slashings: Mutex::new(vec![]),
            voluntary_exits: Mutex::new(vec![]),
            payload_cache: Mutex::new(SizedCache::with_size(PAYLOAD_CACHE_SIZE)),
            payload_id_cache: Mutex::new(SizedCache::with_size(PAYLOAD_ID_CACHE_SIZE)),
            metrics,
        });

        Self { producer_context }
    }

    pub fn new_build_context(
        &self,
        beacon_state: Arc<BeaconState<P>>,
        head_block_root: H256,
        proposer_index: ValidatorIndex,
        options: BlockBuildOptions,
    ) -> BlockBuildContext<P, W> {
        BlockBuildContext {
            producer_context: self.producer_context.clone_arc(),
            beacon_state,
            head_block_root,
            proposer_index,
            options,
        }
    }

    pub async fn add_new_attester_slashing(&self, attester_slashing: AttesterSlashing<P>) {
        self.producer_context
            .attester_slashings
            .lock()
            .await
            .push(attester_slashing);
    }

    pub async fn add_new_prepared_proposers(
        &self,
        proposers: impl IntoIterator<Item = ProposerData> + Send,
    ) {
        let mut prepared_proposers = self.producer_context.prepared_proposers.lock().await;

        for proposer in proposers {
            prepared_proposers.insert(proposer.validator_index, proposer.fee_recipient);
        }
    }

    pub async fn add_new_proposer_slashing(&self, proposer_slashing: ProposerSlashing) {
        self.producer_context
            .proposer_slashings
            .lock()
            .await
            .push(proposer_slashing);
    }

    pub async fn discard_old_data(&self, current_epoch: Epoch) {
        let finalized_state = self
            .producer_context
            .controller
            .last_finalized_state()
            .value;

        self.producer_context
            .proposer_slashings
            .lock()
            .await
            .retain(|slashing| {
                let proposer_index = slashing.signed_header_1.message.proposer_index;

                let proposer = match finalized_state.validators().get(proposer_index) {
                    Ok(proposer) => proposer,
                    Err(error) => {
                        log_with_feature(format_args!(
                            "proposer slashing is too recent to discard: {error}"
                        ));
                        return true;
                    }
                };

                predicates::is_slashable_validator(proposer, current_epoch)
            });

        self.producer_context
            .attester_slashings
            .lock()
            .await
            .retain(|slashing| {
                accessors::slashable_indices(slashing).any(|attester_index| {
                    let attester = match finalized_state.validators().get(attester_index) {
                        Ok(attester) => attester,
                        Err(error) => {
                            log_with_feature(format_args!(
                                "attester slashing is too recent to discard: {error}"
                            ));
                            return true;
                        }
                    };

                    predicates::is_slashable_validator(attester, current_epoch)
                })
            });

        self.producer_context
            .voluntary_exits
            .lock()
            .await
            .retain(|voluntary_exit| {
                let validator_index = voluntary_exit.message.validator_index;

                let validator = match finalized_state.validators().get(validator_index) {
                    Ok(validator) => validator,
                    Err(error) => {
                        log_with_feature(format_args!(
                            "voluntary exit is too recent to discard: {error}"
                        ));
                        return true;
                    }
                };

                validator.exit_epoch == FAR_FUTURE_EPOCH
            })
    }

    pub fn finalize_deposits(&self, finalized_deposit_index: DepositIndex) -> Result<()> {
        self.producer_context
            .eth1_chain
            .finalize_deposits(finalized_deposit_index)
    }

    pub async fn get_attester_slashings(&self) -> Vec<AttesterSlashing<P>> {
        self.producer_context
            .attester_slashings
            .lock()
            .await
            .clone()
    }

    pub async fn get_prepared_proposer_indices(&self) -> Vec<ValidatorIndex> {
        self.producer_context
            .prepared_proposers
            .lock()
            .await
            .keys()
            .copied()
            .collect()
    }

    pub async fn get_proposer_slashings(&self) -> Vec<ProposerSlashing> {
        self.producer_context
            .proposer_slashings
            .lock()
            .await
            .clone()
    }

    pub async fn get_voluntary_exits(&self) -> Vec<SignedVoluntaryExit> {
        self.producer_context.voluntary_exits.lock().await.clone()
    }

    pub async fn handle_external_attester_slashing(
        &self,
        slashing: AttesterSlashing<P>,
    ) -> Result<PoolAdditionOutcome> {
        let mut attester_slashings = self.producer_context.attester_slashings.lock().await;

        let seen_indices = attester_slashings
            .iter()
            .flat_map(accessors::slashable_indices)
            .collect::<HashSet<_>>();

        if accessors::slashable_indices(&slashing).all(|index| seen_indices.contains(&index)) {
            return Ok(PoolAdditionOutcome::Ignore);
        }

        let state = self
            .producer_context
            .controller
            .preprocessed_state_at_current_slot()?;

        let outcome = match unphased::validate_attester_slashing(
            &self.producer_context.chain_config,
            &state,
            &slashing,
        ) {
            Ok(_) => {
                attester_slashings.push(slashing);
                PoolAdditionOutcome::Accept
            }
            Err(error) => {
                log_with_feature(format_args!(
                    "external attester slashing rejected (error: {error}, slashing: {slashing:?})",
                ));
                PoolAdditionOutcome::Reject(PoolRejectionReason::InvalidAttesterSlashing, error)
            }
        };

        Ok(outcome)
    }

    pub async fn handle_external_proposer_slashing(
        &self,
        slashing: ProposerSlashing,
    ) -> Result<PoolAdditionOutcome> {
        let mut proposer_slashings = self.producer_context.proposer_slashings.lock().await;

        let index_seen = proposer_slashings
            .iter()
            .map(|proposer_slashing| proposer_slashing.signed_header_1.message.proposer_index)
            .contains(&slashing.signed_header_1.message.proposer_index);

        if index_seen {
            return Ok(PoolAdditionOutcome::Ignore);
        }

        let state = self
            .producer_context
            .controller
            .preprocessed_state_at_current_slot()?;

        let outcome = match unphased::validate_proposer_slashing(
            &self.producer_context.chain_config,
            &state,
            slashing,
        ) {
            Ok(()) => {
                proposer_slashings.push(slashing);
                PoolAdditionOutcome::Accept
            }
            Err(error) => {
                warn!(
                    "external proposer slashing rejected (error: {error}, slashing: {slashing:?})",
                );
                PoolAdditionOutcome::Reject(PoolRejectionReason::InvalidProposerSlashing, error)
            }
        };

        Ok(outcome)
    }

    pub async fn handle_external_voluntary_exit(
        &self,
        exit: SignedVoluntaryExit,
    ) -> Result<PoolAdditionOutcome> {
        let mut voluntary_exits = self.producer_context.voluntary_exits.lock().await;

        let index_seen = voluntary_exits
            .iter()
            .map(|voluntary_exit| voluntary_exit.message.validator_index)
            .contains(&exit.message.validator_index);

        if index_seen {
            return Ok(PoolAdditionOutcome::Ignore);
        }

        let state = self
            .producer_context
            .controller
            .preprocessed_state_at_current_slot()?;

        let outcome = match unphased::validate_voluntary_exit(
            &self.producer_context.chain_config,
            &state,
            exit,
        ) {
            Ok(()) => {
                voluntary_exits.push(exit);
                PoolAdditionOutcome::Accept
            }
            Err(error) => {
                log_with_feature(format_args!(
                    "external voluntary exit rejected (error: {error}, exit: {exit:?})"
                ));
                PoolAdditionOutcome::Reject(PoolRejectionReason::InvalidVoluntaryExit, error)
            }
        };

        Ok(outcome)
    }

    pub async fn no_prepared_proposers(&self) -> bool {
        self.producer_context
            .prepared_proposers
            .lock()
            .await
            .is_empty()
    }

    pub async fn publish_signed_blinded_block(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Option<WithBlobsAndMev<ExecutionPayload<P>, P>> {
        let header_root = block.execution_payload_header().hash_tree_root();
        let mut payload_cache = self.producer_context.payload_cache.lock().await;
        let local_payload = payload_cache.cache_get(&header_root);

        match local_payload {
            Some(payload) => Some(payload.clone()),
            None => self.publish_signed_blinded_block_using_builder(block).await,
        }
    }

    async fn publish_signed_blinded_block_using_builder(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Option<WithBlobsAndMev<ExecutionPayload<P>, P>> {
        let controller = &self.producer_context.controller;
        let builder_api = self.producer_context.builder_api.as_deref()?;
        let current_slot = controller.slot();
        let head_block_root = controller.head_block_root().value;

        if let Err(error) = builder_api.can_use_builder_api::<P>(
            current_slot,
            controller.snapshot().nonempty_slots(head_block_root),
        ) {
            warn!("cannot use Builder API for execution payload: {error}");
            return None;
        }

        let execution_payload = match builder_api
            .post_blinded_block(
                &self.producer_context.chain_config,
                controller.genesis_time(),
                block,
            )
            .await
        {
            Ok(execution_payload) => execution_payload,
            Err(error) => {
                warn!("failed to post blinded block to the builder node: {error:?}");
                return None;
            }
        };

        log_with_feature(format_args!(
            "received execution payload from the builder node: {:?}",
            execution_payload.value
        ));

        Some(execution_payload)
    }

    pub async fn track_collection_metrics(&self) {
        if let Some(metrics) = self.producer_context.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "proposer_slashings",
                self.producer_context.proposer_slashings.lock().await.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "attester_slashings",
                self.producer_context.attester_slashings.lock().await.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "voluntary_exits",
                self.producer_context.voluntary_exits.lock().await.len(),
            );

            self.producer_context
                .eth1_chain
                .track_collection_metrics(metrics);
        }
    }
}

struct ProducerContext<P: Preset, W: Wait> {
    chain_config: Arc<ChainConfig>,
    proposer_configs: Arc<ProposerConfigs>,
    builder_api: Option<Arc<BuilderApi>>,
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    eth1_chain: Eth1Chain,
    execution_engine: Arc<Eth1ExecutionEngine<P>>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    prepared_proposers: Mutex<HashMap<ValidatorIndex, ExecutionAddress>>,
    proposer_slashings: Mutex<Vec<ProposerSlashing>>,
    attester_slashings: Mutex<Vec<AttesterSlashing<P>>>,
    voluntary_exits: Mutex<Vec<SignedVoluntaryExit>>,
    payload_cache: Mutex<SizedCache<H256, WithBlobsAndMev<ExecutionPayload<P>, P>>>,
    payload_id_cache: Mutex<SizedCache<(H256, Slot), PayloadId>>,
    metrics: Option<Arc<Metrics>>,
}

#[derive(Clone, Copy, Default)]
pub struct BlockBuildOptions {
    pub graffiti: H256,
    pub skip_randao_verification: bool,
    pub builder_boost_factor: Option<u64>,
}

#[derive(Clone)]
pub struct BlockBuildContext<P: Preset, W: Wait> {
    producer_context: Arc<ProducerContext<P, W>>,
    beacon_state: Arc<BeaconState<P>>,
    head_block_root: H256,
    proposer_index: ValidatorIndex,
    options: BlockBuildOptions,
}

impl<P: Preset, W: Wait> BlockBuildContext<P, W> {
    pub async fn build_beacon_block(
        &self,
        randao_reveal: SignatureBytes,
        local_execution_payload_handle: Option<LocalExecutionPayloadJoinHandle<P>>,
    ) -> Result<Option<(WithBlobsAndMev<BeaconBlock<P>, P>, Option<BlockRewards>)>> {
        let _block_timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.build_beacon_block_times.start_timer());

        let block_without_state_root = self
            .build_beacon_block_without_state_root(randao_reveal)
            .await?;

        let produce_beacon_block_join_handle = self.spawn_job(|build_context| async move {
            build_context
                .produce_beacon_block(block_without_state_root, local_execution_payload_handle)
                .await
        });

        wait_for_result(produce_beacon_block_join_handle).await
    }

    pub async fn build_blinded_beacon_block(
        &self,
        randao_reveal: SignatureBytes,
        execution_payload_header_handle: Option<ExecutionPayloadHeaderJoinHandle<P>>,
        local_execution_payload_handle: Option<LocalExecutionPayloadJoinHandle<P>>,
    ) -> Result<
        Option<(
            WithBlobsAndMev<ValidatorBlindedBlock<P>, P>,
            Option<BlockRewards>,
        )>,
    > {
        let block_without_state_root = self
            .build_beacon_block_without_state_root(randao_reveal)
            .await?;

        let block = block_without_state_root.clone();

        let produce_beacon_block_join_handle = self.spawn_job(|build_context| async move {
            build_context
                .produce_beacon_block(block, local_execution_payload_handle)
                .await
        });

        let produce_blinded_block_join_handle = self.spawn_job(|build_context| async move {
            build_context
                .produce_blinded_block(block_without_state_root, execution_payload_header_handle)
                .await
        });

        let beacon_block_opt = wait_for_result(produce_beacon_block_join_handle).await?;
        let blinded_block_opt = wait_for_result(produce_blinded_block_join_handle).await?;

        match (beacon_block_opt, blinded_block_opt) {
            (
                Some((beacon_block, beacon_block_rewards)),
                Some((blinded_block, blinded_block_rewards, builder_mev)),
            ) => {
                if let Some(local_mev) = beacon_block.mev {
                    let builder_boost_factor = Uint256::from_u64(
                        self.options
                            .builder_boost_factor
                            .unwrap_or(DEFAULT_BUILDER_BOOST_FACTOR.get()),
                    );

                    let boosted_builder_mev = builder_mev
                        .div(DEFAULT_BUILDER_BOOST_FACTOR)
                        .saturating_mul(builder_boost_factor);

                    if local_mev >= boosted_builder_mev {
                        info!(
                            "using more profitable local payload: \
                             local MEV: {local_mev}, builder MEV: {builder_mev}, \
                             boosted builder MEV: {boosted_builder_mev}, builder_boost_factor: {builder_boost_factor}",
                        );

                        return Ok(Some((
                            beacon_block.map(ValidatorBlindedBlock::BeaconBlock),
                            beacon_block_rewards,
                        )));
                    }
                }

                let block = ValidatorBlindedBlock::BlindedBeaconBlock {
                    blinded_block,
                    execution_payload: Box::new(
                        beacon_block
                            .value
                            .execution_payload()
                            .expect("post-Bellatrix blocks should have execution payload"),
                    ),
                };

                Ok(Some((
                    WithBlobsAndMev::new(
                        block,
                        None,
                        beacon_block.proofs,
                        beacon_block.blobs,
                        Some(builder_mev),
                    ),
                    blinded_block_rewards,
                )))
            }
            (Some((beacon_block, beacon_block_rewards)), None) => Ok(Some((
                beacon_block.map(ValidatorBlindedBlock::BeaconBlock),
                beacon_block_rewards,
            ))),
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn build_beacon_block_without_state_root(
        &self,
        randao_reveal: SignatureBytes,
    ) -> Result<BeaconBlock<P>> {
        let eth1_data = self.prepare_eth1_data()?;
        let deposits = self.prepare_deposits(eth1_data)?;

        // TODO(Grandine Team): Preparing slashings and voluntary exits independently may result
        //                      in an invalid block because a validator can only exit or be
        //                      slashed once. The code below can handle invalid blocks, but it may
        //                      prevent the validator from proposing.
        let proposer_slashings = self.prepare_proposer_slashings().await;
        let attester_slashings = self.prepare_attester_slashings().await;
        let voluntary_exits = self.prepare_voluntary_exits().await;

        let attestations = self.prepare_attestations().await?;
        let sync_aggregate = self.prepare_sync_aggregate().await?;
        let bls_to_execution_changes = self.prepare_bls_to_execution_changes().await;

        let slot = self.beacon_state.slot();
        let proposer_index = self.proposer_index;
        let parent_root = self.head_block_root;
        let graffiti = self.options.graffiti;

        // This is a placeholder that is overwritten later using `with_state_root`.
        // We define this explicitly instead of using struct update syntax to ensure
        // we fill all fields when constructing a block.
        let state_root = H256::zero();

        match self.beacon_state.phase() {
            Phase::Phase0 => BeaconBlock::from(Phase0BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: Phase0BeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                },
            }),
            Phase::Altair => BeaconBlock::from(AltairBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: AltairBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                },
            }),
            Phase::Bellatrix => BeaconBlock::from(BellatrixBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BellatrixBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: BellatrixExecutionPayload::default(),
                },
            }),
            Phase::Capella => BeaconBlock::from(CapellaBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: CapellaBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: CapellaExecutionPayload::default(),
                    bls_to_execution_changes,
                },
            }),
            Phase::Deneb => BeaconBlock::from(DenebBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: DenebBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings,
                    attestations,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: DenebExecutionPayload::default(),
                    bls_to_execution_changes,
                    blob_kzg_commitments: ContiguousList::default(),
                },
            }),
        }
        .pipe(Ok)
    }

    fn blinded_block_from_beacon_block(
        &self,
        beacon_block: BeaconBlock<P>,
        payload_header: ExecutionPayloadHeader<P>,
        blob_kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Option<(BlindedBeaconBlock<P>, Option<BlockRewards>)> {
        let without_state_root =
            match beacon_block.into_blinded(payload_header, blob_kzg_commitments) {
                Ok(block) => block,
                Err(error) => {
                    warn!("constructed invalid blinded beacon block (error: {error:?})");
                    return None;
                }
            };

        let block_processor = self.producer_context.controller.block_processor();
        let pre_state = self.beacon_state.clone_arc();

        let result = if Feature::TrustOwnBlockSignatures.is_enabled() {
            block_processor
                .process_trusted_blinded_block_with_report(pre_state, &without_state_root)
        } else {
            block_processor.process_untrusted_blinded_block_with_report(
                pre_state,
                &without_state_root,
                self.options.skip_randao_verification,
            )
        };

        let (post_state, block_rewards) = match result {
            Ok((state, block_rewards)) => (state, block_rewards),
            Err(error) => {
                warn!(
                    "constructed invalid blinded beacon block \
                     (error: {error:?}, without_state_root: {without_state_root:?})",
                );
                return None;
            }
        };

        // Computing and setting the state root could be skipped when `skip_randao_verification`
        // is `true`. The resulting block is invalid either way. The client would have to mix in
        // the real RANDAO reveal and recompute the state root to make it valid.
        let with_state_root = without_state_root.with_state_root(post_state.hash_tree_root());

        Some((with_state_root, block_rewards))
    }

    fn process_beacon_block(
        &self,
        without_state_root: BeaconBlock<P>,
    ) -> Option<(BeaconBlock<P>, Option<BlockRewards>)> {
        let block_processor = self.producer_context.controller.block_processor();
        let pre_state = self.beacon_state.clone_arc();

        let result = if Feature::TrustOwnBlockSignatures.is_enabled() {
            block_processor.process_trusted_block_with_report(pre_state, &without_state_root)
        } else {
            block_processor.process_untrusted_block_with_report(
                pre_state,
                &without_state_root,
                self.options.skip_randao_verification,
            )
        };

        let (post_state, block_rewards) = match result {
            Ok((state, block_rewards)) => (state, block_rewards),
            Err(error) => {
                warn!(
                    "constructed invalid beacon block \
                     (error: {error:?}, without_state_root: {without_state_root:?})",
                );
                return None;
            }
        };

        // Computing and setting the state root could be skipped when `skip_randao_verification`
        // is `true`. The resulting block is invalid either way. The client would have to mix in
        // the real RANDAO reveal and recompute the state root to make it valid.
        let beacon_block = without_state_root.with_state_root(post_state.hash_tree_root());

        Some((beacon_block, block_rewards))
    }

    pub async fn produce_beacon_block(
        &self,
        block_without_state_root: BeaconBlock<P>,
        local_execution_payload_handle: Option<LocalExecutionPayloadJoinHandle<P>>,
    ) -> Result<Option<(WithBlobsAndMev<BeaconBlock<P>, P>, Option<BlockRewards>)>> {
        let with_blobs_and_mev = if let Some(handle) = local_execution_payload_handle {
            handle.await?.map(|value| value.map(Some))
        } else {
            None
        };

        let WithBlobsAndMev {
            value: mut execution_payload,
            commitments,
            proofs,
            blobs,
            mev,
        } = with_blobs_and_mev.unwrap_or_else(|| WithBlobsAndMev::with_default(None));

        let slot = self.beacon_state.slot();

        // Starting with Capella, all blocks must be post-Merge.
        // Construct a superficially valid execution payload for snapshot testing.
        // It will almost always be invalid in a real network, but so would a default payload.
        // Construct the payload with a fictitious `ExecutionBlockHash` derived from the slot.
        // Computing the real `ExecutionBlockHash` would make maintaining tests much harder.
        if self.beacon_state.phase() >= Phase::Capella && execution_payload.is_none() {
            execution_payload = Some(factory::execution_payload(
                &self.producer_context.chain_config,
                &self.beacon_state,
                slot,
                ExecutionBlockHash::from_low_u64_be(slot),
            )?);
        }

        let without_state_root_with_payload = block_without_state_root
            .with_execution_payload(execution_payload)?
            .with_blob_kzg_commitments(commitments);

        self.process_beacon_block(without_state_root_with_payload)
            .map(|(beacon_block, block_rewards)| {
                (
                    WithBlobsAndMev::new(
                        beacon_block,
                        // Commitments are moved to block.
                        None,
                        proofs,
                        blobs,
                        mev,
                    ),
                    block_rewards,
                )
            })
            .pipe(Ok)
    }

    pub async fn produce_blinded_block(
        &self,
        block_without_state_root: BeaconBlock<P>,
        execution_payload_header_handle: Option<ExecutionPayloadHeaderJoinHandle<P>>,
    ) -> Result<Option<(BlindedBeaconBlock<P>, Option<BlockRewards>, Uint256)>> {
        let Some(header_handle) = execution_payload_header_handle else {
            return Ok(None);
        };

        match header_handle.await? {
            Ok(Some(response)) => {
                let blob_kzg_commitments = response.blob_kzg_commitments().cloned();
                let builder_mev = response.mev();

                self.blinded_block_from_beacon_block(
                    block_without_state_root,
                    response.execution_payload_header(),
                    blob_kzg_commitments,
                )
                .map(|(blinded_block, block_rewards)| (blinded_block, block_rewards, builder_mev))
                .pipe(Ok)
            }
            Ok(None) => Ok(None),
            Err(error) => {
                warn!("failed to get execution payload header: {error}");
                Ok(None)
            }
        }
    }

    fn prepare_eth1_data(&self) -> Result<Eth1Data> {
        self.producer_context
            .eth1_chain
            .eth1_vote(
                &self.producer_context.chain_config,
                self.producer_context.metrics.as_ref(),
                &self.beacon_state,
            )
            .context("failed to prepare eth1 data")
    }

    async fn prepare_proposer_slashings(
        &self,
    ) -> ContiguousList<ProposerSlashing, P::MaxProposerSlashings> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_proposer_slashings_times.start_timer());

        let mut slashings = self.producer_context.proposer_slashings.lock().await;

        let split_index = itertools::partition(slashings.iter_mut(), |slashing| {
            unphased::validate_proposer_slashing(
                &self.producer_context.chain_config,
                &self.beacon_state,
                *slashing,
            )
            .is_ok()
        });

        let slashings = ContiguousList::try_from_iter(
            slashings.drain(0..split_index.min(P::MaxProposerSlashings::USIZE)),
        )
        .expect(
            "the call to Vec::drain above limits the \
             iterator to P::MaxProposerSlashings::USIZE elements",
        );

        log_with_feature(format_args!(
            "proposer slashings for proposal: {slashings:?}"
        ));

        slashings
    }

    async fn prepare_attester_slashings(
        &self,
    ) -> ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashings> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_attester_slashings_times.start_timer());

        let mut slashings = self.producer_context.attester_slashings.lock().await;

        let split_index = itertools::partition(slashings.iter_mut(), |slashing| {
            unphased::validate_attester_slashing(
                &self.producer_context.chain_config,
                &self.beacon_state,
                slashing,
            )
            .is_ok()
        });

        let slashings = ContiguousList::try_from_iter(
            slashings.drain(0..split_index.min(P::MaxAttesterSlashings::USIZE)),
        )
        .expect(
            "the call to Vec::drain above limits the \
             iterator to P::MaxAttesterSlashings::USIZE elements",
        );

        log_with_feature(format_args!(
            "attester slashings for proposal: {slashings:?}"
        ));

        slashings
    }

    async fn prepare_attestations(
        &self,
    ) -> Result<ContiguousList<Attestation<P>, P::MaxAttestations>> {
        self.producer_context
            .attestation_agg_pool
            .best_proposable_attestations(self.beacon_state.clone_arc())
            .await
    }

    fn prepare_deposits(
        &self,
        eth1_data: Eth1Data,
    ) -> Result<ContiguousList<Deposit, P::MaxDeposits>> {
        self.producer_context
            .eth1_chain
            .pending_deposits(
                &self.beacon_state,
                eth1_data,
                self.producer_context.metrics.as_ref(),
            )
            .context("failed to prepare deposits")
    }

    async fn prepare_voluntary_exits(
        &self,
    ) -> ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_voluntary_exits_times.start_timer());

        let mut exits = self.producer_context.voluntary_exits.lock().await;

        let split_index = itertools::partition(exits.iter_mut(), |voluntary_exit| {
            unphased::validate_voluntary_exit(
                &self.producer_context.chain_config,
                &self.beacon_state,
                *voluntary_exit,
            )
            .is_ok()
        });

        let exits = ContiguousList::try_from_iter(
            exits.drain(0..split_index.min(P::MaxVoluntaryExits::USIZE)),
        )
        .expect(
            "the call to Vec::drain above limits the \
             iterator to P::MaxVoluntaryExits::USIZE elements",
        );

        log_with_feature(format_args!("voluntary exits for proposal: {exits:?}"));

        exits
    }

    async fn prepare_sync_aggregate(&self) -> Result<SyncAggregate<P>> {
        let _timer = self.producer_context.metrics.as_ref().map(|metrics| {
            metrics
                .process_sync_committee_contribution_times
                .start_timer()
        });

        if self.beacon_state.post_altair().is_none() {
            return Ok(SyncAggregate::empty());
        }

        // TODO(Grandine Team): `SyncAggregate` participation could be made higher by aggregating
        //                      `SyncCommitteeMessage`s just like `AttestationPacker` does with
        //                      singular attestations.
        let beacon_block_root = self.head_block_root;
        let message_slot = self.beacon_state.slot().saturating_sub(1).max(GENESIS_SLOT);
        let best_subcommittee_contributions = (0..SyncCommitteeSubnetCount::U64)
            .map(|subcommittee_index| {
                self.producer_context
                    .sync_committee_agg_pool
                    .best_subcommittee_contribution(
                        message_slot,
                        beacon_block_root,
                        subcommittee_index,
                    )
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await;

        let mut sync_committee_bits = BitVector::default();
        let mut sync_committee_signature = AggregateSignature::default();

        for contribution in best_subcommittee_contributions {
            let subcommittee_index = contribution.subcommittee_index;

            for (index, participated) in contribution.aggregation_bits.into_iter().enumerate() {
                if participated {
                    let participant_index = SyncSubcommitteeSize::<P>::USIZE
                        * usize::try_from(subcommittee_index)?
                        + index;
                    sync_committee_bits.set(participant_index, true);
                }
            }

            sync_committee_signature.aggregate_in_place(contribution.signature.try_into()?);
        }

        Ok(SyncAggregate {
            sync_committee_bits,
            sync_committee_signature: sync_committee_signature.into(),
        })
    }

    async fn prepare_bls_to_execution_changes(
        &self,
    ) -> ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_bls_to_execution_changes_times.start_timer());

        let Some(state) = self.beacon_state.post_capella() else {
            return ContiguousList::default();
        };

        self.producer_context
            .bls_to_execution_change_pool
            .signed_bls_to_execution_changes()
            .await
            .map_err(|error| {
                warn!("unable to retrieve BLS to execution changes from operation pool: {error:?}");
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|bls_to_execution_change| {
                capella::validate_bls_to_execution_change(
                    &self.producer_context.chain_config,
                    state,
                    *bls_to_execution_change,
                )
                .is_ok()
            })
            .take(P::MaxBlsToExecutionChanges::USIZE)
            .pipe(ContiguousList::try_from_iter)
            .expect(
                "the call to Iterator::take limits the number of \
                 BlsToExecutionChange to P::MaxBlsToExecutionChanges::USIZE",
            )
    }

    pub async fn prepare_execution_payload_for_slot(
        &self,
        slot: Slot,
        safe_execution_payload_hash: ExecutionBlockHash,
        finalized_execution_payload_hash: ExecutionBlockHash,
    ) {
        let head_root = self.head_block_root;

        let payload_id = self
            .prepare_execution_payload(
                safe_execution_payload_hash,
                finalized_execution_payload_hash,
            )
            .await;

        match payload_id {
            Ok(payload_id_option) => {
                match payload_id_option {
                    Some(payload_id) => {
                        info!(
                            "started work on execution payload with id {payload_id:?} \
                             for head {head_root:?} at slot {slot}",
                        );

                        self.producer_context.payload_id_cache.lock().await.cache_set((head_root, slot), payload_id);
                    }
                    // If we have no block at 4th-second mark, we preprocess new state without the block.
                    // In such case, after the state is preprocessed, we attempt to prepare the execution payload for the next slot with
                    // outdated EL head block hash, which EL client might discard as too old if it has seen newer blocks.
                    None => warn!(
                        "could not prepare execution payload: payload_id is None; \
                         ensure that multiple consensus clients are not driving the same execution client",
                    ),
                }
            }
            Err(error) => warn!("error while preparing execution payload: {error:?}"),
        }
    }

    async fn prepare_execution_payload(
        &self,
        safe_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
    ) -> Result<Option<PayloadId>> {
        let chain_config = &self.producer_context.chain_config;
        let state = self.beacon_state.as_ref();

        if state.post_bellatrix().is_none() {
            return Ok(None);
        }

        let epoch = accessors::get_current_epoch(state);
        let timestamp = misc::compute_timestamp_at_slot(chain_config, state, state.slot());
        let suggested_fee_recipient = self.fee_recipient().await?;

        // > [Modified in Capella] Removed `is_merge_transition_complete` check in Capella
        //
        // See <https://github.com/ethereum/consensus-specs/pull/3350>.
        let parent_hash = if let Some(state) = state.post_capella() {
            state.latest_execution_payload_header().block_hash()
        } else if let Some(state) = post_merge_state(state) {
            state.latest_execution_payload_header().block_hash()
        } else {
            let is_terminal_block_hash_set = !chain_config.terminal_block_hash.is_zero();
            let is_activation_epoch_reached =
                epoch >= chain_config.terminal_block_hash_activation_epoch;

            if is_terminal_block_hash_set && !is_activation_epoch_reached {
                return Ok(None);
            }

            let Some(terminal_pow_block) = self
                .producer_context
                .execution_engine
                .get_terminal_pow_block()
                .await?
            else {
                return Ok(None);
            };

            // If the terminal PoW block was found by difficulty, ensure that
            // `terminal_pow_block.timestamp < timestamp` to avoid making the payload invalid. See:
            // - <https://github.com/ethereum/hive/pull/569>
            // - <https://github.com/sigp/lighthouse/issues/3316>
            // - <https://github.com/prysmaticlabs/prysm/issues/11069>
            // The root cause of this is a conflict between execution and consensus specifications.
            if chain_config.terminal_block_hash.is_zero()
                && terminal_pow_block.timestamp >= timestamp
            {
                return Ok(None);
            }

            terminal_pow_block.pow_block.block_hash
        };

        let prev_randao = accessors::get_randao_mix(state, epoch);

        let payload_attributes = match state {
            BeaconState::Phase0(_) | BeaconState::Altair(_) => return Ok(None),
            BeaconState::Bellatrix(_) => PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }
            .into(),
            BeaconState::Capella(state) => {
                let withdrawals = capella::get_expected_withdrawals(state)?
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                PayloadAttributesV2 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                }
                .into()
            }
            BeaconState::Deneb(state) => {
                let withdrawals = capella::get_expected_withdrawals(state)?
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                let parent_beacon_block_root =
                    accessors::get_block_root_at_slot(state, state.slot().saturating_sub(1))?;

                PayloadAttributesV3 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                }
                .into()
            }
        };

        let (sender, receiver) = futures::channel::oneshot::channel();

        self.producer_context
            .execution_engine
            .notify_forkchoice_updated(
                parent_hash,
                safe_block_hash,
                finalized_block_hash,
                Either::Right(payload_attributes),
                Some(sender),
            );

        receiver.await.map_err(Into::into)
    }

    pub fn get_execution_payload_header(
        &self,
        public_key: PublicKeyBytes,
    ) -> Option<ExecutionPayloadHeaderJoinHandle<P>> {
        if let Some(state) = self.beacon_state.post_bellatrix() {
            if let Some(builder_api) = self.producer_context.builder_api.clone() {
                let slot = self.beacon_state.slot();

                if let Err(error) = builder_api.can_use_builder_api::<P>(
                    slot,
                    self.producer_context
                        .controller
                        .snapshot()
                        .nonempty_slots(self.head_block_root),
                ) {
                    warn!("cannot use Builder API for execution payload header: {error}");
                    return None;
                }

                let chain_config = self.producer_context.chain_config.clone_arc();
                let parent_hash = state.latest_execution_payload_header().block_hash();

                let handle = tokio::spawn(async move {
                    builder_api
                        .get_execution_payload_header::<P>(
                            &chain_config,
                            slot,
                            parent_hash,
                            public_key,
                        )
                        .await
                });

                return Some(handle);
            }
        };

        None
    }

    pub fn get_local_execution_payload(&self) -> Option<LocalExecutionPayloadJoinHandle<P>> {
        self.beacon_state.post_bellatrix()?;

        let builder_context = self.clone();

        let handle =
            tokio::spawn(async move { builder_context.local_execution_payload_option().await });

        Some(handle)
    }

    async fn local_execution_payload_result(
        &self,
    ) -> Result<Option<WithBlobsAndMev<ExecutionPayload<P>, P>>> {
        let snapshot = self.producer_context.controller.snapshot();

        let mut payload_id = self
            .producer_context
            .payload_id_cache
            .lock()
            .await
            .cache_get(&(self.head_block_root, self.beacon_state.slot()))
            .copied()
            .map(PayloadIdEntry::Cached);

        if payload_id.is_none() {
            warn!(
                "payload_id not found in payload_id_cache for {:?}",
                self.head_block_root
            );

            payload_id = self
                .prepare_execution_payload(
                    snapshot.safe_execution_payload_hash(),
                    snapshot.finalized_execution_payload_hash(),
                )
                .await?
                .map(PayloadIdEntry::Live)
        };

        let Some(payload_id) = payload_id else {
            error!(
                "payload_id from execution layer was not received; This will lead to missed block"
            );

            return Ok(None);
        };

        let payload = match self
            .producer_context
            .execution_engine
            .get_execution_payload(payload_id.id())
            .await
        {
            Ok(payload) => payload,
            Err(error) => {
                warn!("unable to retrieve payload with payload_id {payload_id:?}: {error:?}");

                match payload_id {
                    PayloadIdEntry::Cached(_) => {
                        let payload_id = self
                            .prepare_execution_payload(
                                snapshot.safe_execution_payload_hash(),
                                snapshot.finalized_execution_payload_hash(),
                            )
                            .await?;

                        if let Some(payload_id) = payload_id {
                            info!("successfully retrieved non-cached payload_id: {payload_id:?}");

                            self.producer_context
                                .execution_engine
                                .get_execution_payload(payload_id)
                                .await?
                        } else {
                            error!(
                                "payload_id from execution layer was not received; This will lead to missed block"
                            );

                            return Ok(None);
                        }
                    }
                    PayloadIdEntry::Live(_) => return Err(error),
                }
            }
        };

        let payload_root = payload.value.hash_tree_root();

        self.producer_context
            .payload_cache
            .lock()
            .await
            .cache_set(payload_root, payload.clone());

        Ok(Some(payload))
    }

    // If the local execution engine fails, a block can still be constructed with a payload received
    // from an external block builder or even the default payload, though blocks with default
    // payloads are only valid before the Merge.
    async fn local_execution_payload_option(
        &self,
    ) -> Option<WithBlobsAndMev<ExecutionPayload<P>, P>> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.local_execution_payload_times.start_timer());

        self.local_execution_payload_result()
            .await
            .map_err(|error| warn!("execution engine failed to produce payload: {error:?}"))
            .ok()
            .flatten()
    }

    async fn fee_recipient(&self) -> Result<ExecutionAddress> {
        self.producer_context
            .prepared_proposers
            .lock()
            .await
            .get(&self.proposer_index)
            .copied()
            .map(Result::Ok)
            .unwrap_or_else(|| {
                let proposer_pubkey =
                    accessors::public_key(&self.beacon_state, self.proposer_index)?;
                self.producer_context
                    .proposer_configs
                    .fee_recipient(proposer_pubkey.to_bytes())
            })
    }

    fn spawn_job<T, F>(&self, task: T) -> Job<F::Output>
    where
        T: FnOnce(Self) -> F,
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.producer_context
            .dedicated_executor
            .spawn(task(self.clone()))
    }
}

fn log_with_feature(message: impl Display) {
    features::log!(DebugBlockProducer, "{message}");
}

fn post_merge_state<P: Preset>(state: &BeaconState<P>) -> Option<&dyn PostBellatrixBeaconState<P>> {
    state
        .post_bellatrix()
        .filter(|state| predicates::is_merge_transition_complete(*state))
}

async fn wait_for_result<T: Send>(job: Job<Result<T>>) -> Result<T> {
    job.await
        .map_err(AnyhowError::msg)
        .context("block producer task failed")?
}
