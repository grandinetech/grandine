use core::{fmt::Display, future::Future, marker::PhantomData, ops::Div as _};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Context as _, Error as AnyhowError, Result, anyhow};
use bls::{
    AggregateSignature, PublicKeyBytes, SignatureBytes,
    traits::{Signature as _, SignatureBytes as _},
};
use builder_api::{
    BuilderApi, PayloadBuilderApi,
    combined::SignedBuilderBid,
    consts::{BUILDER_BID_REQUEST_TIMEOUT, MaxBuilderEntries},
    gloas::containers::{BuilderEntry, BuilderUrl},
};
use cached::{Cached as _, SizedCache};
use dedicated_executor::{DedicatedExecutor, Job};
use eth1_api::{ApiController, ClientVersions, Eth1ExecutionEngine, WithClientVersions};
use execution_engine::{
    ExecutionEngine as _, PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2,
    PayloadAttributesV3, PayloadAttributesV4, PayloadId,
};
use features::Feature;
use fork_choice_control::{Snapshot, Wait};
use futures::{
    lock::Mutex,
    stream::{FuturesOrdered, FuturesUnordered, StreamExt as _},
};
use helper_functions::{accessors, misc, predicates};
use itertools::{Either, Itertools as _};
use keymanager::ProposerConfigs;
use logging::{debug_with_peers, error_with_peers, info_with_peers, warn_with_peers};
use operation_pools::{
    AttestationAggPool, BlsToExecutionChangePool, PayloadAttestationAggPool, PoolAdditionOutcome,
    PoolAttestation, PoolRejectionReason, SyncCommitteeAggPool,
};
use prometheus_metrics::Metrics;
use pubkey_cache::PubkeyCache;
use ssz::{BitVector, ContiguousList, Hc, ProgressiveList, SszHash, SszList as _};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use tokio::task::JoinHandle;
use tracing::instrument;
use transition_functions::{capella, electra, gloas, unphased};
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
    bellatrix::{
        containers::{
            BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
            ExecutionPayload as BellatrixExecutionPayload,
        },
        primitives::Gas,
    },
    capella::containers::{
        BeaconBlock as CapellaBeaconBlock, BeaconBlockBody as CapellaBeaconBlockBody,
        ExecutionPayload as CapellaExecutionPayload, SignedBlsToExecutionChange,
    },
    combined::{
        AttesterSlashing, BeaconBlock, BeaconState, BlindedBeaconBlock, ExecutionPayload,
        ExecutionPayloadHeader, ExecutionRequests, SignedBlindedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::{
        containers::{
            BeaconBlock as DenebBeaconBlock, BeaconBlockBody as DenebBeaconBlockBody,
            ExecutionPayload as DenebExecutionPayload,
        },
        primitives::{Blob, KzgCommitment},
    },
    electra::containers::{
        Attestation as ElectraAttestation, AttesterSlashing as ElectraAttesterSlashing,
        BeaconBlock as ElectraBeaconBlock, BeaconBlockBody as ElectraBeaconBlockBody,
        ExecutionRequests as ElectraExecutionRequests,
    },
    fulu::containers::{BeaconBlock as FuluBeaconBlock, BeaconBlockBody as FuluBeaconBlockBody},
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        consts::BUILDER_INDEX_SELF_BUILD,
        containers::{
            AttesterSlashing as GloasAttesterSlashing, BeaconBlock as GloasBeaconBlock,
            BeaconBlockBody as GloasBeaconBlockBody, ExecutionPayloadBid, ExecutionPayloadEnvelope,
            ExecutionRequests as GloasExecutionRequests, PayloadAttestation, ProposerPreferences,
            SignedExecutionPayloadBid,
        },
    },
    nonstandard::{BlockRewards, KzgProofs, Phase, WEI_IN_GWEI, WithBlobsAndMev},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::{
            Attestation, AttestationData, AttesterSlashing as Phase0AttesterSlashing,
            BeaconBlock as Phase0BeaconBlock, BeaconBlockBody as Phase0BeaconBlockBody,
            ProposerSlashing, SignedVoluntaryExit,
        },
        primitives::{
            CommitteeIndex, Epoch, ExecutionAddress, ExecutionBlockHash, ExecutionBlockNumber,
            Gwei, H256, Slot, Uint256, ValidatorIndex,
        },
    },
    preset::{Preset, SyncSubcommitteeSize},
    traits::{BeaconState as _, PostBellatrixBeaconState, PostGloasBeaconState},
};

use crate::misc::{
    BlindedBlockPublication, PayloadIdEntry, ProposerData, ValidatorBlindedBlock, build_graffiti,
};

const PAYLOAD_CACHE_SIZE: usize = 20;
const PAYLOAD_ID_CACHE_SIZE: usize = 10;

pub type ExecutionPayloadHeaderJoinHandle<P> = JoinHandle<Result<Option<SignedBuilderBid<P>>>>;
pub type BuilderApiBidsJoinHandle<P> = JoinHandle<Vec<BuilderApiBid<P>>>;
pub type LocalExecutionPayloadJoinHandle<P> =
    JoinHandle<Option<WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>>>;

type PayloadCache<P> =
    Mutex<SizedCache<H256, WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>>>;

#[derive(Default)]
pub struct Options {
    pub fake_execution_payloads: bool,
}

pub struct BlockProducer<P: Preset, W: Wait> {
    producer_context: Arc<ProducerContext<P, W>>,
}

impl<P: Preset, W: Wait> BlockProducer<P, W> {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        proposer_configs: Arc<ProposerConfigs>,
        builder_api: Option<Arc<BuilderApi>>,
        payload_builder_api: Arc<PayloadBuilderApi>,
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        execution_engine: Arc<Eth1ExecutionEngine<P>>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
        metrics: Option<Arc<Metrics>>,
        options: Option<Options>,
    ) -> Self {
        let Options {
            fake_execution_payloads,
        } = options.unwrap_or_default();

        let producer_context = Arc::new(ProducerContext {
            chain_config: controller.chain_config().clone_arc(),
            pubkey_cache: controller.pubkey_cache().clone_arc(),
            proposer_configs,
            builder_api,
            payload_builder_api,
            controller,
            dedicated_executor,
            execution_engine,
            attestation_agg_pool,
            bls_to_execution_change_pool,
            sync_committee_agg_pool,
            payload_attestation_agg_pool,
            prepared_proposers: Mutex::new(HashMap::new()),
            proposer_slashings: Mutex::new(vec![]),
            attester_slashings: Mutex::new(vec![]),
            voluntary_exits: Mutex::new(vec![]),
            payload_cache: Mutex::new(SizedCache::with_size(PAYLOAD_CACHE_SIZE)),
            payload_id_cache: Mutex::new(SizedCache::with_size(PAYLOAD_ID_CACHE_SIZE)),
            cached_payload_roots: Mutex::new(SizedCache::with_size(PAYLOAD_CACHE_SIZE)),
            self_built_block_parents: Mutex::new(SizedCache::with_size(PAYLOAD_CACHE_SIZE)),
            metrics,
            fake_execution_payloads,
        });

        Self { producer_context }
    }

    #[must_use]
    pub fn proposer_configs(&self) -> &ProposerConfigs {
        &self.producer_context.proposer_configs
    }

    #[must_use]
    pub fn payload_builder_api(&self) -> &Arc<PayloadBuilderApi> {
        &self.producer_context.payload_builder_api
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

    #[expect(clippy::too_many_lines)]
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

                let proposer = match finalized_state
                    .validators()
                    .partial_validator(proposer_index)
                {
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
            .retain(|slashing| match slashing {
                AttesterSlashing::Phase0(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).any(|attester_index| {
                        let attester = match finalized_state
                            .validators()
                            .partial_validator(attester_index)
                        {
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
                }
                AttesterSlashing::Electra(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).any(|attester_index| {
                        let attester = match finalized_state
                            .validators()
                            .partial_validator(attester_index)
                        {
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
                }
                AttesterSlashing::Gloas(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).any(|attester_index| {
                        let attester = match finalized_state
                            .validators()
                            .partial_validator(attester_index)
                        {
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
                }
            });

        self.producer_context
            .voluntary_exits
            .lock()
            .await
            .retain(|voluntary_exit| {
                let validator_index = voluntary_exit.message.validator_index;

                let validator = match finalized_state
                    .validators()
                    .partial_validator(validator_index)
                {
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
            .flat_map(|attester_slashing| match attester_slashing {
                AttesterSlashing::Phase0(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).collect::<HashSet<_>>()
                }
                AttesterSlashing::Electra(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).collect::<HashSet<_>>()
                }
                AttesterSlashing::Gloas(attester_slashing) => {
                    accessors::slashable_indices(attester_slashing).collect::<HashSet<_>>()
                }
            })
            .collect::<HashSet<_>>();

        let all_seen = match slashing {
            AttesterSlashing::Phase0(ref attester_slashing) => {
                accessors::slashable_indices(attester_slashing)
                    .all(|index| seen_indices.contains(&index))
            }
            AttesterSlashing::Electra(ref attester_slashing) => {
                accessors::slashable_indices(attester_slashing)
                    .all(|index| seen_indices.contains(&index))
            }
            AttesterSlashing::Gloas(ref attester_slashing) => {
                accessors::slashable_indices(attester_slashing)
                    .all(|index| seen_indices.contains(&index))
            }
        };

        if all_seen {
            return Ok(PoolAdditionOutcome::Ignore);
        }

        let state = self
            .producer_context
            .controller
            .preprocessed_state_at_current_slot()
            .await?;

        // TODO(feature/electra): implement trait for types::combined::AttesterSlashing
        let result = match slashing {
            AttesterSlashing::Phase0(ref attester_slashing) => {
                unphased::validate_attester_slashing(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &state,
                    attester_slashing,
                )
            }
            AttesterSlashing::Electra(ref attester_slashing) => {
                unphased::validate_attester_slashing(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &state,
                    attester_slashing,
                )
            }
            AttesterSlashing::Gloas(ref attester_slashing) => unphased::validate_attester_slashing(
                &self.producer_context.chain_config,
                &self.producer_context.pubkey_cache,
                &state,
                attester_slashing,
            ),
        };

        let outcome = match result {
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
            .preprocessed_state_at_current_slot()
            .await?;

        let outcome = match unphased::validate_proposer_slashing(
            &self.producer_context.chain_config,
            &self.producer_context.pubkey_cache,
            &state,
            slashing,
        ) {
            Ok(()) => {
                proposer_slashings.push(slashing);
                PoolAdditionOutcome::Accept
            }
            Err(error) => {
                warn_with_peers!(
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
            .preprocessed_state_at_current_slot()
            .await?;

        let result = match state.as_ref() {
            BeaconState::Phase0(_)
            | BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_) => unphased::validate_voluntary_exit(
                &self.producer_context.chain_config,
                &self.producer_context.pubkey_cache,
                &state,
                exit,
            ),
            BeaconState::Electra(state) => electra::validate_voluntary_exit(
                &self.producer_context.chain_config,
                &self.producer_context.pubkey_cache,
                state,
                exit,
            ),
            BeaconState::Fulu(state) => electra::validate_voluntary_exit(
                &self.producer_context.chain_config,
                &self.producer_context.pubkey_cache,
                state,
                exit,
            ),
            BeaconState::Gloas(state) => electra::validate_voluntary_exit(
                &self.producer_context.chain_config,
                &self.producer_context.pubkey_cache,
                state,
                exit,
            ),
        };

        let outcome = match result {
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
    ) -> Option<BlindedBlockPublication<P>> {
        let header_root = block.execution_payload_header().hash_tree_root();
        let mut payload_cache = self.producer_context.payload_cache.lock().await;
        let local_payload = payload_cache.cache_get(&header_root);

        match local_payload {
            Some(payload) => Some(BlindedBlockPublication::Payload(Box::new(payload.clone()))),
            None => self.publish_signed_blinded_block_using_builder(block).await,
        }
    }

    async fn publish_signed_blinded_block_using_builder(
        &self,
        block: &SignedBlindedBeaconBlock<P>,
    ) -> Option<BlindedBlockPublication<P>> {
        let controller = &self.producer_context.controller;
        let builder_api = self.producer_context.builder_api.as_deref()?;
        let current_slot = controller.slot();
        let head_block_root = controller.head_block_root().value;

        if let Err(error) = builder_api.can_use_builder_api::<P>(
            current_slot,
            controller.snapshot().nonempty_slots(head_block_root),
        ) {
            warn_with_peers!("cannot use Builder API for execution payload: {error}");
            return None;
        }

        if block.phase() >= Phase::Fulu {
            match builder_api
                .post_blinded_block_post_fulu(
                    &self.producer_context.chain_config,
                    controller.genesis_time(),
                    block,
                )
                .await
            {
                Ok(()) => return Some(BlindedBlockPublication::PublishedByBuilder),
                // The builder may still publish the block, and a v1 retry would wait another interval.
                Err(error)
                    if error
                        .downcast_ref::<reqwest::Error>()
                        .is_some_and(reqwest::Error::is_timeout) =>
                {
                    debug_with_peers!(
                        "failed to post blinded block to the builder node: {error:?}"
                    );

                    return None;
                }
                Err(error) => warn_with_peers!(
                    "builder did not accept the blinded block for publishing, \
                     requesting its payload instead: {error:?}"
                ),
            }
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
                if error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)
                {
                    // If posting signed blinded beacon block to builder fails, don't print a warning,
                    // because builder should publish the block anyway, just cannot respond in a timely
                    // manner. We cannot do anything else here either, but exit early from propose, due
                    // to the risk of slashing.
                    debug_with_peers!(
                        "failed to post blinded block to the builder node: {error:?}"
                    );

                    return None;
                }

                warn_with_peers!("failed to post blinded block to the builder node: {error:?}");
                return None;
            }
        };

        log_with_feature(format_args!(
            "received execution payload from the builder node: {:?}",
            execution_payload.value
        ));

        Some(BlindedBlockPublication::Payload(Box::new(
            WithClientVersions::none(execution_payload),
        )))
    }

    pub async fn cache_self_built_block_parent(
        &self,
        beacon_block_root: H256,
        parent_beacon_block_root: H256,
    ) {
        self.producer_context
            .self_built_block_parents
            .lock()
            .await
            .cache_set(beacon_block_root, parent_beacon_block_root);
    }

    pub async fn cached_execution_payload_envelope_contents(
        &self,
        beacon_block_root: H256,
    ) -> Option<ExecutionPayloadEnvelopeContents<P>> {
        let parent_beacon_block_root = self
            .producer_context
            .self_built_block_parents
            .lock()
            .await
            .cache_get(&beacon_block_root)
            .copied()?;

        self.build_local_execution_payload_envelope_contents(
            beacon_block_root,
            parent_beacon_block_root,
        )
        .await
    }

    pub async fn build_local_execution_payload_envelope_contents(
        &self,
        beacon_block_root: H256,
        parent_beacon_block_root: H256,
    ) -> Option<ExecutionPayloadEnvelopeContents<P>> {
        let payload_root = self
            .producer_context
            .cached_payload_roots
            .lock()
            .await
            .cache_get(&parent_beacon_block_root)
            .copied()?;

        let local_payload = self
            .producer_context
            .payload_cache
            .lock()
            .await
            .cache_get(&payload_root)
            .cloned()?;

        let WithBlobsAndMev {
            value: execution_payload,
            execution_requests,
            proofs,
            blobs,
            ..
        } = local_payload.result;

        let (ExecutionPayload::Gloas(payload), Some(ExecutionRequests::Gloas(execution_requests))) =
            (execution_payload, execution_requests)
        else {
            warn_with_peers!("unexpected non-Gloas payload format in Gloas envelope data");
            return None;
        };

        let blobs = blobs.unwrap_or_default();
        let kzg_proofs = proofs.unwrap_or_else(KzgProofs::empty_fulu);

        let envelope = ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            beacon_block_root,
            parent_beacon_block_root,
        };

        Some((envelope, blobs, kzg_proofs))
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
        }
    }
}

type ExecutionPayloadEnvelopeContents<P> = (
    ExecutionPayloadEnvelope<P>,
    ContiguousList<Blob<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>,
    KzgProofs<P>,
);

struct ProducerContext<P: Preset, W: Wait> {
    chain_config: Arc<ChainConfig>,
    pubkey_cache: Arc<PubkeyCache>,
    proposer_configs: Arc<ProposerConfigs>,
    builder_api: Option<Arc<BuilderApi>>,
    payload_builder_api: Arc<PayloadBuilderApi>,
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    execution_engine: Arc<Eth1ExecutionEngine<P>>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    bls_to_execution_change_pool: Arc<BlsToExecutionChangePool>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
    prepared_proposers: Mutex<HashMap<ValidatorIndex, ExecutionAddress>>,
    proposer_slashings: Mutex<Vec<ProposerSlashing>>,
    attester_slashings: Mutex<Vec<AttesterSlashing<P>>>,
    voluntary_exits: Mutex<Vec<SignedVoluntaryExit>>,
    payload_cache: PayloadCache<P>,
    payload_id_cache: Mutex<SizedCache<(H256, Slot), PayloadId>>,
    // Cached payload root by `BlockBuildContext.head_block_root` for `payload_cache` retrieval
    // used to construct execution payload envelope
    cached_payload_roots: Mutex<SizedCache<H256, H256>>,
    // Parent (head) block root by self-built `beacon_block_root`, used to locate the payload root
    // in `cached_payload_roots` when rebuilding envelope contents for the envelope endpoints.
    self_built_block_parents: Mutex<SizedCache<H256, H256>>,
    metrics: Option<Arc<Metrics>>,
    fake_execution_payloads: bool,
}

#[derive(Clone, Copy, Default)]
pub struct BlockBuildOptions {
    pub graffiti: Option<H256>,
    pub disable_blockprint_graffiti: bool,
    pub skip_randao_verification: bool,
    pub builder_boost_factor: Uint256,
    pub min_bid: Gwei,
}

#[derive(Clone, Copy, Debug)]
pub struct BidWeighting {
    pub max_execution_payment: Gwei,
    pub min_bid: Gwei,
    pub builder_boost_factor: Uint256,
}

impl From<&BuilderEntry> for BidWeighting {
    fn from(entry: &BuilderEntry) -> Self {
        Self {
            max_execution_payment: entry.max_execution_payment,
            min_bid: entry.min_bid,
            builder_boost_factor: Uint256::from_u64(entry.builder_boost_factor),
        }
    }
}

pub struct BuilderApiBid<P: Preset> {
    pub url: BuilderUrl,
    pub bid: SignedExecutionPayloadBid<P>,
    pub weighting: BidWeighting,
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
        builder_api_bids_handle: Option<BuilderApiBidsJoinHandle<P>>,
    ) -> Result<
        Option<(
            WithBlobsAndMev<BeaconBlock<P>, P>,
            Option<BlockRewards>,
            Option<BuilderUrl>,
        )>,
    > {
        let _block_timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.build_beacon_block_times.start_timer());

        let block_without_state_root =
            wait_for_result(self.spawn_job(|build_context| async move {
                build_context
                    .build_beacon_block_without_state_root(randao_reveal)
                    .await
            }))
            .await?;

        let produce_beacon_block_join_handle = self.spawn_job(|build_context| async move {
            build_context
                .produce_beacon_block(
                    block_without_state_root,
                    local_execution_payload_handle,
                    builder_api_bids_handle,
                )
                .await
        });

        wait_for_result(produce_beacon_block_join_handle).await
    }

    fn client_versions(&self) -> impl Iterator<Item = Arc<ClientVersions>> {
        self.producer_context.execution_engine.client_versions()
    }

    pub async fn build_blinded_beacon_block(
        &self,
        randao_reveal: SignatureBytes,
        execution_payload_header_handle: Option<ExecutionPayloadHeaderJoinHandle<P>>,
        local_execution_payload_handle: Option<LocalExecutionPayloadJoinHandle<P>>,
        builder_api_bids_handle: Option<BuilderApiBidsJoinHandle<P>>,
    ) -> Result<
        Option<(
            WithBlobsAndMev<ValidatorBlindedBlock<P>, P>,
            Option<BlockRewards>,
            Option<BuilderUrl>,
        )>,
    > {
        let _block_timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.build_beacon_block_times.start_timer());

        let block_without_state_root =
            wait_for_result(self.spawn_job(|build_context| async move {
                build_context
                    .build_beacon_block_without_state_root(randao_reveal)
                    .await
            }))
            .await?;

        info_with_peers!("block producer built beacon block without state root");

        let block = block_without_state_root.clone();

        let produce_beacon_block_join_handle = self.spawn_job(|build_context| async move {
            info_with_peers!("block producer starting to build local option");

            build_context
                .produce_beacon_block(
                    block,
                    local_execution_payload_handle,
                    builder_api_bids_handle,
                )
                .await
        });

        let client_versions = self
            .client_versions()
            .next()
            .map(|version| version.clone_arc());

        let produce_blinded_block_join_handle = self.spawn_job(|build_context| async move {
            info_with_peers!("block producer starting to build blinded option");

            build_context
                .produce_blinded_block(
                    block_without_state_root,
                    execution_payload_header_handle,
                    client_versions,
                )
                .await
        });

        let beacon_block_opt = wait_for_result(produce_beacon_block_join_handle).await?;

        info_with_peers!("block producer finished building local option");

        let blinded_block_opt = wait_for_result(produce_blinded_block_join_handle).await?;

        info_with_peers!("block producer finished building blinded option");

        match (beacon_block_opt, blinded_block_opt) {
            (
                Some((beacon_block, beacon_block_rewards, builder_url)),
                Some((blinded_block, blinded_block_rewards, builder_mev)),
            ) => {
                if let Some(local_mev) = beacon_block.mev {
                    let builder_boost_factor = self.options.builder_boost_factor;

                    let boosted_builder_mev = builder_mev
                        .div(Uint256::from_u64(100))
                        .saturating_mul(builder_boost_factor);

                    if local_mev >= boosted_builder_mev {
                        info_with_peers!(
                            "using more profitable local payload: \
                             local MEV: {local_mev}, builder MEV: {builder_mev}, \
                             boosted builder MEV: {boosted_builder_mev}, builder_boost_factor: {builder_boost_factor}",
                        );

                        return Ok(Some((
                            beacon_block.map(ValidatorBlindedBlock::BeaconBlock),
                            beacon_block_rewards,
                            builder_url,
                        )));
                    }
                }

                let block = ValidatorBlindedBlock::BlindedBeaconBlock(blinded_block);

                Ok(Some((
                    WithBlobsAndMev::new(block, None, None, None, Some(builder_mev), None),
                    blinded_block_rewards,
                    None,
                )))
            }
            (Some((beacon_block, beacon_block_rewards, builder_url)), None) => Ok(Some((
                beacon_block.map(ValidatorBlindedBlock::BeaconBlock),
                beacon_block_rewards,
                builder_url,
            ))),
            _ => Ok(None),
        }
    }

    #[expect(clippy::too_many_lines)]
    async fn build_beacon_block_without_state_root(
        &self,
        randao_reveal: SignatureBytes,
    ) -> Result<BeaconBlock<P>> {
        info_with_peers!("block producer starting build beacon block without state root task");

        let eth1_data = self.beacon_state.eth1_data();
        let deposits = ContiguousList::default();

        // TODO(Grandine Team): Preparing slashings and voluntary exits independently may result
        //                      in an invalid block because a validator can only exit or be
        //                      slashed once. The code below can handle invalid blocks, but it may
        //                      prevent the validator from proposing.
        let proposer_slashings = self.prepare_proposer_slashings().await;

        info_with_peers!("block producer prepared proposer slashings");

        let voluntary_exits = self.prepare_voluntary_exits().await;

        info_with_peers!("block producer prepared voluntary exits");

        let attestations = if self.beacon_state.is_post_gloas() {
            Vec::new()
        } else {
            self.prepare_attestations().await?
        };

        info_with_peers!("block producer prepared attestations");

        let sync_aggregate = self.prepare_sync_aggregate().await?;

        info_with_peers!("block producer prepared sync aggregate");

        let bls_to_execution_changes = self.prepare_bls_to_execution_changes().await;

        info_with_peers!("block producer prepared bls to execution changes");

        let slot = self.beacon_state.slot();
        let proposer_index = self.proposer_index;
        let parent_root = self.head_block_root;
        let graffiti = self.options.graffiti.unwrap_or_default();

        // This is a placeholder that is overwritten later using `with_state_root`.
        // We define this explicitly instead of using struct update syntax to ensure
        // we fill all fields when constructing a block.
        let state_root = H256::zero();
        let phase = self.beacon_state.phase();

        let result = match phase {
            Phase::Phase0 => BeaconBlock::from(Hc::new(Phase0BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: Phase0BeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings: self.prepare_attester_slashings().await,
                    attestations: Self::phase0_attestations(&attestations)?,
                    deposits,
                    voluntary_exits,
                },
            })),
            Phase::Altair => BeaconBlock::from(Hc::new(AltairBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: AltairBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings: self.prepare_attester_slashings().await,
                    attestations: Self::phase0_attestations(&attestations)?,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                },
            })),
            Phase::Bellatrix => BeaconBlock::from(Hc::new(BellatrixBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: BellatrixBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings: self.prepare_attester_slashings().await,
                    attestations: Self::phase0_attestations(&attestations)?,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: BellatrixExecutionPayload::default(),
                },
            })),
            Phase::Capella => BeaconBlock::from(Hc::new(CapellaBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: CapellaBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings: self.prepare_attester_slashings().await,
                    attestations: Self::phase0_attestations(&attestations)?,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: CapellaExecutionPayload::default(),
                    bls_to_execution_changes,
                },
            })),
            Phase::Deneb => BeaconBlock::from(Hc::new(DenebBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: DenebBeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings,
                    attester_slashings: self.prepare_attester_slashings().await,
                    attestations: Self::phase0_attestations(&attestations)?,
                    deposits,
                    voluntary_exits,
                    sync_aggregate,
                    execution_payload: DenebExecutionPayload::default(),
                    bls_to_execution_changes,
                    blob_kzg_commitments: ContiguousList::default(),
                },
            })),
            Phase::Electra | Phase::Fulu | Phase::Gloas => {
                // Store results in a vec to preserve insertion order and thus the results of the packing algorithm
                let mut results: Vec<(
                    AttestationData,
                    HashSet<CommitteeIndex>,
                    Vec<ElectraAttestation<P>>,
                )> = Vec::new();

                for (electra_attestation, committee_index) in
                    attestations.into_iter().filter_map(|attestation| {
                        let committee_index = attestation.committee_index;

                        match operation_pools::convert_to_electra_attestation(attestation) {
                            Ok(electra_attestation) => Some((electra_attestation, committee_index)),
                            Err(error) => {
                                warn_with_peers!(
                                    "unable to convert to electra attestation: {error:?}"
                                );
                                None
                            }
                        }
                    })
                {
                    if let Some((_, indices, attestations)) = results
                        .iter_mut()
                        .find(|(data, _, _)| *data == electra_attestation.data)
                    {
                        if indices.insert(committee_index) {
                            attestations.push(electra_attestation);
                        }
                    } else {
                        results.push((
                            electra_attestation.data,
                            HashSet::from([committee_index]),
                            vec![electra_attestation],
                        ))
                    }
                }

                info_with_peers!("block producer converted attestations");

                let attestations = results
                    .into_iter()
                    .filter_map(|(_, _, attestations)| {
                        match operation_pools::compute_on_chain_aggregate(attestations.into_iter())
                        {
                            Ok(electra_aggregate) => Some(electra_aggregate),
                            Err(error) => {
                                warn_with_peers!("unable to compute on chain aggregate: {error:?}");
                                None
                            }
                        }
                    })
                    .take(P::MaxAttestationsElectra::USIZE);

                info_with_peers!("block producer computed on chain aggregates");

                let attestations = ContiguousList::try_from_iter(attestations)?;

                match phase {
                    Phase::Electra => BeaconBlock::from(Hc::new(ElectraBeaconBlock {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root,
                        body: ElectraBeaconBlockBody {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings: self.prepare_attester_slashings_electra().await,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: DenebExecutionPayload::default(),
                            bls_to_execution_changes,
                            blob_kzg_commitments: ContiguousList::default(),
                            execution_requests: ElectraExecutionRequests::default(),
                        },
                    })),
                    Phase::Fulu => BeaconBlock::from(Hc::new(FuluBeaconBlock {
                        slot,
                        proposer_index,
                        parent_root,
                        state_root,
                        body: FuluBeaconBlockBody {
                            randao_reveal,
                            eth1_data,
                            graffiti,
                            proposer_slashings,
                            attester_slashings: self.prepare_attester_slashings_electra().await,
                            attestations,
                            deposits,
                            voluntary_exits,
                            sync_aggregate,
                            execution_payload: DenebExecutionPayload::default(),
                            bls_to_execution_changes,
                            blob_kzg_commitments: ContiguousList::default(),
                            execution_requests: ElectraExecutionRequests::default(),
                        },
                    })),
                    Phase::Gloas => {
                        let snapshot = self.producer_context.controller.snapshot();
                        let parent_block = self.producer_context.controller.head_block();

                        // TODO(gloas): payload attestations are valid only for one slot after block.
                        // spec says: "The slot of the parent block is exactly one slot before the proposing slot."
                        let payload_attestations = if parent_block.value().to_header().message.slot
                            == misc::previous_slot(slot)
                        {
                            self.prepare_payload_attestations().await?.into()
                        } else {
                            ProgressiveList::default()
                        };

                        info_with_peers!("block producer prepared payload attestations");

                        let parent_execution_requests = if snapshot.should_build_on_full(slot) {
                            // TODO(gloas): the block root needs to be checked if it is gloas or not.
                            // the current behavior erroneously returns empty execution requests
                            // when payload envelope is not found, though block may be from gloas
                            // phase and envelope is missing (so it should error out).
                            snapshot
                                .cached_execution_payload_envelope_by_root(parent_root)
                                .ok_or_else(|| anyhow!("no cached payload envelope"))
                                .map(|payload| payload.message.execution_requests.clone())
                                .unwrap_or_default()
                        } else {
                            GloasExecutionRequests::default()
                        };

                        info_with_peers!("block producer prepared parent execution requests");

                        BeaconBlock::from(Hc::new(GloasBeaconBlock {
                            slot,
                            proposer_index,
                            parent_root,
                            state_root,
                            body: GloasBeaconBlockBody {
                                randao_reveal,
                                eth1_data,
                                graffiti,
                                proposer_slashings: proposer_slashings.into(),
                                attester_slashings: self.prepare_attester_slashings_gloas().await,
                                attestations: attestations.map(Into::into).into(),
                                deposits: deposits.into(),
                                voluntary_exits: voluntary_exits.into(),
                                sync_aggregate,
                                bls_to_execution_changes: bls_to_execution_changes.into(),
                                signed_execution_payload_bid: SignedExecutionPayloadBid::default(),
                                payload_attestations,
                                parent_execution_requests,
                            },
                        }))
                    }
                    _ => {
                        return Err(AnyhowError::msg(
                            "post-electra building block with incorrect phase",
                        ));
                    }
                }
            }
        }
        .pipe(Ok);

        info_with_peers!("block producer finishing build beacon block without state root task");

        result
    }

    fn blinded_block_from_beacon_block(
        &self,
        beacon_block: BeaconBlock<P>,
        payload_header: ExecutionPayloadHeader<P>,
        blob_kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
        execution_requests: Option<ElectraExecutionRequests<P>>,
    ) -> Option<(BlindedBeaconBlock<P>, Option<BlockRewards>)> {
        let without_state_root = match beacon_block.into_blinded(
            payload_header,
            blob_kzg_commitments,
            execution_requests,
        ) {
            Ok(block) => block,
            Err(error) => {
                warn_with_peers!("constructed invalid blinded beacon block (error: {error:?})");
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
                warn_with_peers!(
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
                warn_with_peers!(
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

    #[expect(clippy::too_many_lines)]
    async fn produce_beacon_block(
        &self,
        block_without_state_root: BeaconBlock<P>,
        local_execution_payload_handle: Option<LocalExecutionPayloadJoinHandle<P>>,
        builder_api_bids_handle: Option<BuilderApiBidsJoinHandle<P>>,
    ) -> Result<
        Option<(
            WithBlobsAndMev<BeaconBlock<P>, P>,
            Option<BlockRewards>,
            Option<BuilderUrl>,
        )>,
    > {
        let mut payload_with_data = None;
        if let Some(handle) = local_execution_payload_handle {
            payload_with_data = handle
                .await?
                .map(|value| value.map(|value| value.map(Some)))
        }

        let builder_api_bids = match builder_api_bids_handle {
            Some(handle) => handle.await.unwrap_or_else(|error| {
                warn_with_peers!("builder API bid requests failed: {error:?}");
                vec![]
            }),
            None => vec![],
        };

        let WithClientVersions {
            client_versions,
            result:
                WithBlobsAndMev {
                    value: execution_payload,
                    commitments,
                    proofs,
                    blobs,
                    mev: mut block_mev,
                    execution_requests,
                },
        } = match payload_with_data {
            Some(payload_with_mev_and_versions) => payload_with_mev_and_versions,
            None => {
                // In ePBS (post-Gloas) the payload is decoupled from the beacon block, so a
                // missing local payload is not fatal here: it is handled below by skipping
                // self-build (and the proposal) rather than erroring. Before Gloas a post-merge
                // block must carry a payload, so its absence is an error.
                let payload_required = !self.beacon_state.is_post_gloas()
                    && (self.beacon_state.post_capella().is_some()
                        || post_merge_state(&self.beacon_state).is_some());

                if payload_required {
                    return Err(AnyhowError::msg("no execution payload to include in block"));
                }

                WithClientVersions::none(WithBlobsAndMev::with_default(None))
            }
        };

        let has_local_payload = execution_payload.is_some();
        let mut builder_url = None;

        let mut without_state_root_with_payload = if let Some(state) =
            self.beacon_state.post_gloas()
        {
            let builder_bid = self.select_best_builder_bid(
                state,
                &block_without_state_root,
                &builder_api_bids,
                block_mev,
                has_local_payload,
            );

            let signed_payload_bid = if let Some((bid, url)) = builder_bid {
                // Set block_mev value to the in-protocol builder bid value
                block_mev = Some(Uint256::from_u64(bid.message.value).saturating_mul(WEI_IN_GWEI));
                builder_url = url;

                Some(bid)
            } else {
                // No builder bid selected — self-build using the local payload that was
                // already prepared via engine_forkchoiceUpdated
                self.cache_and_build_self_payload_bid(state, execution_payload, commitments)
                    .await?
            };

            let Some(signed_payload_bid) = signed_payload_bid else {
                return Ok(None);
            };

            block_without_state_root.with_signed_execution_payload_bid(Some(signed_payload_bid))
        } else {
            block_without_state_root
                .with_execution_payload(execution_payload)?
                .with_blob_kzg_commitments(commitments)
                .with_execution_requests(execution_requests)
        };

        if let (BeaconState::Gloas(state), BeaconBlock::Gloas(block)) =
            (&*self.beacon_state, &mut without_state_root_with_payload)
        {
            let started_at = std::time::Instant::now();
            let config = &self.producer_context.chain_config;
            let scoring_state = prepare_gloas_scoring_state(
                config,
                &self.producer_context.pubkey_cache,
                state,
                block,
                |root| {
                    self.producer_context
                        .controller
                        .snapshot()
                        .cached_execution_payload_envelope_by_root(root)
                        .map(|envelope| envelope.message.execution_requests.clone())
                },
            )?;
            // Attestation packing is optional; parent processing above and final block
            // validation below must still succeed.
            block.body.attestations = match self
                .producer_context
                .attestation_agg_pool
                .gloas_proposable_attestations(Arc::new(BeaconState::Gloas(scoring_state)))
                .await
                .and_then(|attestations| attestations.try_into().map_err(AnyhowError::from))
            {
                Ok(attestations) => attestations,
                Err(error) => {
                    warn_with_peers!(
                        "unable to prepare Gloas attestations for slot {} with parent {:?}; \
                         proposing without attestations: {error:?}",
                        block.slot,
                        block.parent_root,
                    );
                    ProgressiveList::default()
                }
            };
            info_with_peers!(
                "Gloas proposal parent processing and packing elapsed {} us",
                started_at.elapsed().as_micros()
            );
        }

        if !self.options.disable_blockprint_graffiti {
            let graffiti = build_graffiti(self.options.graffiti, client_versions);
            without_state_root_with_payload.set_graffiti(graffiti);
        }

        self.process_beacon_block(without_state_root_with_payload)
            .map(|(beacon_block, block_rewards)| {
                (
                    WithBlobsAndMev::new(
                        beacon_block,
                        // Commitments are moved to block.
                        None,
                        proofs,
                        blobs,
                        block_mev,
                        // Execution requests are moved to block.
                        None,
                    ),
                    block_rewards,
                    builder_url,
                )
            })
            .pipe(Ok)
    }

    async fn produce_blinded_block(
        &self,
        mut block_without_state_root: BeaconBlock<P>,
        execution_payload_header_handle: Option<ExecutionPayloadHeaderJoinHandle<P>>,
        client_versions: Option<Arc<ClientVersions>>,
    ) -> Result<Option<(BlindedBeaconBlock<P>, Option<BlockRewards>, Uint256)>> {
        let Some(header_handle) = execution_payload_header_handle else {
            return Ok(None);
        };

        match header_handle.await? {
            Ok(Some(response)) => {
                let blob_kzg_commitments = response.blob_kzg_commitments().cloned();
                let execution_requests = response.execution_requests().cloned();
                let builder_mev = response.mev();

                if !self.options.disable_blockprint_graffiti {
                    let graffiti = build_graffiti(self.options.graffiti, client_versions);

                    block_without_state_root.set_graffiti(graffiti);
                }

                self.blinded_block_from_beacon_block(
                    block_without_state_root,
                    response.execution_payload_header(),
                    blob_kzg_commitments,
                    execution_requests,
                )
                .map(|(blinded_block, block_rewards)| (blinded_block, block_rewards, builder_mev))
                .pipe(Ok)
            }
            Ok(None) => Ok(None),
            Err(error) => {
                warn_with_peers!("failed to get execution payload header: {error}");
                Ok(None)
            }
        }
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
                &self.producer_context.pubkey_cache,
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
    ) -> ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_attester_slashings_times.start_timer());

        let mut slashings = self.producer_context.attester_slashings.lock().await;

        let split_index = itertools::partition(slashings.iter_mut(), |slashing| {
            match slashing {
                AttesterSlashing::Phase0(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Electra(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Gloas(attester_slashing) => unphased::validate_attester_slashing(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &self.beacon_state,
                    attester_slashing,
                ),
            }
            .is_ok()
        });

        let slashings = ContiguousList::try_from_iter(
            slashings
                .drain(0..split_index.min(P::MaxAttesterSlashings::USIZE))
                .filter_map(AttesterSlashing::pre_electra),
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

    async fn prepare_attester_slashings_electra(
        &self,
    ) -> ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_attester_slashings_times.start_timer());

        let mut slashings = self.producer_context.attester_slashings.lock().await;

        let split_index = itertools::partition(slashings.iter_mut(), |slashing| {
            match slashing {
                AttesterSlashing::Phase0(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Electra(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Gloas(attester_slashing) => unphased::validate_attester_slashing(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &self.beacon_state,
                    attester_slashing,
                ),
            }
            .is_ok()
        });

        let slashings = ContiguousList::try_from_iter(
            slashings
                .drain(0..split_index.min(P::MaxAttesterSlashingsElectra::USIZE))
                .filter_map(AttesterSlashing::post_electra),
        )
        .expect(
            "the call to Vec::drain above limits the \
             iterator to P::MaxAttesterSlashingsElectra::USIZE elements",
        );

        log_with_feature(format_args!(
            "attester slashings for proposal: {slashings:?}"
        ));

        slashings
    }

    async fn prepare_attester_slashings_gloas(&self) -> ProgressiveList<GloasAttesterSlashing<P>> {
        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.prepare_attester_slashings_times.start_timer());

        let mut slashings = self.producer_context.attester_slashings.lock().await;

        let split_index = itertools::partition(slashings.iter_mut(), |slashing| {
            match slashing {
                AttesterSlashing::Phase0(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Electra(attester_slashing) => {
                    unphased::validate_attester_slashing(
                        &self.producer_context.chain_config,
                        &self.producer_context.pubkey_cache,
                        &self.beacon_state,
                        attester_slashing,
                    )
                }
                AttesterSlashing::Gloas(attester_slashing) => unphased::validate_attester_slashing(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &self.beacon_state,
                    attester_slashing,
                ),
            }
            .is_ok()
        });

        let slashings = ProgressiveList::try_from_iter(
            slashings
                .drain(0..split_index.min(P::MaxAttesterSlashingsElectra::USIZE))
                .filter_map(AttesterSlashing::post_gloas),
        )
        .expect(
            "the call to Vec::drain above limits the \
             iterator to P::MaxAttesterSlashingsElectra::USIZE elements",
        );

        log_with_feature(format_args!(
            "attester slashings for proposal: {slashings:?}"
        ));

        slashings
    }

    async fn prepare_attestations(&self) -> Result<Vec<PoolAttestation<P>>> {
        self.producer_context
            .attestation_agg_pool
            .best_proposable_attestations(self.beacon_state.clone_arc())
            .await
    }

    fn phase0_attestations(
        attestations: &[PoolAttestation<P>],
    ) -> Result<ContiguousList<Attestation<P>, P::MaxAttestations>> {
        ContiguousList::try_from_iter(
            attestations
                .iter()
                .cloned()
                .map(PoolAttestation::into_phase0_attestation),
        )
        .map_err(Into::into)
    }

    // Constructed `payload_attestations` in current block is to aggregate all payload attestations for the previous block payload.
    // See <https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/specs/gloas/validator.md#constructing-payload_attestations>
    async fn prepare_payload_attestations(
        &self,
    ) -> Result<ContiguousList<PayloadAttestation<P>, P::MaxPayloadAttestation>> {
        let message_slot = misc::previous_slot(self.beacon_state.slot());

        self.producer_context
            .payload_attestation_agg_pool
            .aggregate_payload_attestations(message_slot, self.head_block_root)
            .await
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
            match self.beacon_state.as_ref() {
                BeaconState::Phase0(_)
                | BeaconState::Altair(_)
                | BeaconState::Bellatrix(_)
                | BeaconState::Capella(_)
                | BeaconState::Deneb(_) => unphased::validate_voluntary_exit(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    &self.beacon_state,
                    *voluntary_exit,
                ),
                BeaconState::Electra(state) => electra::validate_voluntary_exit(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    state,
                    *voluntary_exit,
                ),
                BeaconState::Fulu(state) => electra::validate_voluntary_exit(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    state,
                    *voluntary_exit,
                ),
                BeaconState::Gloas(state) => electra::validate_voluntary_exit(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
                    state,
                    *voluntary_exit,
                ),
            }
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
        let message_slot = misc::previous_slot(self.beacon_state.slot());
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
                        .saturating_mul(usize::try_from(subcommittee_index)?)
                        .saturating_add(index);

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
                warn_with_peers!(
                    "unable to retrieve BLS to execution changes from operation pool: {error:?}"
                );
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|bls_to_execution_change| {
                capella::validate_bls_to_execution_change(
                    &self.producer_context.chain_config,
                    &self.producer_context.pubkey_cache,
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

    async fn cache_and_build_self_payload_bid(
        &self,
        state: &(impl PostGloasBeaconState<P> + ?Sized),
        execution_payload: Option<ExecutionPayload<P>>,
        commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Result<Option<SignedExecutionPayloadBid<P>>> {
        // Cache payload root so compute_execution_payload_envelope can retrieve the full payload
        // after the block is signed and published (external builders publish their own envelope)
        if let Some(ref payload) = execution_payload {
            self.producer_context
                .cached_payload_roots
                .lock()
                .await
                .cache_set(self.head_block_root, payload.hash_tree_root());
        }

        self.construct_self_payload_bid(state, execution_payload, commitments)
            .await
    }

    async fn construct_self_payload_bid(
        &self,
        state: &(impl PostGloasBeaconState<P> + ?Sized),
        execution_payload_opt: Option<ExecutionPayload<P>>,
        blob_kzg_commitments_opt: Option<
            ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
        >,
    ) -> Result<Option<SignedExecutionPayloadBid<P>>> {
        let Some(payload) = execution_payload_opt else {
            return Ok(None);
        };

        let fee_recipient = self.fee_recipient().await?;

        let execution_requests_root = self
            .cached_execution_requests_root()
            .await
            .ok_or_else(|| anyhow!("no gloas envelope data"))?;

        let parent_root = state.latest_block_header().hash_tree_root();

        let payload_bid = ExecutionPayloadBid {
            parent_block_hash: payload.parent_hash(),
            parent_block_root: parent_root,
            block_hash: payload.block_hash(),
            prev_randao: payload.prev_randao(),
            fee_recipient,
            gas_limit: payload.gas_limit(),
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: state.slot(),
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: blob_kzg_commitments_opt.unwrap_or_default().into(),
            execution_requests_root,
            phantom: PhantomData,
        };

        Ok(Some(SignedExecutionPayloadBid {
            message: payload_bid,
            signature: SignatureBytes::empty(),
        }))
    }

    #[instrument(skip_all, level = "debug")]
    #[expect(clippy::too_many_lines)]
    pub async fn prepare_execution_payload_attributes(
        &self,
    ) -> Result<Option<PayloadAttributes<P>>> {
        let chain_config = &self.producer_context.chain_config;
        let state = self.beacon_state.as_ref();

        if state.post_bellatrix().is_none() {
            return Ok(None);
        }

        let epoch = accessors::get_current_epoch(state);
        let timestamp = misc::compute_timestamp_at_slot(chain_config, state, state.slot())?;
        let suggested_fee_recipient = self.fee_recipient().await?;

        let prev_randao = accessors::get_randao_mix(state, epoch);

        let payload_attributes = match state {
            BeaconState::Phase0(_) | BeaconState::Altair(_) => return Ok(None),
            BeaconState::Bellatrix(_) => PayloadAttributes::Bellatrix(PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }),
            BeaconState::Capella(state) => {
                let withdrawals = capella::get_expected_withdrawals(state)?
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                PayloadAttributes::Capella(PayloadAttributesV2 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                })
            }
            BeaconState::Deneb(state) => {
                let withdrawals = capella::get_expected_withdrawals(state)?
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                let parent_beacon_block_root =
                    accessors::get_block_root_at_slot(state, state.slot().saturating_sub(1))?;

                PayloadAttributes::Deneb(PayloadAttributesV3 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                })
            }
            BeaconState::Electra(state) => {
                let (withdrawals, _) = electra::get_expected_withdrawals(state)?;

                let withdrawals = withdrawals
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                let parent_beacon_block_root =
                    accessors::get_block_root_at_slot(state, state.slot().saturating_sub(1))?;

                PayloadAttributes::Electra(PayloadAttributesV3 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                })
            }
            BeaconState::Fulu(state) => {
                let (withdrawals, _) = electra::get_expected_withdrawals(state)?;

                let withdrawals = withdrawals
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                let parent_beacon_block_root =
                    accessors::get_block_root_at_slot(state, state.slot().saturating_sub(1))?;

                PayloadAttributes::Fulu(PayloadAttributesV3 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                })
            }
            BeaconState::Gloas(state) => {
                let head_root = self.head_block_root;
                let target_gas_limit = self.gas_limit()?;
                let snapshot = self.producer_context.controller.snapshot();

                let withdrawals = if snapshot.should_build_on_full(state.slot())
                    && let Some(envelope) =
                        snapshot.cached_execution_payload_envelope_by_root(head_root)
                {
                    debug_with_peers!(
                        "applying parent execution payload from envelope for payload attributes \
                         preparation (head slot: {}, head root: {head_root:?})",
                        state.slot(),
                    );

                    let mut state_copy = state.clone();

                    gloas::apply_parent_execution_payload(
                        chain_config,
                        &self.producer_context.pubkey_cache,
                        &mut state_copy,
                        &envelope.message.execution_requests,
                    )?;

                    gloas::get_expected_withdrawals(&state_copy)?.0
                } else if state.latest_execution_payload_bid().block_hash
                    == state.latest_block_hash()
                {
                    debug_with_peers!(
                        "fork boundary case for payload attributes preparation \
                            (head slot: {}, head root: {head_root:?})",
                        state.slot(),
                    );

                    gloas::get_expected_withdrawals(state)?.0
                } else {
                    debug_with_peers!(
                        "using expected withdrawals from the beacon state for payload attributes preparation, \
                         falling back to direct state access (head slot: {}, head root: {head_root:?})",
                        state.slot(),
                    );

                    state
                        .payload_expected_withdrawals()
                        .into_iter()
                        .copied()
                        .collect()
                };

                let withdrawals = withdrawals
                    .into_iter()
                    .map_into()
                    .pipe(ContiguousList::try_from_iter)?;

                PayloadAttributes::Gloas(PayloadAttributesV4 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root: state.latest_block_header().hash_tree_root(),
                    slot_number: state.slot(),
                    target_gas_limit,
                })
            }
        };

        Ok(Some(payload_attributes))
    }

    /// Execution block that the payload prepared for this context will extend.
    ///
    /// Post-Gloas this must not be taken from `latest_execution_payload_header`: that accessor is
    /// aliased to `latest_execution_payload_bid`, whose `block_hash` is only the parent proposer's
    /// promise and may never be revealed.
    #[must_use]
    pub fn execution_payload_parent(
        &self,
    ) -> Option<(Option<ExecutionBlockNumber>, ExecutionBlockHash)> {
        let state = self.beacon_state.as_ref();

        if let Some(state) = state.post_gloas() {
            return Some((None, self.gloas_payload_parent_hash(state)));
        }

        let payload = state.post_bellatrix()?.latest_execution_payload_header();

        Some((payload.block_number(), payload.block_hash()))
    }

    fn gloas_payload_parent_hash(
        &self,
        state: &(impl PostGloasBeaconState<P> + ?Sized),
    ) -> ExecutionBlockHash {
        let parent_bid = state.latest_execution_payload_bid();
        let parent_slot = state.latest_block_header().slot;
        let snapshot = self.producer_context.controller.snapshot();

        if snapshot.should_build_on_full(state.slot())
            || self
                .producer_context
                .chain_config
                .phase_at_slot::<P>(parent_slot)
                < Phase::Gloas
        {
            parent_bid.block_hash
        } else {
            parent_bid.parent_block_hash
        }
    }

    #[instrument(skip_all, level = "debug")]
    pub async fn prepare_execution_payload_for_slot(
        &self,
        slot: Slot,
        safe_execution_payload_hash: ExecutionBlockHash,
        finalized_execution_payload_hash: ExecutionBlockHash,
        payload_attributes: PayloadAttributes<P>,
    ) {
        let head_root = self.head_block_root;

        let payload_id = self
            .prepare_execution_payload(
                safe_execution_payload_hash,
                finalized_execution_payload_hash,
                payload_attributes,
            )
            .await;

        match payload_id {
            Ok(payload_id_option) => {
                match payload_id_option {
                    Some(payload_id) => {
                        info_with_peers!(
                            "started work on execution payload with id {payload_id:?} \
                             for head {head_root:?} at slot {slot}",
                        );

                        self.producer_context
                            .payload_id_cache
                            .lock()
                            .await
                            .cache_set((head_root, slot), payload_id);
                    }
                    // If we have no block at 4th-second mark, we preprocess new state without the block.
                    // In such case, after the state is preprocessed, we attempt to prepare the execution payload for the next slot with
                    // outdated EL head block hash, which EL client might discard as too old if it has seen newer blocks.
                    None => warn_with_peers!(
                        "could not prepare execution payload: payload_id is None; \
                         ensure that multiple consensus clients are not driving the same execution client",
                    ),
                }
            }
            Err(error) => warn_with_peers!("error while preparing execution payload: {error:?}"),
        }
    }

    #[instrument(skip_all, level = "debug")]
    async fn prepare_execution_payload(
        &self,
        safe_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        payload_attributes: PayloadAttributes<P>,
    ) -> Result<Option<PayloadId>> {
        let chain_config = &self.producer_context.chain_config;
        let state = self.beacon_state.as_ref();
        let epoch = accessors::get_current_epoch(state);
        let timestamp = misc::compute_timestamp_at_slot(chain_config, state, state.slot())?;

        let (sender, receiver) = futures::channel::oneshot::channel();

        // > [Modified in Capella] Removed `is_merge_transition_complete` check in Capella
        //
        // See <https://github.com/ethereum/consensus-specs/pull/3350>.
        let parent_hash = if let Some(state) = state.post_gloas() {
            self.gloas_payload_parent_hash(state)
        } else if let Some(state) = state.post_capella() {
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
        if !self.beacon_state.is_post_gloas()
            && let Some(state) = self.beacon_state.post_bellatrix()
            && let Some(builder_api) = self.producer_context.builder_api.clone()
        {
            let slot = self.beacon_state.slot();

            if let Err(error) = builder_api.can_use_builder_api::<P>(
                slot,
                self.producer_context
                    .controller
                    .snapshot()
                    .nonempty_slots(self.head_block_root),
            ) {
                warn_with_peers!("cannot use Builder API for execution payload header: {error}");
                return None;
            }

            let chain_config = self.producer_context.chain_config.clone_arc();
            let parent_hash = state.latest_execution_payload_header().block_hash();

            let handle = tokio::spawn(async move {
                builder_api
                    .get_execution_payload_header::<P>(&chain_config, slot, parent_hash, public_key)
                    .await
            });

            return Some(handle);
        }

        None
    }

    pub fn get_builder_api_bids(
        &self,
        builders: ContiguousList<BuilderEntry, MaxBuilderEntries>,
    ) -> Option<BuilderApiBidsJoinHandle<P>> {
        if builders.is_empty() {
            return None;
        }

        let state = self.beacon_state.post_gloas()?;
        let parent_block_hash =
            bid_parent_block_hash(&self.producer_context.controller.snapshot(), state);

        let proposer_pubkey = match accessors::public_key(state, self.proposer_index) {
            Ok(pubkey) => *pubkey,
            Err(error) => {
                warn_with_peers!("unable to request builder API bids: {error:?}");
                return None;
            }
        };

        let handle = tokio::spawn(request_builder_api_bids(
            self.producer_context.payload_builder_api.clone_arc(),
            self.beacon_state.clone_arc(),
            self.head_block_root,
            parent_block_hash,
            proposer_pubkey,
            builders,
        ));

        Some(handle)
    }

    /// Returns the most valuable bid that the node is willing to propose on top of the head block.
    ///
    /// [`None`] means the node should build the payload itself, either because there is no bid
    /// worth taking, the local payload is worth more, or the circuit breaker tripped.
    // TODO: allow to configure bid selection, e.g. builders preference over highest bid
    fn select_best_builder_bid(
        &self,
        state: &(impl PostGloasBeaconState<P> + ?Sized),
        block_without_state_root: &BeaconBlock<P>,
        builder_api_bids: &[BuilderApiBid<P>],
        local_mev: Option<Uint256>,
        local_payload_available: bool,
    ) -> Option<(SignedExecutionPayloadBid<P>, Option<BuilderUrl>)> {
        let snapshot = self.producer_context.controller.snapshot();

        if local_payload_available && snapshot.builder_circuit_breaker_tripped() {
            warn_with_peers!("builders are withholding payloads, building the payload locally");

            return None;
        }

        let parent_block_hash = bid_parent_block_hash(&snapshot, state);

        let BlockBuildOptions {
            builder_boost_factor,
            min_bid,
            ..
        } = self.options;

        // no cap on `max_execution_payment` for p2p bids
        let p2p_weighting = BidWeighting {
            max_execution_payment: Gwei::MAX,
            min_bid,
            builder_boost_factor,
        };

        let builder_api_bids = self.valid_builder_api_bids(
            &snapshot,
            block_without_state_root,
            builder_api_bids,
            parent_block_hash,
        );

        let candidates = snapshot
            .selectable_payload_bids(state, state.slot(), parent_block_hash, self.head_block_root)
            .map(|bid| (bid, p2p_weighting, None))
            .chain(builder_api_bids);

        let (bid, url) = select_weighted_bid(candidates, local_mev)?;

        Some((bid.clone(), url.cloned()))
    }

    fn valid_builder_api_bids<'bids>(
        &self,
        snapshot: &Snapshot<P>,
        block_without_state_root: &BeaconBlock<P>,
        builder_api_bids: &'bids [BuilderApiBid<P>],
        parent_block_hash: ExecutionBlockHash,
    ) -> Vec<(
        &'bids SignedExecutionPayloadBid<P>,
        BidWeighting,
        Option<&'bids BuilderUrl>,
    )> {
        if builder_api_bids.is_empty() {
            return vec![];
        }

        let slot = self.beacon_state.slot();

        let Some(proposer_preferences) =
            snapshot.proposer_preferences(self.head_block_root, slot, self.proposer_index)
        else {
            warn_with_peers!(
                "ignoring builder API bids: no proposer preferences accepted for slot {slot} \
                 (proposer_index: {})",
                self.proposer_index,
            );
            return vec![];
        };

        let ProposerPreferences {
            fee_recipient,
            target_gas_limit,
            ..
        } = proposer_preferences.message;

        let Some(parent_gas_limit) = self
            .producer_context
            .controller
            .unfinalized_chain_link_by_execution_block_hash(parent_block_hash)
            .and_then(|chain_link| chain_link.block.execution_gas_limit())
        else {
            warn_with_peers!(
                "ignoring builder API bids: parent execution payload not found in fork choice \
                 (parent_block_hash: {parent_block_hash:?})",
            );
            return vec![];
        };

        let bids = builder_api_bids
            .iter()
            .filter(|BuilderApiBid { bid, .. }| {
                let builds_on_parent = bid.message.parent_block_hash == parent_block_hash
                    && bid.message.parent_block_root == self.head_block_root;

                if !builds_on_parent {
                    warn_with_peers!(
                        "rejected builder API bid from builder {} building on another parent \
                         (parent_block_hash: {:?}, parent_block_root: {:?})",
                        bid.message.builder_index,
                        bid.message.parent_block_hash,
                        bid.message.parent_block_root,
                    );

                    return false;
                }

                matches_proposer_preferences(bid, fee_recipient, parent_gas_limit, target_gas_limit)
            })
            .map(
                |BuilderApiBid {
                     url,
                     bid,
                     weighting,
                 }| (bid, *weighting, Some(url)),
            )
            .collect_vec();

        if bids.is_empty() {
            return vec![];
        }

        let (BeaconState::Gloas(state), BeaconBlock::Gloas(block)) =
            (&*self.beacon_state, block_without_state_root)
        else {
            return vec![];
        };

        let chain_config = &self.producer_context.chain_config;
        let pubkey_cache = &self.producer_context.pubkey_cache;
        let mut state = state.clone();

        // advance state by processing parent payload envelope and withdrawals, so that bids can be
        // validated against the correct state
        if let Err(error) = prepare_state_for_execution_payload_bid(
            chain_config,
            pubkey_cache,
            &mut state,
            parent_block_hash,
            &block.body.parent_execution_requests,
        ) {
            warn_with_peers!("unable to validate builder API bids: {error:?}");
            return vec![];
        }

        bids.into_iter()
            .filter(|(bid, _, _)| {
                gloas::validate_execution_payload_bid(chain_config, pubkey_cache, &state, bid)
                    .inspect_err(|error| {
                        warn_with_peers!(
                            "rejected builder API bid from builder {}: {error:?}",
                            bid.message.builder_index,
                        );
                    })
                    .is_ok()
            })
            .collect()
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
    ) -> Result<Option<WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>>> {
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
            warn_with_peers!(
                "payload_id not found in payload_id_cache for {:?}",
                self.head_block_root
            );

            if let Some(payload_attributes) = self.prepare_execution_payload_attributes().await? {
                payload_id = self
                    .prepare_execution_payload(
                        snapshot.safe_execution_payload_hash(),
                        snapshot.finalized_execution_payload_hash(),
                        payload_attributes,
                    )
                    .await?
                    .map(PayloadIdEntry::Live)
            }
        }

        let Some(payload_id) = payload_id else {
            error_with_peers!(
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
                warn_with_peers!(
                    "unable to retrieve payload with payload_id {payload_id:?}: {error:?}"
                );

                match payload_id {
                    PayloadIdEntry::Cached(_) => {
                        let payload_id = if let Some(payload_attributes) =
                            self.prepare_execution_payload_attributes().await?
                        {
                            self.prepare_execution_payload(
                                snapshot.safe_execution_payload_hash(),
                                snapshot.finalized_execution_payload_hash(),
                                payload_attributes,
                            )
                            .await?
                        } else {
                            None
                        };

                        if let Some(payload_id) = payload_id {
                            info_with_peers!(
                                "successfully retrieved non-cached payload_id: {payload_id:?}"
                            );

                            self.producer_context
                                .execution_engine
                                .get_execution_payload(payload_id)
                                .await?
                        } else {
                            error_with_peers!(
                                "payload_id from execution layer was not received; This will lead to missed block"
                            );

                            return Ok(None);
                        }
                    }
                    PayloadIdEntry::Live(_) => return Err(error),
                }
            }
        };

        let payload_root = payload.result.value.hash_tree_root();

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
    ) -> Option<WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>> {
        if self.producer_context.fake_execution_payloads {
            let slot = self.beacon_state.slot();

            // Starting with Capella, all blocks must be post-Merge.
            // Construct a superficially valid execution payload for snapshot testing.
            // It will almost always be invalid in a real network, but so would a default payload.
            // Construct the payload with a fictitious `ExecutionBlockHash` derived from the slot.
            // Computing the real `ExecutionBlockHash` would make maintaining tests much harder.
            if self.beacon_state.phase() >= Phase::Capella {
                let execution_payload = factory::execution_payload(
                    &self.producer_context.chain_config,
                    &self.beacon_state,
                    slot,
                    ExecutionBlockHash::from_low_u64_be(slot),
                );

                match execution_payload {
                    Ok(payload) => {
                        return Some(WithClientVersions::none(WithBlobsAndMev::with_default(
                            payload,
                        )));
                    }
                    Err(error) => panic!("failed to produce fake payload: {error:?}"),
                };
            }
        }

        let _timer = self
            .producer_context
            .metrics
            .as_ref()
            .map(|metrics| metrics.local_execution_payload_times.start_timer());

        self.local_execution_payload_result()
            .await
            .map_err(|error| {
                warn_with_peers!("execution engine failed to produce payload: {error:?}")
            })
            .ok()
            .flatten()
    }

    /// The `payload_cache` key for the payload built against this context's head, used to locate the
    /// self-built envelope contents for the stateless GET and to record where the envelope endpoints
    /// can rebuild them.
    pub async fn cached_payload_root(&self) -> Option<H256> {
        self.producer_context
            .cached_payload_roots
            .lock()
            .await
            .cache_get(&self.head_block_root)
            .copied()
    }

    async fn cached_execution_requests_root(&self) -> Option<H256> {
        let payload_root = self.cached_payload_root().await?;

        Some(
            self.producer_context
                .payload_cache
                .lock()
                .await
                .cache_get(&payload_root)?
                .result
                .execution_requests
                .as_ref()?
                .hash_tree_root(),
        )
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

                Ok(self
                    .producer_context
                    .proposer_configs
                    .fee_recipient(*proposer_pubkey))
            })
    }

    fn gas_limit(&self) -> Result<Gas> {
        let proposer_pubkey = accessors::public_key(&self.beacon_state, self.proposer_index)?;
        let epoch = accessors::get_current_epoch(&self.beacon_state);

        let configured = self
            .producer_context
            .proposer_configs
            .gas_limit(*proposer_pubkey);

        Ok(self
            .producer_context
            .chain_config
            .gas_limit(configured, epoch))
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

// Both builder and self-build bids use the parent path encoded in the final bid.
// The state must belong to block.parent_root; discard the candidate block on error.
fn prepare_gloas_scoring_state<P: Preset>(
    config: &ChainConfig,
    pubkey_cache: &PubkeyCache,
    state: &Hc<GloasBeaconState<P>>,
    block: &mut GloasBeaconBlock<P>,
    parent_requests: impl FnOnce(H256) -> Option<GloasExecutionRequests<P>>,
) -> Result<Hc<GloasBeaconState<P>>> {
    let parent_bid = &state.latest_execution_payload_bid;
    block.body.parent_execution_requests = if block
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash
        == parent_bid.block_hash
        && config.phase_at_slot::<P>(parent_bid.slot) >= Phase::Gloas
    {
        parent_requests(block.parent_root)
            .ok_or_else(|| anyhow!("missing FULL parent payload envelope"))?
    } else {
        GloasExecutionRequests::default()
    };
    let mut scoring_state = state.clone();
    gloas::process_parent_execution_payload(
        config,
        pubkey_cache,
        &mut scoring_state,
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash,
        &block.body.parent_execution_requests,
    )?;
    Ok(scoring_state)
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

async fn request_builder_api_bids<P: Preset>(
    payload_builder_api: Arc<PayloadBuilderApi>,
    state: Arc<BeaconState<P>>,
    parent_root: H256,
    parent_hash: ExecutionBlockHash,
    proposer_pubkey: PublicKeyBytes,
    builders: ContiguousList<BuilderEntry, MaxBuilderEntries>,
) -> Vec<BuilderApiBid<P>> {
    let Some(state) = state.post_gloas() else {
        return vec![];
    };

    let payload_builder_api = &payload_builder_api;
    let slot = state.slot();
    let mut requested = HashSet::new();

    let responses = builders
        .iter()
        .filter(|&entry| {
            let BuilderEntry { url, auth, .. } = entry;

            if auth.message.slot != slot {
                warn_with_peers!(
                    "skipping builder entry for {url} authorized for slot {} instead of {slot}",
                    auth.message.slot,
                );

                return false;
            }

            if !requested.insert((url.as_str(), auth.message.data.as_bytes())) {
                warn_with_peers!("skipping duplicate builder entry for {url}");

                return false;
            }

            true
        })
        .map(|entry| async move {
            let response = payload_builder_api
                .get_execution_payload_bid::<P>(
                    &entry.url,
                    &entry.auth,
                    slot,
                    parent_hash,
                    parent_root,
                    proposer_pubkey,
                )
                .await;

            (entry, response)
        })
        .collect::<FuturesUnordered<_>>()
        .take_until(tokio::time::sleep(BUILDER_BID_REQUEST_TIMEOUT))
        .collect::<Vec<_>>()
        .await;

    let unanswered = requested.len().saturating_sub(responses.len());

    if unanswered > 0 {
        warn_with_peers!(
            "{unanswered} builders did not answer within {BUILDER_BID_REQUEST_TIMEOUT:?}",
        );
    }

    responses
        .into_iter()
        .filter_map(|(entry, response)| {
            let url = &entry.url;

            let bid = match response {
                Ok(Some(bid)) => bid,
                Ok(None) => {
                    debug_with_peers!("builder {url} has no bid for slot {slot}");
                    return None;
                }
                Err(error) => {
                    warn_with_peers!("failed to get bid from builder {url}: {error:?}");
                    return None;
                }
            };

            let builder_index = bid.message.builder_index;

            debug_with_peers!(
                "received bid from builder {builder_index} at {url} for slot {slot} \
                 (value: {}, execution_payment: {})",
                bid.message.value,
                bid.message.execution_payment,
            );

            let accepted = entry.builder_pubkeys.is_empty()
                || state
                    .builders()
                    .get(builder_index)
                    .is_ok_and(|builder| entry.builder_pubkeys.contains(&builder.pubkey));

            if !accepted {
                warn_with_peers!(
                    "rejected bid from builder {builder_index} at {url}: \
                     not one of the accepted builder pubkeys",
                );

                return None;
            }

            Some(BuilderApiBid {
                url: url.clone(),
                bid,
                weighting: entry.into(),
            })
        })
        .collect()
}

fn bid_parent_block_hash<P: Preset>(
    snapshot: &Snapshot<P>,
    state: &(impl PostGloasBeaconState<P> + ?Sized),
) -> ExecutionBlockHash {
    if snapshot.should_build_on_full(state.slot()) {
        state.latest_execution_payload_bid().block_hash
    } else {
        state.latest_execution_payload_bid().parent_block_hash
    }
}

fn prepare_state_for_execution_payload_bid<P: Preset>(
    chain_config: &ChainConfig,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    parent_block_hash: ExecutionBlockHash,
    parent_execution_requests: &GloasExecutionRequests<P>,
) -> Result<()> {
    gloas::process_parent_execution_payload(
        chain_config,
        pubkey_cache,
        state,
        parent_block_hash,
        parent_execution_requests,
    )?;

    gloas::process_withdrawals(state)
}

fn matches_proposer_preferences<P: Preset>(
    bid: &SignedExecutionPayloadBid<P>,
    fee_recipient: ExecutionAddress,
    parent_gas_limit: Gas,
    target_gas_limit: Gas,
) -> bool {
    if bid.message.fee_recipient != fee_recipient {
        warn_with_peers!(
            "rejected builder API bid from builder {} with wrong fee recipient \
             (fee_recipient: {:?}, expected: {fee_recipient:?})",
            bid.message.builder_index,
            bid.message.fee_recipient,
        );

        return false;
    }

    if !predicates::is_gas_limit_target_compatible(
        parent_gas_limit,
        bid.message.gas_limit,
        target_gas_limit,
    ) {
        warn_with_peers!(
            "rejected builder API bid from builder {} with incompatible gas limit \
             (gas_limit: {}, parent_gas_limit: {parent_gas_limit}, \
             target_gas_limit: {target_gas_limit})",
            bid.message.builder_index,
            bid.message.gas_limit,
        );

        return false;
    }

    true
}

/// Returns the winning bid along with the `source` it came with.
fn select_weighted_bid<'bid, P: Preset, S>(
    candidates: impl IntoIterator<Item = (&'bid SignedExecutionPayloadBid<P>, BidWeighting, S)>,
    local_mev: Option<Uint256>,
) -> Option<(&'bid SignedExecutionPayloadBid<P>, S)> {
    let (bid, source, builder_mev, builder_boost_factor, weighted_builder_mev) = candidates
        .into_iter()
        .filter_map(|(bid, weighting, source)| {
            let BidWeighting {
                max_execution_payment,
                min_bid,
                builder_boost_factor,
            } = weighting;

            let payment = bid
                .message
                .value
                .saturating_add(bid.message.execution_payment.min(max_execution_payment));

            if payment < min_bid {
                return None;
            }

            let builder_mev = Uint256::from_u64(payment).saturating_mul(WEI_IN_GWEI);
            let weighted_builder_mev = builder_mev.saturating_mul(builder_boost_factor);

            Some((
                bid,
                source,
                builder_mev,
                builder_boost_factor,
                weighted_builder_mev,
            ))
        })
        .max_by_key(|(_, _, builder_mev, _, weighted_builder_mev)| {
            (*weighted_builder_mev, *builder_mev)
        })?;

    if let Some(local_mev) = local_mev
        && local_mev.saturating_mul(Uint256::from_u64(100)) >= weighted_builder_mev
    {
        info_with_peers!(
            "using more profitable local payload: \
             local MEV: {local_mev}, builder MEV: {builder_mev}, \
             builder_boost_factor: {builder_boost_factor}",
        );

        return None;
    }

    Some((bid, source))
}

#[cfg(test)]
mod gloas_scoring_tests {
    use types::{gloas::containers::BuilderExitRequest, preset::Minimal};

    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProposalScenario {
        ProducerPaths,
        PackingFailure,
        Measure,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_build_and_builder_run_pool_packing_and_block_processing() -> Result<()> {
        proposal_fixture::<Minimal>(ChainConfig::minimal(), 64, ProposalScenario::ProducerPaths)
            .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn packing_failure_still_proposes_a_valid_block_without_attestations() -> Result<()> {
        proposal_fixture::<Minimal>(ChainConfig::minimal(), 64, ProposalScenario::PackingFailure)
            .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "manual release Mainnet-scale synthetic proposal latency measurement"]
    async fn measure_mainnet_scale_gloas_proposal() -> Result<()> {
        proposal_fixture::<types::preset::Mainnet>(
            ChainConfig::mainnet(),
            0x0010_0000,
            ProposalScenario::Measure,
        )
        .await
    }

    #[expect(
        clippy::too_many_lines,
        clippy::arithmetic_side_effects,
        clippy::print_stdout,
        clippy::default_trait_access
    )]
    async fn proposal_fixture<P: Preset>(
        config: ChainConfig,
        validator_count: usize,
        scenario: ProposalScenario,
    ) -> Result<()> {
        use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
        use crossbeam_utils::sync::WaitGroup;
        use helper_functions::signing::SignForSingleFork as _;
        use ssz::{BitList, SszListMut as _};
        use types::{phase0::containers::Validator, traits::SszValidatorListMut as _};

        assert!(!Feature::TrustOwnBlockSignatures.is_enabled());
        let config = Arc::new(config.start_and_stay_in(Phase::Gloas));
        let anchor_slot = P::SlotsPerEpoch::U64;
        let first_attestation_slot = 2 * P::SlotsPerEpoch::U64;
        let proposal_slot = 3 * P::SlotsPerEpoch::U64 - 2;
        let pubkeys = Arc::new(PubkeyCache::default());
        let keys = (1_u64..=validator_count as u64)
            .map(|index| {
                let mut bytes = SecretKeyBytes::default();
                bytes.as_mut()[24..].copy_from_slice(&index.to_be_bytes());
                SecretKey::try_from(bytes).expect("nonzero fixture secret key")
            })
            .collect_vec();
        let mut state = GloasBeaconState::<P>::default();
        state.fork.current_version = config.gloas_fork_version;
        state.fork.previous_version = config.gloas_fork_version;
        state.slot = anchor_slot;
        state.latest_block_header.slot = anchor_slot;
        state.latest_execution_payload_bid.slot = anchor_slot;
        state.current_justified_checkpoint.epoch = 1;
        state.justification_bits.set(0, true);
        state.builders.push(types::gloas::containers::Builder {
            pubkey: keys[63].to_public_key().into(),
            balance: 32_000_000_000,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Default::default()
        })?;
        state.latest_execution_payload_bid.block_hash = H256::repeat_byte(2);
        for key in &keys {
            state.validators.push(Validator {
                pubkey: key.to_public_key().into(),
                effective_balance: 32_000_000_000,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
                ..Default::default()
            })?;
            state.balances.push(32_000_000_000)?;
            state.previous_epoch_participation.push(0)?;
            state.current_epoch_participation.push(0)?;
            state.inactivity_scores.push(0)?;
        }
        let mut sync = types::altair::containers::SyncCommittee::<P>::default();
        for key in sync.pubkeys.iter_mut() {
            *key = keys[0].to_public_key().into();
        }
        state.current_sync_committee = Arc::new(Hc::new(sync));
        let mut anchor = GloasBeaconBlock::<P> {
            slot: anchor_slot,
            ..Default::default()
        };
        anchor.body.signed_execution_payload_bid.message =
            state.latest_execution_payload_bid.clone();
        state.latest_block_header.body_root = anchor.body.hash_tree_root();
        anchor.state_root = state.hash_tree_root();
        let root = anchor.hash_tree_root();
        let anchor =
            Arc::new(BeaconBlock::from(Hc::new(anchor)).with_signature(SignatureBytes::empty()));
        let state = Arc::new(BeaconState::Gloas(Hc::new(state)));
        let engine = Arc::new(Eth1ExecutionEngine::new(
            config.clone_arc(),
            Arc::new(eth1_api::Eth1Api::new(
                config.clone_arc(),
                reqwest::Client::new(),
                Arc::default(),
                vec![],
                None,
                None,
            )),
            futures::channel::mpsc::unbounded().0,
        ));
        let events = Arc::new(fork_choice_control::EventChannels::default());
        let storage = Arc::new(fork_choice_control::Storage::new(
            config.clone_arc(),
            pubkeys.clone_arc(),
            database::Database::in_memory(),
            fork_choice_control::DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
            Default::default(),
            true,
            fork_choice_control::DEFAULT_ZSTD_COMPRESSION_LEVEL,
        ));
        let (controller, _mutator) = fork_choice_control::Controller::<P, _, _, WaitGroup>::new(
            config.clone_arc(),
            pubkeys.clone_arc(),
            Default::default(),
            anchor,
            state,
            clock::Tick::start_of_slot(proposal_slot),
            events.clone_arc(),
            engine.clone_arc(),
            None,
            futures::channel::mpsc::unbounded().0,
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            storage,
            core::iter::empty(),
            true,
            Default::default(),
            Arc::default(),
            Some(2),
        )?;
        let executor = Arc::new(DedicatedExecutor::new("gloas integration", 2, None, None));
        // Only the attestation task fails; the producer and other pools must keep running.
        let attestation_executor = if scenario == ProposalScenario::PackingFailure {
            Arc::new(DedicatedExecutor::new(
                "failing attestation pool",
                2,
                None,
                None,
            ))
        } else {
            executor.clone_arc()
        };
        let pool = AttestationAggPool::new(
            controller.clone_arc(),
            attestation_executor.clone_arc(),
            None,
            None,
        );
        let (pool_tx, _) = futures::channel::mpsc::unbounded();
        let sync_pool = SyncCommitteeAggPool::new(
            executor.clone_arc(),
            controller.clone_arc(),
            pool_tx.clone(),
            None,
            None,
        );
        let (bls_pool, service) =
            BlsToExecutionChangePool::new(controller.clone_arc(), events, pool_tx, None);
        let service = tokio::spawn(service.run());
        let payload_pool =
            PayloadAttestationAggPool::new(controller.clone_arc(), executor.clone_arc(), None);
        let configs = Arc::new(ProposerConfigs::new(
            Default::default(),
            Some(30_000_000),
            H256::zero(),
            keymanager::BuilderSettings::default(),
            Arc::new(keymanager::ValidatorDefinitionsWithStorage::new(
                Arc::default(),
                Default::default(),
            )),
        ));
        let producer = BlockProducer::new(
            configs,
            None,
            Arc::new(PayloadBuilderApi::new(
                config.clone_arc(),
                reqwest::Client::new(),
                builder_api::BuilderApiFormat::default(),
                None,
            )),
            controller.clone_arc(),
            executor.clone_arc(),
            engine,
            pool.clone_arc(),
            bls_pool,
            sync_pool,
            payload_pool,
            None,
            None,
        );
        let proposal_state = controller.preprocessed_state_at_current_slot_blocking()?;
        let before = proposal_state.hash_tree_root();
        let data = AttestationData {
            slot: first_attestation_slot + 1,
            index: 0,
            beacon_block_root: root,
            source: proposal_state.current_justified_checkpoint(),
            target: types::phase0::containers::Checkpoint { epoch: 2, root },
        };
        let wait = WaitGroup::new();
        // Minimal: six fully participating slots justify the checkpoint. The scale
        // measurement also uses full committees, but stops before importing.
        let committees = accessors::get_committee_count_per_slot(
            &proposal_state,
            types::nonstandard::RelativeEpoch::Current,
        )?;
        for attestation_slot in first_attestation_slot..proposal_slot {
            let data = AttestationData {
                slot: attestation_slot,
                ..data
            };
            for committee_index in 0..committees {
                let committee = accessors::beacon_committee(
                    &proposal_state,
                    attestation_slot,
                    committee_index,
                )?;
                let mut signature = AggregateSignature::default();
                let participants = committee.len();
                let mut aggregation_bits = BitList::new(false, committee.len());
                for (position, index) in committee.into_iter().take(participants).enumerate() {
                    aggregation_bits.set(position, true);
                    signature.aggregate_in_place(data.sign(
                        &config,
                        &proposal_state,
                        &keys[usize::try_from(index)?],
                    ));
                }
                let attestation =
                    operation_pools::convert_to_electra_attestation(PoolAttestation::<P> {
                        data,
                        committee_index,
                        aggregation_bits,
                        signature: signature.into(),
                    })?;
                pool.insert_attestation(
                    wait.clone(),
                    Arc::new(types::combined::Attestation::Gloas(attestation.into())),
                    None,
                );
            }
        }
        tokio::task::spawn_blocking(move || wait.wait()).await?;
        let candidate_count = (proposal_slot - first_attestation_slot) * committees;
        assert_eq!(
            pool.aggregate_attestations_by_epoch(2).await.len(),
            usize::try_from(candidate_count)?
        );
        let context = producer.new_build_context(
            proposal_state.clone_arc(),
            root,
            0,
            BlockBuildOptions {
                disable_blockprint_graffiti: true,
                ..Default::default()
            },
        );
        let payload = ExecutionPayload::Gloas(types::gloas::containers::ExecutionPayload::<P> {
            block_hash: H256::repeat_byte(3),
            gas_limit: 30_000_000,
            slot_number: proposal_slot,
            timestamp: misc::compute_timestamp_at_slot(&config, &proposal_state, proposal_slot)?,
            prev_randao: accessors::get_randao_mix(&proposal_state, 2),
            ..Default::default()
        });
        let mut response = WithBlobsAndMev::with_default(payload.clone());
        response.execution_requests =
            Some(ExecutionRequests::Gloas(GloasExecutionRequests::default()));
        context
            .producer_context
            .payload_cache
            .lock()
            .await
            .cache_set(
                payload.hash_tree_root(),
                WithClientVersions::none(response.clone()),
            );
        let randao = helper_functions::signing::RandaoEpoch::from(2)
            .sign(&config, &proposal_state, &keys[0])
            .into();
        if scenario == ProposalScenario::PackingFailure {
            assert!(
                !pool
                    .gloas_proposable_attestations(proposal_state.clone_arc())
                    .await?
                    .is_empty()
            );
            attestation_executor.shutdown();
            pool.gloas_proposable_attestations(proposal_state.clone_arc())
                .await
                .expect_err("packing task must fail after its executor shuts down");
        }
        let started = std::time::Instant::now();
        let result = context
            .build_blinded_beacon_block(
                randao,
                None,
                Some(tokio::spawn(async move {
                    Some(WithClientVersions::none(response))
                })),
                None,
            )
            .await?
            .expect("self-built block must process successfully");
        let elapsed = started.elapsed();
        let ValidatorBlindedBlock::BeaconBlock(BeaconBlock::Gloas(block)) = result.0.value else {
            panic!("expected Gloas block")
        };
        if scenario == ProposalScenario::PackingFailure {
            assert!(block.body.attestations.is_empty());
            assert_eq!(
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .builder_index,
                BUILDER_INDEX_SELF_BUILD
            );
            assert_ne!(block.state_root, H256::zero());
            assert_eq!(proposal_state.hash_tree_root(), before);
            service.abort();
            executor.shutdown();
            return Ok(());
        }
        assert_eq!(
            block.body.attestations.len(),
            usize::try_from(proposal_slot - first_attestation_slot)?
                .min(P::MaxAttestationsElectra::USIZE)
        );
        assert!(
            block
                .body
                .attestations
                .iter()
                .all(|attestation| attestation.committee_bits.count_ones()
                    == usize::try_from(committees).expect("bounded committee count"))
        );
        assert_eq!(
            block
                .body
                .signed_execution_payload_bid
                .message
                .builder_index,
            BUILDER_INDEX_SELF_BUILD
        );
        assert_ne!(block.state_root, H256::zero());
        assert_eq!(proposal_state.hash_tree_root(), before);
        println!(
            "proposal preset={} validators={validator_count} candidates={candidate_count} full_committee_participation=true final_aggregates={} total_build_us={} (includes task scheduling, pool retrieval, parent processing, packing and block processing; excludes fixture/EL/signing/publish)",
            core::any::type_name::<P>(),
            block.body.attestations.len(),
            elapsed.as_micros()
        );
        if scenario == ProposalScenario::Measure {
            let BeaconState::Gloas(state) = &*proposal_state else {
                unreachable!()
            };
            let mut times = Vec::new();
            for _ in 0..5 {
                let mut scoring_block = (*block).clone();
                let started = std::time::Instant::now();
                let scoring_state = prepare_gloas_scoring_state(
                    &config,
                    &pubkeys,
                    state,
                    &mut scoring_block,
                    |_| panic!("EMPTY parent needs no envelope"),
                )?;
                let attestations = pool
                    .gloas_proposable_attestations(Arc::new(BeaconState::Gloas(scoring_state)))
                    .await?;
                times.push(started.elapsed().as_micros());
                assert_eq!(attestations.as_slice(), block.body.attestations.as_ref());
            }
            println!(
                "warm EMPTY parent preparation + real manager/task/pool/packer us={times:?}; standalone seam measurement, not incremental whole-proposal A/B"
            );
            service.abort();
            executor.shutdown();
            return Ok(());
        }
        assert!(
            block
                .body
                .attestations
                .iter()
                .any(|attestation| attestation.data == data)
        );
        // Import the self-built block and its envelope through the real controller before
        // accepting an external builder bid on its FULL payload.
        let built_root = block.hash_tree_root();
        let signature = block.sign(&config, &proposal_state, &keys[0]).into();
        let (tx, mut rx) = futures::channel::mpsc::channel(2);
        controller.on_api_block(
            Arc::new(BeaconBlock::Gloas(block).with_signature(signature)),
            tx,
        );
        assert_eq!(
            rx.next().await.expect("block validation reply")?,
            types::nonstandard::ValidationOutcome::Accept
        );
        controller.wait_for_tasks();
        assert_eq!(controller.head().value.block_root, built_root);
        let (envelope, _, _) = producer
            .build_local_execution_payload_envelope_contents(built_root, root)
            .await
            .expect("cached local payload");
        let post = controller.preprocessed_state_at_current_slot_blocking()?;
        let signed = types::gloas::containers::SignedExecutionPayloadEnvelope {
            signature: envelope.sign(&config, &post, &keys[0]).into(),
            message: envelope,
        };
        controller.on_own_execution_payload_envelope(Arc::new(signed));
        controller.wait_for_tasks();
        assert!(
            controller
                .snapshot()
                .cached_execution_payload_envelope_by_root(built_root)
                .is_some()
        );
        controller.on_notified_new_payload(
            built_root,
            H256::repeat_byte(3),
            execution_engine::PayloadStatusV1 {
                status: execution_engine::PayloadValidationStatus::Valid,
                latest_valid_hash: Some(H256::repeat_byte(3)),
                validation_error: None,
            },
        );
        controller.wait_for_tasks();
        controller.on_slot(25);
        controller.wait_for_tasks();
        let proposal_state = controller.preprocessed_state_at_next_slot_blocking()?;
        assert!(controller.snapshot().should_build_on_full(26));
        let proposer = accessors::get_beacon_proposer_index(&config, &proposal_state)?;
        let preferences = ProposerPreferences {
            dependent_root: controller
                .shuffling_dependent_root(built_root, 3)
                .expect("known shuffling root"),
            proposal_slot: 26,
            validator_index: proposer,
            fee_recipient: Default::default(),
            target_gas_limit: 30_000_000,
        };
        let (tx, rx) = futures::channel::oneshot::channel();
        controller.on_api_proposer_preferences(
            Arc::new(types::gloas::containers::SignedProposerPreferences {
                signature: preferences
                    .sign(&config, &proposal_state, &keys[usize::try_from(proposer)?])
                    .into(),
                message: preferences,
            }),
            tx,
        );
        assert_eq!(rx.await??, types::nonstandard::ValidationOutcome::Accept);
        controller.wait_for_tasks();
        controller.on_slot(26);
        controller.wait_for_tasks();
        let bid = ExecutionPayloadBid::<P> {
            parent_block_hash: H256::repeat_byte(3),
            parent_block_root: built_root,
            block_hash: H256::repeat_byte(4),
            prev_randao: accessors::get_randao_mix(&proposal_state, 3),
            gas_limit: 30_000_000,
            builder_index: 0,
            slot: 26,
            value: 1,
            execution_requests_root: GloasExecutionRequests::<P>::default().hash_tree_root(),
            ..Default::default()
        };
        let (tx, rx) = futures::channel::oneshot::channel();
        controller.on_api_execution_payload_bid(
            Arc::new(SignedExecutionPayloadBid {
                signature: bid.sign(&config, &proposal_state, &keys[63]).into(),
                message: bid,
            }),
            tx,
        );
        assert_eq!(
            rx.await??,
            types::nonstandard::ValidationOutcomeWithReason::Accept
        );
        // Bid validation replies before publishing the store snapshot and has no
        // WaitGroup token. A subsequent tick provides a mutator-queue barrier.
        controller.on_slot(26);
        controller.wait_for_tasks();
        assert!(
            controller
                .snapshot()
                .accepted_payload_bids_at_slot(26)
                .iter()
                .any(|bid| bid.message.builder_index == 0)
        );
        let data = AttestationData {
            slot: 25,
            index: 1,
            beacon_block_root: built_root,
            source: proposal_state.current_justified_checkpoint(),
            target: types::phase0::containers::Checkpoint {
                epoch: 3,
                root: built_root,
            },
        };
        let wait = WaitGroup::new();
        // Controlled conflicting votes make the selected group depend on the
        // parent context, rather than merely checking that one group survives.
        for vote in [0, 1] {
            let data = AttestationData {
                index: vote,
                ..data
            };
            for committee_index in 0..2 {
                let committee = accessors::beacon_committee(&proposal_state, 25, committee_index)?;
                let mut signature = AggregateSignature::default();
                for index in committee {
                    signature.aggregate_in_place(data.sign(
                        &config,
                        &proposal_state,
                        &keys[usize::try_from(index)?],
                    ));
                }
                pool.insert_attestation(
                    wait.clone(),
                    Arc::new(types::combined::Attestation::Gloas(
                        operation_pools::convert_to_electra_attestation(PoolAttestation::<P> {
                            data,
                            committee_index,
                            aggregation_bits: BitList::new(true, committee.len()),
                            signature: signature.into(),
                        })?
                        .into(),
                    )),
                    None,
                );
            }
        }
        tokio::task::spawn_blocking(move || wait.wait()).await?;
        let before_parent = pool
            .gloas_proposable_attestations(proposal_state.clone_arc())
            .await?;
        assert_eq!(before_parent.len(), 1);
        assert_eq!(before_parent[0].data.index, 0);
        let before = proposal_state.hash_tree_root();
        let context = producer.new_build_context(
            proposal_state.clone_arc(),
            built_root,
            proposer,
            BlockBuildOptions {
                disable_blockprint_graffiti: true,
                ..Default::default()
            },
        );
        let randao = helper_functions::signing::RandaoEpoch::from(3)
            .sign(&config, &proposal_state, &keys[usize::try_from(proposer)?])
            .into();
        let result = context
            .build_blinded_beacon_block(randao, None, None, None)
            .await?
            .expect("external builder proposal must process");
        let ValidatorBlindedBlock::BeaconBlock(BeaconBlock::Gloas(block)) = result.0.value else {
            panic!("expected Gloas")
        };
        assert_eq!(block.body.attestations.len(), 1);
        assert_eq!(
            block
                .body
                .signed_execution_payload_bid
                .message
                .builder_index,
            0
        );
        assert!(
            block
                .body
                .attestations
                .iter()
                .any(|att| att.data == data && att.committee_bits.count_ones() == 2)
        );
        assert_eq!(proposal_state.hash_tree_root(), before);
        service.abort();
        executor.shutdown();
        Ok(())
    }

    fn fixture(full: bool) -> (Hc<GloasBeaconState<Minimal>>, GloasBeaconBlock<Minimal>) {
        let mut state = GloasBeaconState::<Minimal> {
            slot: 102,
            ..Default::default()
        };
        state.latest_block_header.slot = 100;
        state.latest_execution_payload_bid.slot = 100;
        state.latest_execution_payload_bid.block_hash = H256::repeat_byte(2);
        state.latest_execution_payload_bid.execution_requests_root =
            GloasExecutionRequests::<Minimal>::default().hash_tree_root();
        let mut block = GloasBeaconBlock::<Minimal> {
            slot: 102,
            parent_root: H256::repeat_byte(1),
            ..Default::default()
        };
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash = if full {
            state.latest_execution_payload_bid.block_hash
        } else {
            state.latest_block_hash
        };
        (Hc::new(state), block)
    }

    #[test]
    fn final_bid_parent_path_controls_requests_and_scoring_copy() -> Result<()> {
        let config = ChainConfig::minimal().start_and_stay_in(Phase::Gloas);
        for builder_index in [BUILDER_INDEX_SELF_BUILD, 0] {
            for full in [false, true] {
                let (mut state, mut block) = fixture(full);
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .builder_index = builder_index;
                // An unknown builder exit is ignored, but gives the envelope a nonempty commitment.
                let requests = GloasExecutionRequests::<Minimal> {
                    builder_exits: vec![BuilderExitRequest::default()].try_into()?,
                    ..GloasExecutionRequests::default()
                };
                state.latest_execution_payload_bid.execution_requests_root =
                    requests.hash_tree_root();
                let original_root = state.hash_tree_root();
                let expected_root = block.parent_root;
                let mut lookups = 0;
                let scoring = prepare_gloas_scoring_state(
                    &config,
                    &PubkeyCache::default(),
                    &state,
                    &mut block,
                    |root| {
                        lookups += 1;
                        assert_eq!(root, expected_root);
                        Some(requests.clone())
                    },
                )?;
                assert_eq!(lookups, usize::from(full));
                assert_eq!(state.hash_tree_root(), original_root);
                assert_eq!(
                    scoring
                        .execution_payload_availability
                        .get(100 % types::preset::SlotsPerHistoricalRoot::<Minimal>::USIZE),
                    Some(full)
                );
                assert_eq!(
                    block.body.parent_execution_requests,
                    if full {
                        requests
                    } else {
                        GloasExecutionRequests::default()
                    }
                );
            }
        }
        Ok(())
    }

    #[test]
    fn full_parent_requires_envelope_and_matching_commitment() {
        let config = ChainConfig::minimal().start_and_stay_in(Phase::Gloas);
        let (mut state, mut block) = fixture(true);
        let missing = prepare_gloas_scoring_state(
            &config,
            &PubkeyCache::default(),
            &state,
            &mut block,
            |_| None,
        );
        assert!(
            missing
                .expect_err("FULL parent requires an envelope")
                .to_string()
                .contains("missing FULL parent payload envelope")
        );
        state.latest_execution_payload_bid.execution_requests_root = H256::repeat_byte(9);
        let original_root = state.hash_tree_root();
        prepare_gloas_scoring_state(&config, &PubkeyCache::default(), &state, &mut block, |_| {
            Some(GloasExecutionRequests::default())
        })
        .expect_err("parent requests must match the commitment");
        assert_eq!(state.hash_tree_root(), original_root);
    }

    #[test]
    fn pre_gloas_parent_does_not_require_envelope() -> Result<()> {
        use ssz::SszListMut as _;
        use types::traits::SszValidatorListMut as _;

        let mut config = ChainConfig::minimal().start_and_stay_in(Phase::Fulu);
        config.gloas_fork_epoch = 12;
        let mut pre = types::fulu::beacon_state::BeaconState::<Minimal> {
            slot: 96,
            ..Default::default()
        };
        pre.latest_block_header.slot = 95;
        pre.latest_execution_payload_header.block_hash = H256::repeat_byte(2);
        for _ in 0..64 {
            pre.validators.push(types::phase0::containers::Validator {
                effective_balance: 32_000_000_000,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
                ..Default::default()
            })?;
            pre.balances.push(32_000_000_000)?;
            pre.previous_epoch_participation.push(0)?;
            pre.current_epoch_participation.push(0)?;
            pre.inactivity_scores.push(0)?;
        }
        let state = Hc::new(helper_functions::fork::upgrade_to_gloas(
            &config,
            &PubkeyCache::default(),
            pre,
        )?);
        assert_eq!(state.latest_execution_payload_bid.slot, 95);
        assert_eq!(
            state.latest_execution_payload_bid.execution_requests_root,
            GloasExecutionRequests::<Minimal>::default().hash_tree_root()
        );
        let mut block = GloasBeaconBlock::<Minimal> {
            slot: 96,
            ..Default::default()
        };
        block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash = state.latest_execution_payload_bid.block_hash;
        assert_eq!(config.phase_at_slot::<Minimal>(95), Phase::Fulu);
        assert_eq!(config.phase_at_slot::<Minimal>(96), Phase::Gloas);
        let scoring = prepare_gloas_scoring_state(
            &config,
            &PubkeyCache::default(),
            &state,
            &mut block,
            |_| panic!("pre-Gloas parent has no envelope"),
        )?;
        assert_eq!(
            scoring
                .execution_payload_availability
                .get(95 % types::preset::SlotsPerHistoricalRoot::<Minimal>::USIZE),
            Some(true)
        );
        assert_eq!(
            block.body.parent_execution_requests,
            GloasExecutionRequests::default()
        );
        Ok(())
    }
}
