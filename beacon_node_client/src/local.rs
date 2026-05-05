use std::{collections::HashSet, pin::Pin, sync::Arc, time::Duration};

use anyhow::{Result, anyhow, bail, ensure};
use async_trait::async_trait;
use bls::{PublicKeyBytes, SignatureBytes, traits::SignatureBytes as _};
use eth1_api::ApiController;
use fork_choice_control::{Event, EventChannels, Topic, Wait};
use futures::{
    StreamExt,
    channel::{mpsc::UnboundedSender, oneshot},
    stream::{self, Stream},
};
use genesis::AnchorCheckpointProvider;
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use kzg_utils::KzgBackend;
use liveness_tracker::ApiToLiveness;
use operation_pools::{AttestationAggPool, SyncCommitteeAggPool, convert_to_electra_attestation};
use p2p::{
    BeaconCommitteeSubscription, SyncCommitteeSubscription, ToSubnetService, ValidatorToP2p,
};
use prometheus_metrics::Metrics;
use ssz::{Hc, SszHash};
use std_ext::ArcExt as _;
use tokio::time::timeout;
use tokio_stream::wrappers::BroadcastStream;
use typenum::Unsigned;
use types::{
    altair::{
        consts::SyncCommitteeSubnetCount,
        containers::{
            SignedContributionAndProof, SyncCommittee, SyncCommitteeContribution,
            SyncCommitteeMessage,
        },
    },
    combined::{Attestation, AttesterSlashing, BeaconState, DataColumnSidecar, SignedBeaconBlock},
    config::Config as ChainConfig,
    deneb::containers::BlobSidecar,
    gloas::containers::ExecutionPayloadBid,
    nonstandard::{Phase, RelativeEpoch, WithBlobsAndMev, WithStatus},
    phase0::{
        containers::{AttestationData, Checkpoint, ProposerSlashing},
        primitives::{
            CommitteeIndex, Epoch, ExecutionAddress, H256, Slot, SubnetId, Uint256, ValidatorIndex,
        },
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    ids::StateId,
    traits::{BeaconChainReader, BeaconDutyEndpoints, BeaconEventStream, BeaconPublisher},
    types::{
        AttesterDuty, BlockHeaderSummary, BlockProductionOptions, BroadcastValidation,
        DutiesResponse, GenesisData, ProposerDuty, ProposerPreparation, SyncCommitteeDuty,
        SyncingStatus, ValidatorLiveness,
    },
};

const ATTESTATION_DATA_BLOCK_EVENT_WAIT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug)]
pub struct LocalConfig {
    pub max_empty_slots: u64,
    pub disable_wait_for_late_blocks: bool,
    pub disable_blockprint_graffiti: bool,
    pub default_builder_boost_factor: Uint256,
}

pub struct LocalBeaconClient<P: Preset, W: Wait> {
    chain_config: Arc<ChainConfig>,
    local_config: LocalConfig,
    controller: ApiController<P, W>,
    block_producer: Arc<block_producer::BlockProducer<P, W>>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    event_channels: Arc<EventChannels<P>>,
    anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
    metrics: Option<Arc<Metrics>>,
    api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    subnet_service_tx: UnboundedSender<ToSubnetService>,
}

impl<P: Preset, W: Wait> LocalBeaconClient<P, W> {
    #[expect(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        local_config: LocalConfig,
        controller: ApiController<P, W>,
        block_producer: Arc<block_producer::BlockProducer<P, W>>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        event_channels: Arc<EventChannels<P>>,
        anchor_checkpoint_provider: AnchorCheckpointProvider<P>,
        metrics: Option<Arc<Metrics>>,
        api_to_liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
        p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
        subnet_service_tx: UnboundedSender<ToSubnetService>,
    ) -> Self {
        Self {
            chain_config,
            local_config,
            controller,
            block_producer,
            attestation_agg_pool,
            sync_committee_agg_pool,
            event_channels,
            anchor_checkpoint_provider,
            metrics,
            api_to_liveness_tx,
            p2p_tx,
            subnet_service_tx,
        }
    }

    fn resolve_state(&self, state_id: StateId) -> Result<WithStatus<Arc<BeaconState<P>>>> {
        let result = match state_id {
            StateId::Head => Some(self.controller.head_state()),
            StateId::Genesis => self
                .anchor_checkpoint_provider
                .checkpoint()
                .genesis()
                .map(|checkpoint| checkpoint.state)
                .map(WithStatus::valid_and_finalized),
            StateId::Finalized => Some(self.controller.last_finalized_state()),
            StateId::Justified => Some(self.controller.justified_state()?),
            StateId::Slot(slot) => {
                tokio::task::block_in_place(|| self.controller.state_at_slot_cached_blocking(slot))?
            }
            StateId::Root(root) => self.controller.state_by_state_root(root)?,
        };
        result.ok_or_else(|| anyhow!("state not found"))
    }

    fn state_sync_committee(
        beacon_state: &BeaconState<P>,
        requested_period: u64,
    ) -> Option<Arc<Hc<SyncCommittee<P>>>> {
        let state = beacon_state.post_altair()?;
        let state_epoch = misc::compute_epoch_at_slot::<P>(state.slot());
        let state_period = misc::sync_committee_period::<P>(state_epoch);

        if requested_period == state_period {
            Some(state.current_sync_committee().clone_arc())
        } else if requested_period == state_period + 1 {
            Some(state.next_sync_committee().clone_arc())
        } else {
            None
        }
    }
}

#[async_trait]
impl<P: Preset, W: Wait> BeaconChainReader<P> for LocalBeaconClient<P, W> {
    async fn genesis(&self) -> Result<GenesisData> {
        let anchor_state = self.anchor_checkpoint_provider.checkpoint().value.state;

        Ok(GenesisData {
            genesis_time: anchor_state.genesis_time(),
            genesis_validators_root: anchor_state.genesis_validators_root(),
            genesis_fork_version: self.chain_config.genesis_fork_version.into(),
        })
    }

    async fn chain_config(&self) -> Result<Arc<ChainConfig>> {
        Ok(self.chain_config.clone())
    }

    async fn is_forward_synced(&self) -> bool {
        self.controller.is_forward_synced()
    }

    async fn syncing_status(&self) -> Result<SyncingStatus> {
        let head_slot = self.controller.head_slot();
        let highest_slot = self.controller.slot();
        let head = self.controller.head();
        Ok(SyncingStatus {
            head_slot,
            sync_distance: highest_slot.saturating_sub(head_slot),
            is_syncing: !self.controller.is_forward_synced(),
            is_optimistic: head.status.is_optimistic(),
            el_offline: false,
        })
    }

    async fn head_block_header(&self) -> Result<BlockHeaderSummary> {
        let head = self.controller.head().value;
        let block_message = head.block.message();
        Ok(BlockHeaderSummary {
            slot: block_message.slot(),
            block_root: head.block_root,
            parent_root: block_message.parent_root(),
            state_root: block_message.state_root(),
            proposer_index: block_message.proposer_index(),
        })
    }

    async fn state_root(&self, state_id: StateId) -> Result<H256> {
        let state = self.beacon_state(state_id).await?;
        Ok(state.hash_tree_root())
    }

    async fn beacon_state(&self, state_id: StateId) -> Result<Arc<BeaconState<P>>> {
        Ok(self.resolve_state(state_id)?.value)
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<DutiesResponse<Vec<AttesterDuty>>> {
        let head_state = self.controller.head_state();

        let (state_with_status, relative_epoch) =
            match accessors::relative_epoch(&head_state.value, epoch) {
                Ok(relative_epoch) => (head_state, relative_epoch),
                Err(_) => {
                    let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
                    let state_with_status = self.resolve_state(StateId::Slot(start_slot))?;
                    (state_with_status, RelativeEpoch::Current)
                }
            };

        let WithStatus {
            value: state,
            status,
            finalized: _,
        } = state_with_status;

        let previous_epoch = misc::previous_epoch(epoch);
        let dependent_root = self.controller.dependent_root(&state, previous_epoch)?;

        let index_set: HashSet<ValidatorIndex> = indices.iter().copied().collect();
        let committees_at_slot = accessors::get_committee_count_per_slot(&state, relative_epoch);

        let duties = misc::slots_in_epoch::<P>(epoch)
            .map(|slot| {
                accessors::beacon_committees(&state, slot)?
                    .zip(0..)
                    .flat_map(|(committee, committee_index)| {
                        let state_ref = &state;
                        committee
                            .into_iter()
                            .enumerate()
                            .filter(|(_, validator_index)| index_set.contains(validator_index))
                            .map(move |(validator_committee_index, validator_index)| {
                                let pubkey = *accessors::public_key(state_ref, validator_index)?;
                                Ok(AttesterDuty {
                                    pubkey,
                                    validator_index,
                                    committee_index,
                                    committee_length: committee.len(),
                                    committees_at_slot,
                                    validator_committee_index,
                                    slot,
                                })
                            })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .flatten_ok()
            .try_collect()?;

        Ok(DutiesResponse {
            dependent_root,
            execution_optimistic: status.is_optimistic(),
            data: duties,
        })
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<DutiesResponse<Vec<ProposerDuty>>> {
        let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
        let head = self.controller.head();

        let (state, status) = if start_slot >= head.value.slot() {
            let block_root = head.value.block_root;
            let state = self
                .controller
                .preprocessed_state_for_block_production(block_root, start_slot)
                .await?;
            (state, head.status)
        } else {
            let WithStatus {
                value: state,
                status,
                finalized: _,
            } = self.resolve_state(StateId::Slot(start_slot))?;
            (state, status)
        };

        let dependent_root = if self.chain_config.phase_at_epoch(epoch) >= Phase::Fulu {
            self.controller
                .dependent_root(&state, misc::previous_epoch(epoch))?
        } else {
            self.controller.dependent_root(&state, epoch)?
        };

        let duties: Vec<ProposerDuty> = misc::slots_in_epoch::<P>(epoch)
            .map(|slot| -> Result<ProposerDuty> {
                let validator_index =
                    accessors::get_beacon_proposer_index_at_slot(&self.chain_config, &state, slot)?;
                let pubkey = *accessors::public_key(&state, validator_index)?;
                Ok(ProposerDuty {
                    pubkey,
                    validator_index,
                    slot,
                })
            })
            .try_collect()?;

        Ok(DutiesResponse {
            dependent_root,
            execution_optimistic: status.is_optimistic(),
            data: duties,
        })
    }

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<DutiesResponse<Vec<SyncCommitteeDuty>>> {
        if self.chain_config.phase_at_epoch(epoch) < Phase::Altair {
            return Ok(DutiesResponse {
                dependent_root: H256::zero(),
                execution_optimistic: false,
                data: vec![],
            });
        }

        let requested_period = misc::sync_committee_period::<P>(epoch);
        let head_state = self.controller.head_state();

        let (state_with_status, committee) = if let Some(committee) =
            Self::state_sync_committee(&head_state.value, requested_period)
        {
            (head_state, committee)
        } else {
            let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
            let state = self.resolve_state(StateId::Slot(start_slot))?;
            if let Some(committee) = Self::state_sync_committee(&state.value, requested_period) {
                (state, committee)
            } else {
                bail!("requested epoch is not within the current or next sync committee period");
            }
        };

        let WithStatus {
            value: state,
            status,
            finalized: _,
        } = state_with_status;

        let duties = indices
            .iter()
            .copied()
            .map(|validator_index| {
                let validator_pubkey = accessors::public_key(&state, validator_index)?;
                let validator_sync_committee_indices = committee
                    .pubkeys
                    .iter()
                    .enumerate()
                    .filter_map(|(index, pubkey)| (pubkey == validator_pubkey).then_some(index))
                    .collect_vec();

                if validator_sync_committee_indices.is_empty() {
                    return Ok(None);
                }

                Ok(Some(SyncCommitteeDuty {
                    pubkey: *validator_pubkey,
                    validator_index,
                    validator_sync_committee_indices,
                }))
            })
            .filter_map(Result::transpose)
            .collect::<Result<Vec<_>>>()?;

        Ok(DutiesResponse {
            dependent_root: H256::zero(),
            execution_optimistic: status.is_optimistic(),
            data: duties,
        })
    }

    async fn validator_liveness(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLiveness>> {
        let api_to_liveness_tx = self
            .api_to_liveness_tx
            .as_ref()
            .ok_or_else(|| anyhow!("liveness tracking is not enabled"))?;

        let state = self.controller.preprocessed_state_at_current_slot().await?;
        accessors::attestation_epoch(&state, epoch)?;

        let (sender, receiver) = oneshot::channel();
        ApiToLiveness::CheckLiveness(sender, epoch, indices.to_vec()).send(api_to_liveness_tx);

        let liveness = receiver
            .await??
            .into_iter()
            .map(|(index, is_live)| ValidatorLiveness { index, is_live })
            .collect();

        Ok(liveness)
    }

    async fn is_registered_validator(&self, validator_index: ValidatorIndex) -> bool {
        self.attestation_agg_pool
            .is_registered_validator(validator_index)
            .await
    }

    async fn registered_validator_indices(&self) -> HashSet<ValidatorIndex> {
        self.attestation_agg_pool
            .registered_validator_indices()
            .await
    }

    async fn no_prepared_proposers(&self) -> bool {
        self.block_producer.no_prepared_proposers().await
    }

    async fn prepared_proposer_indices(&self) -> Vec<ValidatorIndex> {
        self.block_producer.get_prepared_proposer_indices().await
    }

    fn kzg_backend(&self) -> KzgBackend {
        self.controller.store_config().kzg_backend
    }

    async fn preprocessed_state_at_current_slot(&self) -> Result<Arc<BeaconState<P>>> {
        self.controller.preprocessed_state_at_current_slot().await
    }

    async fn preprocessed_state_post_block(
        &self,
        block_root: H256,
        slot: Slot,
    ) -> Result<Arc<BeaconState<P>>> {
        let controller = self.controller.clone();
        tokio::task::spawn_blocking(move || {
            controller.preprocessed_state_post_block_blocking(block_root, slot)
        })
        .await?
    }

    async fn has_current_slot_blocks_in_processing(&self) -> bool {
        self.controller.has_current_slot_blocks_in_processing()
    }
}

#[async_trait]
impl<P: Preset, W: Wait> BeaconDutyEndpoints<P> for LocalBeaconClient<P, W> {
    async fn produce_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let _timer = self
            .metrics
            .as_ref()
            .map(|metrics| metrics.validator_api_attestation_data_times.start_timer());

        let phase_at_slot = self.controller.chain_config().phase_at_slot::<P>(slot);
        let committee_index = if phase_at_slot < Phase::Electra {
            committee_index
        } else {
            0
        };

        let WithStatus {
            value: head,
            status,
            ..
        } = self.controller.head();

        let head_slot = head.slot();
        let max_empty_slots = self.local_config.max_empty_slots;

        if head_slot + max_empty_slots < slot {
            bail!(
                "head is too far behind: head_slot={head_slot} slot={slot} max_empty_slots={max_empty_slots}"
            );
        }

        let requested_epoch = misc::compute_epoch_at_slot::<P>(slot);
        let previous_epoch = misc::previous_epoch(misc::compute_epoch_at_slot::<P>(head_slot));
        ensure!(
            requested_epoch >= previous_epoch,
            "requested epoch is before the previous epoch",
        );

        let mut block_root;
        let mut state;

        let is_optimistic = if slot < head_slot {
            let block = self
                .controller
                .block_by_slot(slot)?
                .ok_or_else(|| anyhow!("block not found"))?;
            block_root = block.value.root;
            state = self
                .controller
                .state_before_or_at_slot(block_root, slot)
                .ok_or_else(|| anyhow!("state not found"))?;
            block.status.is_optimistic()
        } else {
            block_root = head.block_root;
            state = self.controller.state_by_chain_link(&head);
            status.is_optimistic()
        };

        let should_wait_for_late_block = !self.local_config.disable_wait_for_late_blocks
            && self.controller.has_current_slot_blocks_in_processing();

        if is_optimistic || should_wait_for_late_block {
            let event_channels = self.event_channels.clone();
            let controller = self.controller.clone();
            let mut current_block_root = block_root;
            let mut current_state = state.clone();
            let wait_result = timeout(ATTESTATION_DATA_BLOCK_EVENT_WAIT_TIMEOUT, async move {
                let mut receiver = BroadcastStream::new(event_channels.receiver_for(Topic::Block));
                while let Some(event) = receiver.next().await {
                    let block_event = match event {
                        Ok(Event::Block(block_event)) => block_event,
                        Ok(_) => continue,
                        Err(_) => continue,
                    };

                    if block_event.execution_optimistic {
                        continue;
                    }

                    if block_event.block == current_block_root {
                        break;
                    }

                    let head = controller.head().value;
                    if block_event.block == head.block_root {
                        current_block_root = head.block_root;
                        current_state = controller.state_by_chain_link(&head);
                        break;
                    }
                }
                (current_block_root, current_state)
            })
            .await;

            match wait_result {
                Ok((updated_root, updated_state)) => {
                    block_root = updated_root;
                    state = updated_state;
                }
                Err(_) if is_optimistic => {
                    bail!("timed out waiting for chain head to become fully validated");
                }
                Err(_) => {}
            }
        }

        if state.slot() < slot {
            let controller = self.controller.clone();
            state = tokio::task::spawn_blocking(move || {
                controller.preprocessed_state_post_block_blocking(block_root, slot)
            })
            .await??;
        }

        let target = Checkpoint {
            epoch: requested_epoch,
            root: accessors::epoch_boundary_block_root(&state, block_root),
        };

        Ok(AttestationData {
            slot,
            index: committee_index,
            beacon_block_root: block_root,
            source: state.current_justified_checkpoint(),
            target,
        })
    }

    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        options: BlockProductionOptions,
    ) -> Result<WithBlobsAndMev<block_producer::ValidatorBlindedBlock<P>, P>> {
        ensure!(
            !(options.skip_randao_verification && !randao_reveal.is_empty()),
            "skip_randao_verification requires an empty randao_reveal",
        );

        let block_root = self.controller.head().value.block_root;
        let beacon_state = self
            .controller
            .preprocessed_state_for_block_production(block_root, slot)
            .await?;

        let proposer_index =
            accessors::get_beacon_proposer_index(&self.chain_config, &beacon_state)
                .map_err(|_| anyhow!("head state has no active validators"))?;

        let public_key = accessors::public_key(&beacon_state, proposer_index)?;

        let builder_boost_factor = options
            .builder_boost_factor
            .map(Uint256::from_u64)
            .unwrap_or(self.local_config.default_builder_boost_factor);

        let block_build_context = self.block_producer.new_build_context(
            beacon_state.clone_arc(),
            block_root,
            proposer_index,
            block_producer::BlockBuildOptions {
                graffiti: options.graffiti,
                disable_blockprint_graffiti: self.local_config.disable_blockprint_graffiti,
                skip_randao_verification: options.skip_randao_verification,
                builder_boost_factor,
            },
        );

        let execution_payload_header_handle =
            block_build_context.get_execution_payload_header(*public_key);

        let local_execution_payload_handle = block_build_context.get_local_execution_payload();

        let (validator_block, _block_rewards) = block_build_context
            .build_blinded_beacon_block(
                randao_reveal,
                execution_payload_header_handle,
                local_execution_payload_handle,
            )
            .await?
            .ok_or_else(|| anyhow!("failed to produce beacon block"))?;

        let _ = slot;
        Ok(validator_block)
    }

    async fn produce_aggregate(
        &self,
        slot: Slot,
        attestation_data_root: H256,
        committee_index: Option<CommitteeIndex>,
    ) -> Result<Attestation<P>> {
        let phase = self.chain_config.phase_at_slot::<P>(slot);
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        let attestation = if let Some(committee_index) = committee_index {
            self.attestation_agg_pool
                .best_aggregate_attestation_by_data_root_and_committee_index(
                    attestation_data_root,
                    epoch,
                    committee_index,
                )
                .await
        } else {
            self.attestation_agg_pool
                .best_aggregate_attestation_by_data_root(attestation_data_root, epoch)
                .await
        }
        .ok_or_else(|| anyhow!("aggregate attestation not found"))?;

        let block_root = attestation.data.beacon_block_root;
        let is_valid = self
            .controller
            .block_by_root(block_root)?
            .is_some_and(|block| block.is_valid());

        ensure!(
            is_valid,
            "block referenced by attestation is not yet validated for aggregation",
        );

        let attestation = if phase < Phase::Electra {
            Attestation::Phase0(attestation)
        } else {
            convert_to_electra_attestation(attestation).map(Attestation::Electra)?
        };

        Ok(attestation)
    }

    async fn produce_sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        ensure!(
            subcommittee_index < SyncCommitteeSubnetCount::U64,
            "subcommittee_index out of range",
        );

        let contribution = self
            .sync_committee_agg_pool
            .best_subcommittee_contribution(slot, beacon_block_root, subcommittee_index)
            .await;

        Ok(contribution)
    }

    async fn execution_payload_bid(
        &self,
        slot: Slot,
        builder_index: ValidatorIndex,
    ) -> Result<ExecutionPayloadBid<P>> {
        let current_slot = self.controller.slot();
        let beacon_state = if slot == current_slot {
            self.controller.preprocessed_state_at_current_slot().await?
        } else if slot == current_slot + 1 {
            self.controller.preprocessed_state_at_next_slot().await?
        } else {
            bail!("execution_payload_bid: invalid slot {slot}");
        };

        let _ = beacon_state
            .post_gloas()
            .ok_or_else(|| anyhow!("state is pre-Gloas"))?
            .builders()
            .get(builder_index)
            .map_err(|_| anyhow!("invalid builder_index {builder_index}"))?;

        let signed_bid = self
            .controller
            .get_payload_bid_from(slot, builder_index)
            .ok_or_else(|| anyhow!("execution payload bid not found"))?;

        Ok(signed_bid.message.clone())
    }
}

#[async_trait]
impl<P: Preset, W: Wait> BeaconPublisher<P> for LocalBeaconClient<P, W> {
    async fn publish_block(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        _validation: BroadcastValidation,
    ) -> Result<()> {
        ValidatorToP2p::PublishBeaconBlock(block).send(&self.p2p_tx);
        Ok(())
    }

    async fn publish_blob_sidecar(&self, sidecar: Arc<BlobSidecar<P>>) -> Result<()> {
        ValidatorToP2p::PublishBlobSidecar(sidecar).send(&self.p2p_tx);
        Ok(())
    }

    async fn publish_data_column_sidecar(&self, sidecar: Arc<DataColumnSidecar<P>>) -> Result<()> {
        ValidatorToP2p::PublishDataColumnSidecar(sidecar).send(&self.p2p_tx);
        Ok(())
    }

    async fn publish_sync_committee_message(
        &self,
        subnet_id: SubnetId,
        message: SyncCommitteeMessage,
    ) -> Result<()> {
        ValidatorToP2p::PublishSyncCommitteeMessage(Box::new((subnet_id, message)))
            .send(&self.p2p_tx);
        Ok(())
    }

    async fn publish_contribution_and_proof(
        &self,
        contribution: Box<SignedContributionAndProof<P>>,
        beacon_state: Arc<BeaconState<P>>,
    ) -> Result<()> {
        let aggregator_index = contribution.message.aggregator_index;
        let inner_contribution = contribution.message.contribution.clone();

        ValidatorToP2p::PublishContributionAndProof(contribution).send(&self.p2p_tx);

        self.sync_committee_agg_pool.add_own_contribution(
            aggregator_index,
            inner_contribution,
            beacon_state,
        );

        Ok(())
    }

    async fn publish_attester_slashing(&self, slashing: AttesterSlashing<P>) -> Result<()> {
        self.block_producer
            .add_new_attester_slashing(slashing)
            .await;
        Ok(())
    }

    async fn publish_proposer_slashing(&self, slashing: ProposerSlashing) -> Result<()> {
        self.block_producer
            .add_new_proposer_slashing(slashing)
            .await;
        Ok(())
    }

    async fn subscribe_beacon_committee(
        &self,
        subscriptions: Vec<BeaconCommitteeSubscription>,
    ) -> Result<()> {
        let current_state = self.controller.preprocessed_state_at_current_slot().await?;

        for subscription in &subscriptions {
            let BeaconCommitteeSubscription {
                committees_at_slot,
                slot,
                ..
            } = *subscription;

            let epoch = misc::compute_epoch_at_slot::<P>(slot);

            let (state, relative_epoch) = match accessors::relative_epoch(&current_state, epoch) {
                Ok(relative_epoch) => (current_state.clone_arc(), relative_epoch),
                Err(_) => {
                    let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
                    let state_with_status = self.resolve_state(StateId::Slot(start_slot))?;
                    (state_with_status.value, RelativeEpoch::Current)
                }
            };

            let computed = accessors::get_committee_count_per_slot(&state, relative_epoch);
            ensure!(
                committees_at_slot == computed,
                "committees_at_slot mismatch: requested={committees_at_slot} computed={computed}",
            );
        }

        let (sender, receiver) = oneshot::channel();
        ToSubnetService::UpdateBeaconCommitteeSubscriptions(
            self.controller.slot(),
            subscriptions,
            sender,
        )
        .send(&self.subnet_service_tx);

        receiver.await??;
        Ok(())
    }

    async fn subscribe_sync_committee(
        &self,
        subscriptions: Vec<SyncCommitteeSubscription>,
    ) -> Result<()> {
        let current_epoch = misc::compute_epoch_at_slot::<P>(self.controller.slot());
        ToSubnetService::UpdateSyncCommitteeSubscriptions(current_epoch, subscriptions)
            .send(&self.subnet_service_tx);
        Ok(())
    }

    async fn prepare_beacon_proposer(&self, preparations: Vec<ProposerPreparation>) -> Result<()> {
        let mapped: Vec<block_producer::ProposerData> = preparations
            .into_iter()
            .map(|preparation| block_producer::ProposerData {
                validator_index: preparation.validator_index,
                fee_recipient: preparation.fee_recipient,
            })
            .collect();
        let _ = ExecutionAddress::default();
        self.block_producer.add_new_prepared_proposers(mapped).await;
        Ok(())
    }

    async fn set_registered_validators(
        &self,
        pubkeys: Vec<PublicKeyBytes>,
        prepared_proposer_indices: Vec<ValidatorIndex>,
    ) -> Result<()> {
        ToSubnetService::SetRegisteredValidators(pubkeys, prepared_proposer_indices)
            .send(&self.subnet_service_tx);
        Ok(())
    }
}

impl<P: Preset, W: Wait> BeaconEventStream<P> for LocalBeaconClient<P, W> {
    fn subscribe(
        &self,
        topics: &[Topic],
    ) -> Pin<Box<dyn Stream<Item = Event<P>> + Send + 'static>> {
        let receivers = topics
            .iter()
            .map(|topic| BroadcastStream::new(self.event_channels.receiver_for(*topic)))
            .collect::<Vec<_>>();

        let merged = stream::select_all(receivers).filter_map(|item| async move { item.ok() });

        Box::pin(merged)
    }
}
