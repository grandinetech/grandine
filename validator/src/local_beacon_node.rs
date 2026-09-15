use core::ops::Range;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Result, anyhow, bail, ensure};
use block_producer::{BlockBuildOptions, ProposerData, ValidatorBlindedBlock};
use bls::{PublicKeyBytes, SignatureBytes};
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use dedicated_executor::DedicatedExecutor;
use derive_more::Display;
use fork_choice_control::Wait;
use fork_choice_store::{
    AttestationItem, AttestationOrigin, PayloadAttestationItem, PayloadAttestationOrigin,
};
use futures::channel::{mpsc::UnboundedSender, oneshot};
use helper_functions::{accessors, misc};
use http_api_utils::{
    ValidatorAttesterDutyResponse, ValidatorLivenessResponse, ValidatorPTCDutyResponse,
    ValidatorProposerDutyResponse, ValidatorSyncDutyResponse,
};
use itertools::Itertools as _;
use liveness_tracker::ApiToLiveness;
use logging::{debug_with_peers, warn_with_peers};
use operation_pools::{AttestationKey, convert_to_electra_attestation};
use p2p::{
    BeaconCommitteeSubscription, SyncCommitteeSubscription, ToSubnetService, ValidatorToP2p,
};
use prometheus_metrics::Metrics;
use signer::Signer;
use ssz::{ContiguousList, SszHash as _};
use std_ext::ArcExt as _;
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{
        Attestation, BeaconState, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
        SignedBlindedBeaconBlock,
    },
    config::Config,
    deneb::primitives::{Blob, KzgProof},
    gloas::{
        consts::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_STATUS_FULL},
        containers::{
            PayloadAttestationData, PayloadAttestationMessage, SignedExecutionPayloadEnvelope,
            SignedProposerPreferences,
        },
    },
    nonstandard::{KzgProofs, OwnAttestation, Phase, RelativeEpoch, WithBlobsAndMev, WithStatus},
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{CommitteeIndex, Epoch, H256, Slot, SubnetId, Uint256, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconBlock as _, BeaconState as _, PostAltairBeaconState},
};

use crate::{
    beacon_node_api::{
        AttesterDuties, BeaconNodeApi, EnvelopeContents, ProducedBlock, ProposerDuties, PtcDuties,
    },
    misc::LocalChain,
    slot_head::SlotHead,
    tasks::proposer_dependent_epoch,
    validator_config::ValidatorConfig,
};

const NAME: &str = "local";

/// What duties against the built-in beacon node are performed with, the same in every slot.
pub struct LocalContext<P: Preset, W: Wait> {
    pub chain: Arc<LocalChain<P, W>>,
    pub validator_config: Arc<ValidatorConfig>,
    pub signer: Arc<Signer>,
    pub p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    pub subnet_service_tx: UnboundedSender<ToSubnetService>,
    pub liveness_tx: Option<UnboundedSender<ApiToLiveness>>,
    pub metrics: Option<Arc<Metrics>>,
    pub dedicated_executor: Arc<DedicatedExecutor>,
}

#[derive(Clone, Display)]
#[display("{NAME}")]
pub struct LocalBeaconNode<P: Preset, W: Wait> {
    context: Arc<LocalContext<P, W>>,
    slot_head: SlotHead<P>,
    beacon_state: Arc<BeaconState<P>>,
    wait_group: W,
}

impl<P: Preset, W: Wait + Sync> LocalBeaconNode<P, W> {
    #[must_use]
    pub const fn head(&self) -> &SlotHead<P> {
        &self.slot_head
    }

    #[must_use]
    pub const fn state(&self) -> &Arc<BeaconState<P>> {
        &self.beacon_state
    }

    pub const fn new(
        context: Arc<LocalContext<P, W>>,
        slot_head: SlotHead<P>,
        beacon_state: Arc<BeaconState<P>>,
        wait_group: W,
    ) -> Self {
        Self {
            context,
            slot_head,
            beacon_state,
            wait_group,
        }
    }

    pub fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let state = self.beacon_state.as_ref();
        // `slots` must lie within one epoch, as the duties carry a single dependent root.
        let epoch = misc::compute_epoch_at_slot::<P>(slots.start);
        let dependent_root = self.dependent_root_at(epoch)?;
        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        let duties = slots
            .map(|slot| duties_at_slot(state, slot, &indices))
            .flatten_ok()
            .try_collect()?;

        Ok(AttesterDuties {
            dependent_root,
            duties,
        })
    }

    pub const fn head_block_root(&self) -> H256 {
        self.slot_head.beacon_block_root
    }

    async fn publish_blob_data(
        &self,
        block: &Arc<SignedBeaconBlock<P>>,
        blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
        kzg_proofs: Option<KzgProofs<P>>,
    ) -> Result<()> {
        if self.slot_head.phase().is_peerdas_activated() {
            let data_column_sidecars = eip_7594::construct_data_column_sidecars_from_blobs(
                block.clone_arc().into(),
                blobs.into_iter(),
                kzg_proofs
                    .unwrap_or_else(KzgProofs::empty_fulu)
                    .into_iter()
                    .collect_vec(),
                self.context.chain.controller.store_config().kzg_backend,
                self.context.metrics.clone(),
                self.context.dedicated_executor.clone_arc(),
            )
            .await?;

            self.publish_data_column_sidecars(data_column_sidecars)
                .await;
        } else {
            for blob_sidecar in misc::construct_blob_sidecars(
                block,
                blobs,
                kzg_proofs.unwrap_or_else(KzgProofs::empty_deneb),
            )? {
                let blob_sidecar = Arc::new(blob_sidecar);

                self.context
                    .chain
                    .controller
                    .on_own_blob_sidecar(self.wait_group.clone(), blob_sidecar.clone_arc());
            }
        }

        Ok(())
    }

    async fn publish_data_column_sidecars(
        &self,
        data_column_sidecars: Vec<Arc<DataColumnSidecar<P>>>,
    ) {
        for data_column_sidecar in data_column_sidecars {
            if self
                .context
                .chain
                .controller
                .sampling_columns()
                .into_iter()
                .contains(&data_column_sidecar.index())
            {
                self.context
                    .chain
                    .controller
                    .on_own_data_column_sidecar(
                        self.wait_group.clone(),
                        data_column_sidecar.clone_arc(),
                    )
                    .await;
            }

            ValidatorToP2p::PublishDataColumnSidecar(data_column_sidecar)
                .send(&self.context.p2p_tx);
        }
    }

    fn dependent_root_at(&self, epoch: Epoch) -> Result<H256> {
        self.context
            .chain
            .controller
            .dependent_root(&self.beacon_state, misc::previous_epoch(epoch))
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for LocalBeaconNode<P, W> {
    async fn liveness(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLivenessResponse>> {
        let liveness_tx = self.context.liveness_tx.as_ref().ok_or_else(|| {
            anyhow!("liveness tracking is disabled; enable it with --track-liveness")
        })?;

        let (sender, receiver) = oneshot::channel();

        ApiToLiveness::CheckLiveness(sender, epoch, validator_indices.to_vec()).send(liveness_tx);

        let liveness = receiver.await??;

        Ok(liveness
            .into_iter()
            .map(|(index, is_live)| ValidatorLivenessResponse { index, is_live })
            .collect())
    }

    async fn dependent_root(&self, epoch: Epoch, _validator_index: ValidatorIndex) -> Result<H256> {
        self.dependent_root_at(epoch)
    }

    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let slot_head = &self.slot_head;
        let phase = slot_head.phase();

        let index = if phase >= Phase::Gloas {
            // The payload present vote.
            // See <https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/gloas/validator.md#attestation>
            if self.beacon_state.latest_block_header().slot == slot_head.slot() {
                0
            } else {
                let (head_root, payload_status) = self
                    .context
                    .chain
                    .controller
                    .head_root_with_payload_status();

                // The status belongs to fork choice's head, which may have moved since
                // `slot_head` was taken. Signalling a payload the attestation does not point at
                // would put weight behind the wrong branch, so fall back to empty.
                u64::from(
                    head_root == slot_head.beacon_block_root
                        && payload_status == PAYLOAD_STATUS_FULL,
                )
            }
        } else if phase >= Phase::Electra {
            0
        } else {
            committee_index
        };

        let target = tokio::task::block_in_place(|| Checkpoint {
            epoch: slot_head.current_epoch(),
            root: accessors::epoch_boundary_block_root(
                &self.beacon_state,
                slot_head.beacon_block_root,
            ),
        });

        Ok(AttestationData {
            slot,
            index,
            beacon_block_root: slot_head.beacon_block_root,
            source: self.beacon_state.current_justified_checkpoint(),
            target,
        })
    }

    async fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<P>> {
        let aggregate = self
            .context
            .chain
            .attestation_agg_pool
            .best_aggregate_attestation(AttestationKey {
                data,
                committee_index,
            })
            .await
            .ok_or_else(|| {
                anyhow!(
                    "no aggregate attestation for committee {committee_index} in slot {}",
                    data.slot,
                )
            })?;

        let phase = self.slot_head.config.phase_at_slot::<P>(data.slot);

        if phase < Phase::Electra {
            Ok(Attestation::Phase0(aggregate.into_phase0_attestation()))
        } else if phase < Phase::Gloas {
            convert_to_electra_attestation(aggregate).map(Attestation::Electra)
        } else {
            convert_to_electra_attestation(aggregate)
                .map(|aggregate| Attestation::Gloas(aggregate.into()))
        }
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        for own_attestation in attestations {
            let OwnAttestation {
                validator_index,
                attestation,
                ..
            } = own_attestation;

            let committee_index = misc::committee_index(attestation);
            let attestation = Arc::new(attestation.clone());
            let subnet_id =
                subnet_id::<P>(&self.beacon_state, attestation.data().slot, committee_index)?;

            self.context.chain.controller.on_singular_attestation(
                self.wait_group.clone(),
                AttestationItem::unverified(
                    attestation.clone_arc(),
                    AttestationOrigin::Own(subnet_id),
                ),
            );

            ValidatorToP2p::PublishSingularAttestation(attestation.clone_arc(), subnet_id)
                .send(&self.context.p2p_tx);

            self.context.chain.attestation_agg_pool.insert_attestation(
                self.wait_group.clone(),
                attestation,
                Some(*validator_index),
            );
        }

        Ok(())
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        for aggregate_and_proof in aggregates_and_proofs {
            let attestation = Arc::new(aggregate_and_proof.aggregate());

            self.context.chain.attestation_agg_pool.insert_attestation(
                self.wait_group.clone(),
                attestation,
                None,
            );

            ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof.clone_arc())
                .send(&self.context.p2p_tx);
        }

        Ok(())
    }

    async fn subscribe_to_beacon_committees(
        &self,
        current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();

        ToSubnetService::UpdateBeaconCommitteeSubscriptions(
            current_slot,
            subscriptions.to_vec(),
            sender,
        )
        .send(&self.context.subnet_service_tx);

        receiver.await?
    }

    async fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> Result<HashMap<PublicKeyBytes, ValidatorIndex>> {
        let state = self.beacon_state.as_ref();

        Ok(public_keys
            .iter()
            .filter_map(|public_key| {
                let validator_index = accessors::index_of_public_key(state, public_key)?;
                Some((*public_key, validator_index))
            })
            .collect())
    }

    async fn slot_head(&self, _slot: Slot) -> Result<Option<SlotHead<P>>> {
        Ok(Some(self.slot_head.clone()))
    }

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorSyncDutyResponse>> {
        let Some(state) = self.beacon_state.post_altair() else {
            // Erring rather than answering with no duties keeps the answer out of the cache.
            ensure!(
                epoch
                    < self
                        .context
                        .chain
                        .controller
                        .chain_config()
                        .altair_fork_epoch,
                "sync committee duties for epoch {epoch} are not known to a pre-Altair state",
            );

            return Ok(vec![]);
        };

        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        sync_duties_at_epoch(state, epoch, &indices)
    }

    async fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> Result<()> {
        for (subcommittee_index, messages) in messages {
            for message in messages {
                ValidatorToP2p::PublishSyncCommitteeMessage(Box::new((
                    *subcommittee_index,
                    *message,
                )))
                .send(&self.context.p2p_tx);
            }

            self.context
                .chain
                .sync_committee_agg_pool
                .aggregate_own_messages(
                    self.wait_group.clone(),
                    messages.clone(),
                    *subcommittee_index,
                    self.beacon_state.clone_arc(),
                );
        }

        Ok(())
    }

    async fn subscribe_to_sync_committees(
        &self,
        current_epoch: Epoch,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> Result<()> {
        ToSubnetService::UpdateSyncCommitteeSubscriptions(current_epoch, subscriptions.to_vec())
            .send(&self.context.subnet_service_tx);

        Ok(())
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        Ok(self
            .context
            .chain
            .sync_committee_agg_pool
            .best_subcommittee_contribution(slot, beacon_block_root, subcommittee_index)
            .await)
    }

    async fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> Result<()> {
        for contribution_and_proof in contributions_and_proofs {
            ValidatorToP2p::PublishContributionAndProof(Box::new(*contribution_and_proof))
                .send(&self.context.p2p_tx);

            self.context
                .chain
                .sync_committee_agg_pool
                .add_own_contribution(
                    contribution_and_proof.message.aggregator_index,
                    contribution_and_proof.message.contribution,
                    self.beacon_state.clone_arc(),
                );
        }

        Ok(())
    }

    async fn ptc_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<PtcDuties> {
        let dependent_root = self.dependent_root_at(epoch)?;
        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        let duties = tokio::task::block_in_place(|| {
            ptc_duties_at_epoch(
                &self.slot_head.config,
                self.beacon_state.as_ref(),
                epoch,
                &indices,
            )
        })?;

        Ok(PtcDuties {
            dependent_root,
            duties,
        })
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        let state = self.beacon_state.as_ref();

        let dependent_root =
            self.dependent_root_at(proposer_dependent_epoch(&self.slot_head.config, epoch))?;

        let duties = misc::slots_in_epoch::<P>(epoch)?
            .map(|slot| {
                let validator_index = accessors::get_beacon_proposer_index_at_slot(
                    &self.slot_head.config,
                    state,
                    slot,
                )?;

                Ok(ValidatorProposerDutyResponse {
                    pubkey: *accessors::public_key(state, validator_index)?,
                    validator_index,
                    slot,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ProposerDuties {
            dependent_root,
            duties,
        })
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        let Some(block_with_root) = self
            .context
            .chain
            .controller
            .block_by_slot(slot)?
            .map(WithStatus::value)
        else {
            return Ok(None);
        };

        let beacon_block_root = block_with_root.root;

        let blob_data_available = self
            .context
            .chain
            .controller
            .indices_of_missing_data_columns(&block_with_root.block)
            .is_empty();

        Ok(Some(PayloadAttestationData {
            beacon_block_root,
            slot,
            payload_present: self
                .context
                .chain
                .controller
                .is_payload_present_timely(beacon_block_root),
            blob_data_available,
        }))
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        for message in messages {
            self.context.chain.controller.on_payload_attestation(
                self.wait_group.clone(),
                PayloadAttestationItem::unverified(
                    Arc::new(message.clone_arc().into()),
                    PayloadAttestationOrigin::Own,
                ),
            );

            ValidatorToP2p::PublishPayloadAttestation(message.clone_arc())
                .send(&self.context.p2p_tx);
        }

        let beacon_state = &self.beacon_state;

        let next_proposer_index =
            tokio::task::block_in_place(|| self.slot_head.next_proposer_index(beacon_state))?;

        let public_key = accessors::public_key(beacon_state.as_ref(), next_proposer_index)?;

        // The messages are only aggregated when an own validator proposes next.
        if self.context.signer.load().has_key(*public_key) {
            self.context
                .chain
                .payload_attestation_agg_pool
                .aggregate_own_messages(
                    self.wait_group.clone(),
                    messages.iter().map(|message| **message).collect(),
                    beacon_state.clone_arc(),
                );
        }

        Ok(())
    }

    async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        graffiti: Option<H256>,
        builder_boost_factor: Uint256,
    ) -> Result<ProducedBlock<P>> {
        ensure!(
            slot == self.slot_head.slot(),
            "the built-in beacon node produces blocks for slot {} only, not slot {slot}",
            self.slot_head.slot(),
        );

        let beacon_state = &self.beacon_state;
        let proposer_index =
            tokio::task::block_in_place(|| self.slot_head.proposer_index(beacon_state))?;
        let public_key = *accessors::public_key(beacon_state.as_ref(), proposer_index)?;

        let block_build_context = self.context.chain.block_producer.new_build_context(
            beacon_state.clone_arc(),
            self.slot_head.beacon_block_root,
            proposer_index,
            BlockBuildOptions {
                graffiti,
                disable_blockprint_graffiti: self
                    .context
                    .validator_config
                    .disable_blockprint_graffiti,
                builder_boost_factor,
                ..BlockBuildOptions::default()
            },
        );

        let execution_payload_header_handle =
            block_build_context.get_execution_payload_header(public_key);

        let local_execution_payload_handle = block_build_context.get_local_execution_payload();

        let Some((
            WithBlobsAndMev {
                value: block,
                proofs,
                blobs,
                ..
            },
            _block_rewards,
        )) = block_build_context
            .build_blinded_beacon_block(
                randao_reveal,
                execution_payload_header_handle,
                local_execution_payload_handle,
            )
            .await?
        else {
            bail!("no block could be built for slot {slot}");
        };

        let envelope_contents = match &block {
            ValidatorBlindedBlock::BeaconBlock(block)
                if block
                    .payload_bid()
                    .is_some_and(|bid| bid.builder_index == BUILDER_INDEX_SELF_BUILD) =>
            {
                match self
                    .context
                    .chain
                    .block_producer
                    .build_local_execution_payload_envelope_contents(
                        block.hash_tree_root(),
                        block.parent_root(),
                    )
                    .await
                {
                    Some((envelope, blobs, kzg_proofs)) => Some(EnvelopeContents {
                        envelope,
                        kzg_proofs: ContiguousList::try_from_iter(kzg_proofs)?,
                        blobs,
                    }),
                    None => {
                        warn_with_peers!(
                            "the payload of the self-built block for slot {slot} is missing, \
                             so the block is published without it",
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        // The blobs of a self-built payload travel with its envelope rather than the block.
        Ok(match envelope_contents {
            Some(_) => ProducedBlock {
                block,
                kzg_proofs: None,
                blobs: None,
                envelope_contents,
            },
            // From Gloas on a block without its own payload commits to a builder's blobs.
            None if self.slot_head.phase() >= Phase::Gloas => ProducedBlock::without_blobs(block),
            None => ProducedBlock {
                block,
                kzg_proofs: proofs,
                blobs,
                envelope_contents: None,
            },
        })
    }

    async fn publish_block(
        &self,
        signed_block: &Arc<SignedBeaconBlock<P>>,
        kzg_proofs: Option<&KzgProofs<P>>,
        blobs: Option<&ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Result<()> {
        if let Some(blobs) = blobs
            && !blobs.is_empty()
        {
            self.publish_blob_data(signed_block, blobs.clone(), kzg_proofs.cloned())
                .await?;
        }

        self.context
            .chain
            .controller
            .on_own_block(self.wait_group.clone(), signed_block.clone_arc());

        ValidatorToP2p::PublishBeaconBlock(signed_block.clone_arc()).send(&self.context.p2p_tx);

        Ok(())
    }

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock<P>,
    ) -> Result<()> {
        let Some(builder_api) = &self.context.chain.builder_api else {
            bail!("no builder API is configured to submit the blinded block to");
        };

        let chain_config = self.context.chain.controller.chain_config();
        let genesis_time = self.context.chain.controller.genesis_time();

        if self.slot_head.phase() >= Phase::Fulu
            && builder_api
                .post_blinded_block_post_fulu(chain_config, genesis_time, signed_block)
                .await
                .is_ok()
        {
            debug_with_peers!("submitted blinded block to the builder node");

            return Ok(());
        }

        let WithBlobsAndMev {
            value: execution_payload,
            proofs,
            blobs,
            ..
        } = match builder_api
            .post_blinded_block(chain_config, genesis_time, signed_block)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                // A builder that times out is expected to publish the block anyway, and nothing
                // else can be done with it without risking a slashing.
                if error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)
                {
                    debug_with_peers!(
                        "failed to post blinded block to the builder node: {error:?}"
                    );

                    return Ok(());
                }

                bail!("failed to post blinded block to the builder node: {error:?}");
            }
        };

        debug_with_peers!(
            "received execution payload from the builder node: {execution_payload:?}"
        );

        let (message, signature) = signed_block.clone().split();

        let signed_block = message
            .with_execution_payload(execution_payload)?
            .with_signature(signature)
            .pipe(Arc::new);

        self.publish_block(&signed_block, proofs.as_ref(), blobs.as_ref())
            .await
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &Arc<SignedExecutionPayloadEnvelope<P>>,
        kzg_proofs: &ContiguousList<KzgProof, P::MaxCellProofsPerBlock>,
        blobs: &ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
    ) -> Result<()> {
        let envelope = &signed_envelope.message;

        if !blobs.is_empty() {
            let data_column_sidecars = eip_7594::construct_data_column_sidecars_from_blobs(
                (envelope.beacon_block_root, envelope.payload.slot_number).into(),
                blobs.clone().into_iter(),
                kzg_proofs.iter().copied().collect_vec(),
                self.context.chain.controller.store_config().kzg_backend,
                self.context.metrics.clone(),
                self.context.dedicated_executor.clone_arc(),
            )
            .await?;

            self.publish_data_column_sidecars(data_column_sidecars)
                .await;
        }

        self.context
            .chain
            .controller
            .on_own_execution_payload_envelope(signed_envelope.clone_arc());

        ValidatorToP2p::PublishExecutionPayloadEnvelope(signed_envelope.clone_arc())
            .send(&self.context.p2p_tx);

        Ok(())
    }

    async fn prepare_beacon_proposer(&self, _proposers: &[ProposerData]) -> Result<()> {
        Ok(())
    }

    async fn register_validators(
        &self,
        _registrations: &[SignedValidatorRegistrationV1],
    ) -> Result<()> {
        Ok(())
    }

    async fn publish_proposer_preferences(
        &self,
        preferences: &[Arc<SignedProposerPreferences>],
    ) -> Result<()> {
        for signed_preferences in preferences {
            // Pass into own fork-choice store so bids for this slot pass the
            // `accepted_proposer_preferences` gate in validate_execution_payload_bid.
            self.context
                .chain
                .controller
                .on_own_proposer_preferences(signed_preferences.clone_arc());

            ValidatorToP2p::PublishProposerPreferences(signed_preferences.clone_arc())
                .send(&self.context.p2p_tx);
        }

        Ok(())
    }
}

pub fn ptc_duties_at_epoch<P: Preset>(
    config: &Config,
    state: &BeaconState<P>,
    epoch: Epoch,
    indices: &HashSet<ValidatorIndex>,
) -> Result<Vec<ValidatorPTCDutyResponse>> {
    // The state carries the committees an epoch ahead through the seed lookahead.
    misc::slots_in_epoch::<P>(epoch)?
        .map(|slot| {
            accessors::get_ptc(config, state, slot)?
                .into_iter()
                .filter(|validator_index| indices.contains(validator_index))
                .map(|validator_index| {
                    let pubkey = *accessors::public_key(state, validator_index)?;

                    Ok(ValidatorPTCDutyResponse {
                        pubkey,
                        validator_index,
                        slot,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .flatten_ok()
        .try_collect()
}

pub fn sync_duties_at_epoch<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
    epoch: Epoch,
    indices: &HashSet<ValidatorIndex>,
) -> Result<Vec<ValidatorSyncDutyResponse>> {
    let period = misc::sync_committee_period::<P>(epoch);
    let current_period = misc::sync_committee_period::<P>(accessors::get_current_epoch(state));

    // The state carries only the current period's committee and the next.
    let committee = if period == current_period {
        state.current_sync_committee()
    } else if period == current_period.saturating_add(1) {
        state.next_sync_committee()
    } else {
        return Err(anyhow!(
            "sync committee of period {period} is not known to a state in period {current_period}",
        ));
    };

    let mut duties = BTreeMap::<ValidatorIndex, (PublicKeyBytes, Vec<usize>)>::new();

    for (position, public_key) in committee.pubkeys.iter().enumerate() {
        let Some(validator_index) = accessors::index_of_public_key(state, public_key) else {
            continue;
        };

        if !indices.contains(&validator_index) {
            continue;
        }

        duties
            .entry(validator_index)
            .or_insert_with(|| (*public_key, vec![]))
            .1
            .push(position);
    }

    Ok(duties
        .into_iter()
        .map(
            |(validator_index, (pubkey, validator_sync_committee_indices))| {
                ValidatorSyncDutyResponse {
                    pubkey,
                    validator_index,
                    validator_sync_committee_indices,
                }
            },
        )
        .collect())
}

fn subnet_id<P: Preset>(
    beacon_state: &BeaconState<P>,
    slot: Slot,
    committee_index: CommitteeIndex,
) -> Result<SubnetId> {
    let committees_per_slot =
        accessors::get_committee_count_per_slot(beacon_state, RelativeEpoch::Current)?;

    misc::compute_subnet_for_attestation::<P>(committees_per_slot, slot, committee_index)
}

pub fn duties_at_slot<P: Preset>(
    state: &BeaconState<P>,
    slot: Slot,
    indices: &HashSet<ValidatorIndex>,
) -> Result<Vec<ValidatorAttesterDutyResponse>> {
    let epoch = misc::compute_epoch_at_slot::<P>(slot);
    let relative_epoch = accessors::relative_epoch(state, epoch)?;
    let committees_at_slot = accessors::get_committee_count_per_slot(state, relative_epoch)?;

    accessors::beacon_committees(state, slot)?
        .zip(0..)
        .flat_map(|(committee, committee_index)| {
            let committee_length = committee.len();

            committee
                .into_iter()
                .enumerate()
                .filter(|(_, validator_index)| indices.contains(validator_index))
                .map(move |(validator_committee_index, validator_index)| {
                    let pubkey = *accessors::public_key(state, validator_index)?;

                    Ok(ValidatorAttesterDutyResponse {
                        committee_index,
                        committee_length,
                        committees_at_slot,
                        pubkey,
                        slot,
                        validator_committee_index,
                        validator_index,
                    })
                })
        })
        .collect()
}
