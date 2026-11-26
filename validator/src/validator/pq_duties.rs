//! Duties signed with XMSS, performed through the built-in beacon node.
//!
//! TODO(PQ): Perform PQ duties through remote beacon nodes and Web3Signer.

use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, bail, ensure};
use block_producer::ValidatorBlindedBlock;
use bls::{PublicKeyBytes, Signature};
use fork_choice_control::Wait;
use helper_functions::{accessors, misc, pq, signing::SignForSingleFork};
use logging::{info_with_peers, warn_with_peers};
use slashing_protection::Attestation as SlashingProtectionAttestation;
use ssz::{ContiguousList, SszHash as _};
use std_ext::ArcExt as _;
use try_from_iterator::TryFromIterator as _;
use types::{
    combined::{
        Attestation, BeaconBlock, BeaconState, RandaoReveal, SignedAggregateAndProof,
        SignedBeaconBlock, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    gloas::containers::{PayloadAttestationData, ProposerPreferences},
    nonstandard::OwnAttestation,
    phase0::{
        consts::DOMAIN_AGGREGATE_AND_PROOF,
        containers::AttestationData,
        primitives::{CommitteeIndex, H256, Uint256},
    },
    pq::{
        consts::{
            LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_BEACON_PROPOSER,
            LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE, LEAF_OFFSET_PROPOSER_PREFERENCES,
            LEAF_OFFSET_PTC_ATTESTER,
        },
        containers::{
            AggregateAndProof as PqAggregateAndProof,
            PayloadAttestationMessage as PqPayloadAttestationMessage,
            SignedAggregateAndProof as PqSignedAggregateAndProof,
            SignedBeaconBlock as PqSignedBeaconBlock,
            SignedExecutionPayloadEnvelope as PqSignedExecutionPayloadEnvelope,
            SignedProposerPreferences as PqSignedProposerPreferences,
            SingleAttestation as PqSingleAttestation,
        },
    },
    preset::Preset,
    traits::ExecutionPayloadEnvelope as ExecutionPayloadEnvelopeTrait,
};

use crate::{
    beacon_node_api::BeaconNodeApi as _, beacon_nodes::BeaconNodes,
    own_beacon_committee_members::BeaconCommitteeMember, own_ptc_members::PTCMember,
    slot_head::SlotHead, validator::Validator,
};

impl<P: Preset, W: Wait + Sync> Validator<P, W> {
    /// [`get_attestation_signature`] at the attestation leaf of the target epoch, for each member.
    ///
    /// [`get_attestation_signature`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#signature-1
    pub(super) async fn own_pq_singular_attestations(
        &self,
        slot_head: &SlotHead<P>,
        own_members: &[BeaconCommitteeMember],
        attestation_data: &HashMap<CommitteeIndex, AttestationData>,
        beacon_nodes: &BeaconNodes<P, W>,
    ) -> Result<Vec<OwnAttestation<P>>> {
        // From Electra on a single request covers every member.
        let Some(data) = attestation_data.get(&0).copied() else {
            return Ok(vec![]);
        };

        let config = &self.chain_source.chain_config;
        let signing_root =
            SignForSingleFork::<P>::signing_root_from_fork_info(&data, config, slot_head.fork_info);
        let leaf_index = pq::compute_xmss_attestation_leaf_index(data.target.epoch)?;

        let members = own_members
            .iter()
            .filter(|member| self.signer.pq_key(member.public_key).is_some())
            .collect::<Vec<_>>();

        // Surround and double votes are refused as for BLS keys.
        let permitted = self
            .slashing_protector
            .lock()
            .await
            .validate_and_store_own_attestations(
                slot_head.current_epoch(),
                members.iter().map(|member| {
                    let attestation = SlashingProtectionAttestation {
                        source_epoch: data.source.epoch,
                        target_epoch: data.target.epoch,
                        signing_root: Some(signing_root),
                    };

                    (attestation, member.public_key)
                }),
            )?;

        let members = members
            .into_iter()
            .zip(permitted)
            .filter_map(|(member, permitted)| permitted.map(|_| member))
            .collect::<Vec<_>>();

        // Each attestation is published as soon as it is signed rather than after the slowest.
        let (signed_tx, mut signed_rx) = tokio::sync::mpsc::unbounded_channel();

        let signing = self.signer.sign_pq_streaming(
            members
                .iter()
                .map(|member| (member.public_key, leaf_index, signing_root))
                .collect(),
            &self.slashing_protector,
            move |index, signature| {
                signed_tx.send((index, signature.clone())).ok();
            },
        );

        let publishing = async {
            let mut own_attestations = vec![];

            while let Some((index, signature)) = signed_rx.recv().await {
                let member = members[index];

                let own_attestation = OwnAttestation {
                    validator_index: member.validator_index,
                    attestation: Attestation::PqSingle(PqSingleAttestation {
                        committee_index: member.committee_index,
                        attester_index: member.validator_index,
                        data,
                        signature,
                    }),
                    // Only BLS attestations carry this signature.
                    signature: Signature::default(),
                };

                if let Err(error) = beacon_nodes
                    .publish_singular_attestations(core::slice::from_ref(&own_attestation))
                    .await
                {
                    warn_with_peers!("failed to publish PQ attestation: {error:?}");
                }

                own_attestations.push(own_attestation);
            }

            own_attestations
        };

        let (signed, own_attestations) = tokio::join!(signing, publishing);

        signed?;

        Ok(own_attestations)
    }

    /// Proposes with the VRF proof of the slot as the RANDAO reveal, signs the block at the
    /// proposer leaf of the slot and the self-built envelope at the envelope leaf.
    #[expect(clippy::too_many_lines)]
    pub(super) async fn propose_pq(&mut self, beacon_nodes: &BeaconNodes<P, W>) -> Result<()> {
        let BeaconNodes::Local(local) = beacon_nodes else {
            warn_with_peers!("PQ blocks are proposed only through the built-in beacon node");
            return Ok(());
        };

        let slot_head = beacon_nodes.head();
        let slot = slot_head.slot();
        let Some(beacon_state) = beacon_nodes.state() else {
            return Ok(());
        };
        let config = self.chain_source.chain_config.clone_arc();

        let proposer_index =
            tokio::task::block_in_place(|| slot_head.proposer_index(beacon_state))?;

        let state_public_key = *accessors::public_key(beacon_state.as_ref(), proposer_index)?;

        let Some(public_key) = self.signer.bls_public_key_of(state_public_key) else {
            return Ok(());
        };

        let Some(pq_key) = self.signer.pq_key(public_key) else {
            return Ok(());
        };

        if !pq_key.has_vrf_tree() {
            warn_with_peers!(
                "validator {proposer_index} cannot propose in slot {slot}: \
                 its VRF tree is still being built",
            );
            return Ok(());
        }

        info_with_peers!(
            "starting PQ block proposal for validator {proposer_index} at slot {slot}"
        );

        let vrf_proof = tokio::task::spawn_blocking(move || pq_key.vrf_proof(slot)).await??;

        let graffiti = self
            .proposer_configs
            .graffiti_bytes(public_key)?
            .or_else(|| self.next_graffiti());

        // TODO(PQ): Ask builders for bids once PQ blocks select them.
        let produced = local
            .produce_block_with_reveal(
                slot,
                RandaoReveal::Vrf(Box::new(vrf_proof)),
                graffiti,
                Uint256::ZERO,
                0,
                &ContiguousList::default(),
            )
            .await?;

        let ValidatorBlindedBlock::BeaconBlock(BeaconBlock::Pq(block)) = produced.block else {
            bail!("the built-in beacon node produced a block that is not a PQ one for slot {slot}");
        };

        ensure!(
            (block.slot, block.proposer_index) == (slot, proposer_index),
            "the built-in beacon node produced a block for slot {} and proposer {} \
             where slot {slot} and proposer {proposer_index} were expected",
            block.slot,
            block.proposer_index,
        );

        let signing_root =
            SignForSingleFork::<P>::signing_root(block.as_ref(), &config, beacon_state.as_ref());
        let leaf_index = pq::compute_xmss_leaf_index(slot, LEAF_OFFSET_BEACON_PROPOSER)?;

        let Some(signature) = sign_one(self, public_key, leaf_index, signing_root).await? else {
            return Ok(());
        };

        let block_root = block.hash_tree_root();
        let parent_root = block.parent_root;

        let signed_block = Arc::new(SignedBeaconBlock::Pq(PqSignedBeaconBlock {
            message: block,
            signature,
        }));

        info_with_peers!(
            "validator {proposer_index} proposing PQ beacon block with root {block_root:?} \
             in slot {slot}",
        );

        local.publish_block(&signed_block, None, None, None).await?;

        let Some(block_producer) = self.chain_source.block_producer() else {
            return Ok(());
        };

        let Some((envelope, blobs, kzg_proofs)) = block_producer
            .build_local_pq_execution_payload_envelope_contents(block_root, parent_root)
            .await
        else {
            warn_with_peers!(
                "the payload of the self-built PQ block for slot {slot} is missing, \
                 so the block is published without it",
            );
            return Ok(());
        };

        let envelope_message: &dyn ExecutionPayloadEnvelopeTrait<P> = &envelope;
        let signing_root =
            SignForSingleFork::<P>::signing_root(envelope_message, &config, beacon_state.as_ref());
        let leaf_index = pq::compute_xmss_leaf_index(slot, LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE)?;

        let Some(signature) = sign_one(self, public_key, leaf_index, signing_root).await? else {
            return Ok(());
        };

        let signed_envelope = Arc::new(SignedExecutionPayloadEnvelope::from(
            PqSignedExecutionPayloadEnvelope {
                message: envelope,
                signature,
            },
        ));

        local
            .publish_combined_execution_payload_envelope(
                signed_envelope,
                &ContiguousList::try_from_iter(kzg_proofs)?,
                &blobs,
            )
            .await
    }

    /// [`get_payload_attestation_message_signature`] at the PTC leaf of the slot.
    ///
    /// [`get_payload_attestation_message_signature`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#constructing-the-payloadattestationmessage
    pub(super) async fn attest_payload_pq(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        data: PayloadAttestationData,
        own_members: &[PTCMember],
    ) -> Result<()> {
        let BeaconNodes::Local(local) = beacon_nodes else {
            warn_with_peers!(
                "PQ payload attestations are made only through the built-in beacon node"
            );
            return Ok(());
        };

        let slot_head = beacon_nodes.head();

        // Marks the slot as attested, like the BLS messages.
        self.own_payload_attestations.get_or_init(Vec::new);

        let signing_root = SignForSingleFork::<P>::signing_root_from_fork_info(
            &data,
            &self.chain_source.chain_config,
            slot_head.fork_info,
        );
        let leaf_index = pq::compute_xmss_leaf_index(data.slot, LEAF_OFFSET_PTC_ATTESTER)?;

        // Each vote is published as soon as it is signed rather than after the slowest.
        let (signed_tx, mut signed_rx) = tokio::sync::mpsc::unbounded_channel();

        let signing = self.signer.sign_pq_streaming(
            own_members
                .iter()
                .map(|member| (member.public_key, leaf_index, signing_root))
                .collect(),
            &self.slashing_protector,
            move |index, signature| {
                signed_tx.send((index, signature.clone())).ok();
            },
        );

        let publishing = async {
            while let Some((index, signature)) = signed_rx.recv().await {
                let message = Arc::new(PqPayloadAttestationMessage {
                    validator_index: own_members[index].validator_index,
                    data,
                    signature,
                });

                local.publish_pq_payload_attestations(&[message]);
            }
        };

        let (signed, ()) = tokio::join!(signing, publishing);

        signed.map(|_| ())
    }

    /// [`get_signed_proposer_preferences`] at the preferences leaf of the proposal slot.
    ///
    /// The leaf is the same for every dependent root, so preferences that differ from ones
    /// already signed for the slot are refused.
    ///
    /// [`get_signed_proposer_preferences`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#broadcasting-signedproposerpreferences
    pub(super) fn publish_pq_proposer_preferences(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        preferences: Vec<(PublicKeyBytes, ProposerPreferences)>,
    ) {
        let BeaconNodes::Local(local) = beacon_nodes else {
            warn_with_peers!(
                "PQ proposer preferences are published only through the built-in beacon node"
            );
            return;
        };

        let local = local.clone();
        let config = self.chain_source.chain_config.clone_arc();
        let fork_info = beacon_nodes.head().fork_info;
        let signer = self.signer.clone_arc();
        let slashing_protector = self.slashing_protector.clone_arc();
        let published = self.published_proposer_preferences.clone_arc();

        tokio::spawn(async move {
            let requests = preferences
                .iter()
                .map(|(public_key, preferences)| {
                    let signing_root = SignForSingleFork::<P>::signing_root_from_fork_info(
                        preferences,
                        &config,
                        fork_info,
                    );
                    let leaf_index = pq::compute_xmss_leaf_index(
                        preferences.proposal_slot,
                        LEAF_OFFSET_PROPOSER_PREFERENCES,
                    )?;

                    Ok((*public_key, leaf_index, signing_root))
                })
                .collect::<Result<Vec<_>>>();

            let signatures = match requests {
                Ok(requests) => signer.sign_pq(requests, &slashing_protector).await,
                Err(error) => Err(error),
            };

            let signatures = match signatures {
                Ok(signatures) => signatures,
                Err(error) => {
                    warn_with_peers!("failed to sign PQ proposer preferences: {error:?}");
                    return;
                }
            };

            let signed_preferences = preferences
                .into_iter()
                .zip(signatures)
                .filter_map(|((_, message), signature)| {
                    Some(Arc::new(SignedProposerPreferences::Pq(
                        PqSignedProposerPreferences {
                            message,
                            signature: signature?,
                        },
                    )))
                })
                .collect::<Vec<_>>();

            local.publish_combined_proposer_preferences(&signed_preferences);

            published
                .lock()
                .await
                .extend(signed_preferences.iter().map(|signed| {
                    let ProposerPreferences {
                        dependent_root,
                        proposal_slot,
                        validator_index,
                        ..
                    } = *signed.message();

                    (dependent_root, proposal_slot, validator_index)
                }));
        });
    }

    /// Signs and publishes the proven aggregate of each committee an own validator aggregates
    /// for, at the aggregator's staggered `get_aggregate_due_ms`.
    ///
    /// TODO(PQ): Skip aggregates whose attesters a received aggregate already has
    /// (`should_broadcast_aggregate`).
    #[expect(clippy::too_many_lines)]
    pub(super) async fn publish_pq_aggregates_and_proofs(&self, beacon_nodes: &BeaconNodes<P, W>) {
        let BeaconNodes::Local(local) = beacon_nodes else {
            warn_with_peers!("PQ aggregates are published only through the built-in beacon node");
            return;
        };

        let Some(BeaconState::Pq(state)) = beacon_nodes.state().map(AsRef::as_ref) else {
            return;
        };

        let Some(attestation_agg_pool) = self.chain_source.attestation_agg_pool() else {
            return;
        };

        let config = self.chain_source.chain_config.clone_arc();

        for (key, aggregators) in &self.own_aggregators {
            let (aggregate, proof) = match attestation_agg_pool.best_pq_aggregate(*key).await {
                Ok(Some(aggregate_and_proof)) => aggregate_and_proof,
                Ok(None) => {
                    warn_with_peers!(
                        "no proven PQ aggregate for committee {} in slot {}",
                        key.committee_index,
                        key.data.slot,
                    );
                    continue;
                }
                Err(error) => {
                    warn_with_peers!("failed to obtain a PQ aggregate: {error:?}");
                    continue;
                }
            };

            let aggregation_committee =
                match pq::get_aggregation_committee(state, key.data.slot, key.committee_index) {
                    Ok(aggregation_committee) => aggregation_committee,
                    Err(error) => {
                        warn_with_peers!("failed to compute an aggregation committee: {error:?}");
                        continue;
                    }
                };

            for aggregator in aggregators {
                let Some(position) = aggregation_committee
                    .iter()
                    .position(|index| *index == aggregator.aggregator_index)
                    .and_then(|position| u32::try_from(position).ok())
                else {
                    continue;
                };

                let message = PqAggregateAndProof {
                    aggregator_index: aggregator.aggregator_index,
                    aggregate: aggregate.clone(),
                    proof: proof.clone(),
                };

                let domain = accessors::get_domain(
                    &config,
                    state,
                    DOMAIN_AGGREGATE_AND_PROOF,
                    Some(aggregate.data.target.epoch),
                );
                let signing_root = misc::compute_signing_root(&message, domain);

                let Ok(leaf_index) = pq::compute_xmss_leaf_index(
                    aggregate.data.slot,
                    LEAF_OFFSET_AGGREGATE_AND_PROOF,
                ) else {
                    continue;
                };

                // The aggregate tick is the due time of the first aggregator.
                let delay = config
                    .aggregate_due_pq(position)
                    .saturating_sub(config.aggregate_due_pq(0));

                let local = local.clone();
                let signer = self.signer.clone_arc();
                let slashing_protector = self.slashing_protector.clone_arc();
                let public_key = aggregator.public_key;

                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;

                    let signature = match signer
                        .sign_pq(
                            vec![(public_key, leaf_index, signing_root)],
                            &slashing_protector,
                        )
                        .await
                    {
                        Ok(mut signatures) => signatures.pop().flatten(),
                        Err(error) => {
                            warn_with_peers!("failed to sign PQ aggregate: {error:?}");
                            return;
                        }
                    };

                    let Some(signature) = signature else {
                        return;
                    };

                    let signed_aggregate =
                        Arc::new(SignedAggregateAndProof::Pq(PqSignedAggregateAndProof {
                            message,
                            signature,
                        }));

                    if let Err(error) = local
                        .publish_aggregates_and_proofs(&[signed_aggregate])
                        .await
                    {
                        warn_with_peers!("failed to publish PQ aggregate: {error:?}");
                    }
                });
            }
        }
    }
}

/// Signs `signing_root` at `leaf_index` with the XMSS key derived from `public_key`.
pub(super) async fn sign_one<P: Preset, W: Wait + Sync>(
    validator: &Validator<P, W>,
    public_key: PublicKeyBytes,
    leaf_index: u64,
    signing_root: H256,
) -> Result<Option<xmss::XmssSignature>> {
    let mut signatures = validator
        .signer
        .sign_pq(
            vec![(public_key, leaf_index, signing_root)],
            &validator.slashing_protector,
        )
        .await?;

    let signature = signatures.pop().flatten();

    if signature.is_none() {
        warn_with_peers!("not signing at XMSS leaf {leaf_index} of {public_key:?}");
    }

    Ok(signature)
}
