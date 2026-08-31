use core::ops::Range;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Error as AnyhowError, Result, ensure};
use bls::PublicKeyBytes;
use derive_more::Display;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::{
    AttestationItem, AttestationOrigin, PayloadAttestationItem, PayloadAttestationOrigin,
};
use futures::channel::{mpsc::UnboundedSender, oneshot};
use helper_functions::{accessors, misc};
use http_api_utils::{
    ValidatorAttesterDutyResponse, ValidatorPTCDutyResponse, ValidatorSyncDutyResponse,
};
use itertools::Itertools as _;
use operation_pools::{
    AttestationAggPool, AttestationKey, PayloadAttestationAggPool, SyncCommitteeAggPool,
    convert_to_electra_attestation,
};
use p2p::{
    BeaconCommitteeSubscription, SyncCommitteeSubscription, ToSubnetService, ValidatorToP2p,
};
use signer::Signer;
use std_ext::ArcExt as _;
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{Attestation, BeaconState, SignedAggregateAndProof},
    gloas::{
        consts::PAYLOAD_STATUS_FULL,
        containers::{PayloadAttestationData, PayloadAttestationMessage},
    },
    nonstandard::{OwnAttestation, Phase, RelativeEpoch, WithStatus},
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{CommitteeIndex, Epoch, H256, Slot, SubnetId, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconState as _, PostAltairBeaconState},
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi, PtcDuties},
    slot_head::SlotHead,
};

const NAME: &str = "local";

#[derive(Display)]
#[display("{NAME}")]
pub struct LocalBeaconNode<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    slot_head: SlotHead<P>,
    beacon_state: Arc<BeaconState<P>>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
    signer: Arc<Signer>,
    p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    subnet_service_tx: UnboundedSender<ToSubnetService>,
    wait_group: W,
}

impl<P: Preset, W: Wait + Sync> LocalBeaconNode<P, W> {
    #[expect(clippy::too_many_arguments)]
    pub const fn new(
        controller: ApiController<P, W>,
        slot_head: SlotHead<P>,
        beacon_state: Arc<BeaconState<P>>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
        payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
        signer: Arc<Signer>,
        p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
        subnet_service_tx: UnboundedSender<ToSubnetService>,
        wait_group: W,
    ) -> Self {
        Self {
            controller,
            slot_head,
            beacon_state,
            attestation_agg_pool,
            sync_committee_agg_pool,
            payload_attestation_agg_pool,
            signer,
            p2p_tx,
            subnet_service_tx,
            wait_group,
        }
    }

    pub async fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let state = self.beacon_state.as_ref();
        // `slots` must lie within one epoch, as the duties carry a single dependent root.
        let epoch = misc::compute_epoch_at_slot::<P>(slots.start);
        let dependent_root = self.dependent_root(epoch, None).await?;
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
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for LocalBeaconNode<P, W> {
    async fn dependent_root(
        &self,
        epoch: Epoch,
        _validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        self.controller
            .dependent_root(&self.beacon_state, misc::previous_epoch(epoch))
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
                let (head_root, payload_status) = self.controller.head_root_with_payload_status();

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
            .attestation_agg_pool
            .best_aggregate_attestation(AttestationKey {
                data,
                committee_index,
            })
            .await
            .ok_or_else(|| {
                AnyhowError::msg(format!(
                    "no aggregate attestation for committee {committee_index} in slot {}",
                    data.slot,
                ))
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

            self.controller.on_singular_attestation(
                self.wait_group.clone(),
                AttestationItem::unverified(
                    attestation.clone_arc(),
                    AttestationOrigin::Own(subnet_id),
                ),
            );

            ValidatorToP2p::PublishSingularAttestation(attestation.clone_arc(), subnet_id)
                .send(&self.p2p_tx);

            self.attestation_agg_pool.insert_attestation(
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

            self.attestation_agg_pool.insert_attestation(
                self.wait_group.clone(),
                attestation,
                None,
            );

            ValidatorToP2p::PublishAggregateAndProof(aggregate_and_proof.clone_arc())
                .send(&self.p2p_tx);
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
        .send(&self.subnet_service_tx);

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
                epoch < self.controller.chain_config().altair_fork_epoch,
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
                .send(&self.p2p_tx);
            }

            self.sync_committee_agg_pool.aggregate_own_messages(
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
            .send(&self.subnet_service_tx);

        Ok(())
    }

    async fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>> {
        Ok(self
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
                .send(&self.p2p_tx);

            self.sync_committee_agg_pool.add_own_contribution(
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
        let dependent_root = self.dependent_root(epoch, None).await?;
        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        let duties = tokio::task::block_in_place(|| {
            ptc_duties_at_epoch(self.beacon_state.as_ref(), epoch, &indices)
        })?;

        Ok(PtcDuties {
            dependent_root,
            duties,
        })
    }

    async fn payload_attestation_data(&self, slot: Slot) -> Result<Option<PayloadAttestationData>> {
        let Some(block_with_root) = self.controller.block_by_slot(slot)?.map(WithStatus::value)
        else {
            return Ok(None);
        };

        let beacon_block_root = block_with_root.root;

        let blob_data_available = self
            .controller
            .indices_of_missing_data_columns(&block_with_root.block)
            .is_empty();

        Ok(Some(PayloadAttestationData {
            beacon_block_root,
            slot,
            payload_present: self.controller.is_payload_present_timely(beacon_block_root),
            blob_data_available,
        }))
    }

    async fn publish_payload_attestations(
        &self,
        messages: &[Arc<PayloadAttestationMessage>],
    ) -> Result<()> {
        for message in messages {
            self.controller.on_payload_attestation(
                self.wait_group.clone(),
                PayloadAttestationItem::unverified(
                    Arc::new(message.clone_arc().into()),
                    PayloadAttestationOrigin::Own,
                ),
            );

            ValidatorToP2p::PublishPayloadAttestation(message.clone_arc()).send(&self.p2p_tx);
        }

        let beacon_state = &self.beacon_state;

        let next_proposer_index =
            tokio::task::block_in_place(|| self.slot_head.next_proposer_index(beacon_state))?;

        let public_key = accessors::public_key(beacon_state.as_ref(), next_proposer_index)?;

        // The messages are only aggregated when an own validator proposes next.
        if self.signer.load().has_key(*public_key) {
            self.payload_attestation_agg_pool.aggregate_own_messages(
                self.wait_group.clone(),
                messages.iter().map(|message| **message).collect(),
                beacon_state.clone_arc(),
            );
        }

        Ok(())
    }
}

// The payload timeliness committees of `epoch`, which the state carries for the previous epoch
// through the seed lookahead.
pub fn ptc_duties_at_epoch<P: Preset>(
    state: &BeaconState<P>,
    epoch: Epoch,
    indices: &HashSet<ValidatorIndex>,
) -> Result<Vec<ValidatorPTCDutyResponse>> {
    misc::slots_in_epoch::<P>(epoch)?
        .map(|slot| {
            accessors::get_ptc(state, slot)?
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

// The sync committee of `epoch`, which the state carries only for the current period and the next.
pub fn sync_duties_at_epoch<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
    epoch: Epoch,
    indices: &HashSet<ValidatorIndex>,
) -> Result<Vec<ValidatorSyncDutyResponse>> {
    let period = misc::sync_committee_period::<P>(epoch);
    let current_period = misc::sync_committee_period::<P>(accessors::get_current_epoch(state));

    let committee = if period == current_period {
        state.current_sync_committee()
    } else if period == current_period.saturating_add(1) {
        state.next_sync_committee()
    } else {
        return Err(AnyhowError::msg(format!(
            "sync committee of period {period} is not known to a state in period {current_period}",
        )));
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
