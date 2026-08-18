use core::ops::Range;
use std::{collections::HashSet, sync::Arc};

use anyhow::{Error as AnyhowError, Result};
use derive_more::Display;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::{AttestationItem, AttestationOrigin};
use futures::channel::{mpsc::UnboundedSender, oneshot};
use helper_functions::{accessors, misc};
use http_api_utils::ValidatorAttesterDutyResponse;
use itertools::Itertools as _;
use operation_pools::{AttestationAggPool, AttestationKey};
use p2p::{BeaconCommitteeSubscription, ToSubnetService, ValidatorToP2p};
use std_ext::ArcExt as _;
use types::{
    combined::{Attestation, BeaconState, SignedAggregateAndProof},
    nonstandard::{OwnAttestation, Phase},
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi},
    slot_head::SlotHead,
};

const NAME: &str = "local";

#[derive(Display)]
#[display("{NAME}")]
pub struct LocalBeaconNode<P: Preset, W: Wait> {
    slot_head: SlotHead<P>,
    controller: ApiController<P, W>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    subnet_service_tx: UnboundedSender<ToSubnetService>,
    wait_group: W,
}

impl<P: Preset, W: Wait + Sync> LocalBeaconNode<P, W> {
    pub const fn new(
        slot_head: SlotHead<P>,
        controller: ApiController<P, W>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
        subnet_service_tx: UnboundedSender<ToSubnetService>,
        wait_group: W,
    ) -> Self {
        Self {
            slot_head,
            controller,
            attestation_agg_pool,
            p2p_tx,
            subnet_service_tx,
            wait_group,
        }
    }

    // `slots` must lie within one epoch, as the duties carry a single dependent root.
    pub async fn attester_duties_at_slots(
        &self,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let state = self.slot_head.beacon_state.as_ref();
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
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for LocalBeaconNode<P, W> {
    async fn dependent_root(
        &self,
        epoch: Epoch,
        _validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        self.controller
            .dependent_root(&self.slot_head.beacon_state, misc::previous_epoch(epoch))
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        self.attester_duties_at_slots(misc::slots_in_epoch::<P>(epoch)?, validator_indices)
            .await
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
            u64::from(
                slot_head.beacon_state.latest_block_header().slot != slot_head.slot()
                    && self
                        .controller
                        .is_payload_verified(slot_head.beacon_block_root),
            )
        } else if phase >= Phase::Electra {
            0
        } else {
            committee_index
        };

        let target = tokio::task::block_in_place(|| Checkpoint {
            epoch: slot_head.current_epoch(),
            root: accessors::epoch_boundary_block_root(
                &slot_head.beacon_state,
                slot_head.beacon_block_root,
            ),
        });

        Ok(AttestationData {
            slot,
            index,
            beacon_block_root: slot_head.beacon_block_root,
            source: slot_head.beacon_state.current_justified_checkpoint(),
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
            aggregate
                .try_into_electra_attestation()
                .map(Attestation::Electra)
        } else {
            aggregate
                .try_into_electra_attestation()
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
            let subnet_id = self
                .slot_head
                .subnet_id(attestation.data().slot, committee_index)?;

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
