use core::ops::Range;
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use derive_more::Display;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::{AttestationItem, AttestationOrigin};
use futures::channel::{mpsc::UnboundedSender, oneshot};
use helper_functions::{accessors, misc};
use http_api_utils::ValidatorAttesterDutyResponse;
use itertools::Itertools as _;
use operation_pools::AttestationAggPool;
use p2p::{BeaconCommitteeSubscription, ToSubnetService, ValidatorToP2p};
use std_ext::ArcExt as _;
use types::{
    combined::BeaconState,
    gloas::consts::PAYLOAD_STATUS_FULL,
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
            if slot_head.beacon_state.latest_block_header().slot == slot_head.slot() {
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
