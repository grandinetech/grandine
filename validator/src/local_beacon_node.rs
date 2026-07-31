use std::sync::Arc;

use anyhow::Result;
use derive_more::Display;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::{AttestationItem, AttestationOrigin};
use futures::channel::mpsc::UnboundedSender;
use helper_functions::{accessors, misc};
use operation_pools::AttestationAggPool;
use p2p::ValidatorToP2p;
use std_ext::ArcExt as _;
use types::{
    nonstandard::{OwnAttestation, Phase},
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{CommitteeIndex, Slot},
    },
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{beacon_node_api::BeaconNodeApi, slot_head::SlotHead};

const NAME: &str = "local";

/// The built-in beacon node, as seen through [`BeaconNodeApi`].
///
/// Built per tick from the `SlotHead` the validator is already working with, so the local path
/// keeps using exactly the head and state it used before this seam existed.
#[derive(Display)]
#[display("{NAME}")]
pub struct LocalBeaconNode<P: Preset, W: Wait> {
    slot_head: SlotHead<P>,
    controller: ApiController<P, W>,
    attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
    wait_group: W,
}

impl<P: Preset, W: Wait + Sync> LocalBeaconNode<P, W> {
    pub const fn new(
        slot_head: SlotHead<P>,
        controller: ApiController<P, W>,
        attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
        p2p_tx: UnboundedSender<ValidatorToP2p<P>>,
        wait_group: W,
    ) -> Self {
        Self {
            slot_head,
            controller,
            attestation_agg_pool,
            p2p_tx,
            wait_group,
        }
    }
}

impl<P: Preset, W: Wait + Sync> BeaconNodeApi<P> for LocalBeaconNode<P, W> {
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
}
