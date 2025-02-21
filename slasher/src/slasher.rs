use core::convert::Infallible as Never;
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result};
use database::Database;
use eth1_api::RealController;
use features::Feature;
use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    select,
    stream::StreamExt,
};
use helper_functions::{misc, phase0};
use log::{debug, info, warn};
use p2p::P2pToSlasher;
use thiserror::Error;
use types::{
    combined::{Attestation, AttesterSlashing as CombinedAttesterSlashing, SignedBeaconBlock},
    phase0::{
        containers::{AttesterSlashing, IndexedAttestation, ProposerSlashing},
        primitives::{Epoch, Version},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    attestations::Attestations,
    blocks::Blocks,
    status::{ExplainedAttesterSlashing, ExplainedProposerSlashing},
    SlasherConfig, SlasherToValidator, ValidatorToSlasher,
};

#[derive(Debug, Error)]
enum Error<P: Preset> {
    #[error(
        "attempted to process invalid attestation (error: {error}, attestation: {attestation:?})"
    )]
    InvalidAttestation {
        error: AnyhowError,
        attestation: Arc<Attestation<P>>,
    },
    #[error("attempted to process invalid beacon block (error: {error}, block: {block:?})")]
    InvalidBlock {
        error: AnyhowError,
        block: Arc<SignedBeaconBlock<P>>,
    },
}

pub struct Databases {
    pub votes_db: Database,
    pub attestations_db: Database,
    pub min_targets_db: Database,
    pub max_targets_db: Database,
    pub blocks_db: Database,
}

pub struct Slasher<P: Preset> {
    controller: RealController<P>,
    fork_version: Version,
    attestations: Attestations<P>,
    blocks: Blocks,
    slasher_to_validator_tx: UnboundedSender<SlasherToValidator<P>>,
    network_to_slasher_rx: UnboundedReceiver<P2pToSlasher<P>>,
    validator_to_slasher_rx: UnboundedReceiver<ValidatorToSlasher>,
}

impl<P: Preset> Slasher<P> {
    #[must_use]
    pub fn new(
        config: SlasherConfig,
        controller: RealController<P>,
        fork_version: Version,
        databases: Databases,
        slasher_to_validator_tx: UnboundedSender<SlasherToValidator<P>>,
        network_to_slasher_rx: UnboundedReceiver<P2pToSlasher<P>>,
        validator_to_slasher_rx: UnboundedReceiver<ValidatorToSlasher>,
    ) -> Self {
        let Databases {
            votes_db,
            attestations_db,
            min_targets_db,
            max_targets_db,
            blocks_db,
        } = databases;

        Self {
            controller,
            fork_version,
            attestations: Attestations::new(
                config,
                votes_db,
                attestations_db,
                min_targets_db,
                max_targets_db,
            ),
            blocks: Blocks::new(config, blocks_db),
            slasher_to_validator_tx,
            network_to_slasher_rx,
            validator_to_slasher_rx,
        }
    }

    pub async fn run(mut self) -> Result<Never> {
        loop {
            select! {
                network_message = self.network_to_slasher_rx.select_next_some() => {
                    let result = match network_message {
                        P2pToSlasher::Attestation(attestation) => self
                            .process_attestation(&attestation)
                            .map_err(|error| Error::InvalidAttestation { error, attestation }),
                        P2pToSlasher::Block(block) => self
                            .process_block(&block)
                            .map_err(|error| Error::InvalidBlock { error, block }),
                    };

                    if let Err(error) = result {
                        warn!("{error}");
                    }
                },

                validator_message = self.validator_to_slasher_rx.select_next_some() => {
                    match validator_message {
                        ValidatorToSlasher::Epoch(epoch) => self.cleanup(epoch)?,
                    }
                },
            }
        }
    }

    fn process_block(&self, block: &SignedBeaconBlock<P>) -> Result<()> {
        debug!(
            "processing block record \
             (slot: {}, proposer: {}, fork_version: {:?}, state_root: {:?})",
            block.message().slot(),
            block.message().proposer_index(),
            self.fork_version,
            block.message().state_root(),
        );

        if let Some(explained_proposer_slashing) = self.check_block(block)? {
            info!("proposer slashing constructed: {explained_proposer_slashing:?}");

            self.process_proposer_slashing(explained_proposer_slashing.slashing);
        }

        Ok(())
    }

    fn process_attestation(&self, attestation: &Attestation<P>) -> Result<()> {
        let attestation = match attestation {
            Attestation::Phase0(attestation) => attestation,
            // TODO:
            Attestation::Electra(_) | Attestation::Single(_) => return Ok(()),
        };

        let target = attestation.data.target;
        let slot = misc::compute_start_slot_at_epoch::<P>(target.epoch);

        let target_state = if Feature::CacheTargetStates.is_enabled() {
            self.controller.checkpoint_state(attestation.data.target)?
        } else {
            self.controller.state_before_or_at_slot(target.root, slot)
        };

        if let Some(target_state) = target_state {
            let current_epoch = self.controller.finalized_epoch();
            // TODO(feature/electra): use electra::get_indexed_attestation for electra attestations
            let indexed_attestation = phase0::get_indexed_attestation(&target_state, attestation)?;

            debug!(
                "processing attestation record \
                 (attesters: {:?}, slot: {}, source: {}, target: {}, fork_version: {:?})",
                indexed_attestation.attesting_indices,
                indexed_attestation.data.slot,
                indexed_attestation.data.source.epoch,
                indexed_attestation.data.target.epoch,
                self.fork_version,
            );

            for explained_attester_slashing in
                self.check_attestation(&indexed_attestation, current_epoch)?
            {
                info!("attester slashing constructed: {explained_attester_slashing:?}");

                self.process_attester_slashing(explained_attester_slashing.slashing);
            }
        }

        Ok(())
    }

    fn check_block(
        &self,
        block: &SignedBeaconBlock<P>,
    ) -> Result<Option<ExplainedProposerSlashing>> {
        if let Some(slashing) = self.blocks.find_slashing::<P>(block)? {
            return Ok(Some(slashing));
        }

        self.blocks.update(block)?;

        Ok(None)
    }

    fn check_attestation(
        &self,
        attestation: &IndexedAttestation<P>,
        current_epoch: Epoch,
    ) -> Result<Vec<ExplainedAttesterSlashing<P>>> {
        let mut slashings = vec![];

        for validator_index in attestation.attesting_indices.clone() {
            let slashing = self
                .attestations
                .find_slashing(validator_index, attestation)?;

            if let Some(slashing_status) = slashing {
                slashings.push(slashing_status);
            } else {
                self.attestations
                    .update(validator_index, attestation, current_epoch)?;
            }
        }

        Ok(slashings)
    }

    fn cleanup(&self, current_epoch: Epoch) -> Result<()> {
        self.blocks.cleanup::<P>(current_epoch)?;
        self.attestations.cleanup(current_epoch)?;

        Ok(())
    }

    fn process_proposer_slashing(&self, proposer_slashing: ProposerSlashing) {
        SlasherToValidator::ProposerSlashing(proposer_slashing).send(&self.slasher_to_validator_tx);
    }

    fn process_attester_slashing(&self, attester_slashing: AttesterSlashing<P>) {
        self.controller
            .on_own_attester_slashing(Box::new(CombinedAttesterSlashing::Phase0(
                attester_slashing.clone(),
            )));

        SlasherToValidator::AttesterSlashing(attester_slashing).send(&self.slasher_to_validator_tx);
    }
}
