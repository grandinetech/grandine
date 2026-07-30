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
use helper_functions::{electra, misc, phase0};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use p2p::P2pToSlasher;
use ssz::ContiguousList;
use thiserror::Error;
use try_from_iterator::TryFromIterator as _;
use types::{
    combined::{Attestation, AttesterSlashing as CombinedAttesterSlashing, SignedBeaconBlock},
    electra::containers::{AttesterSlashing, IndexedAttestation, SingleAttestation},
    phase0::{
        containers::{IndexedAttestation as Phase0IndexedAttestation, ProposerSlashing},
        primitives::{Epoch, Version},
    },
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::{
    SlasherConfig, SlasherToValidator, ValidatorToSlasher,
    attestations::Attestations,
    blocks::Blocks,
    status::{ExplainedAttesterSlashing, ExplainedProposerSlashing},
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
                        warn_with_peers!("{error}");
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
        debug_with_peers!(
            "processing block record \
             (slot: {}, proposer: {}, fork_version: {:?}, state_root: {:?})",
            block.message().slot(),
            block.message().proposer_index(),
            self.fork_version,
            block.message().state_root(),
        );

        if let Some(explained_proposer_slashing) = self.check_block(block)? {
            info_with_peers!("proposer slashing constructed: {explained_proposer_slashing:?}");

            self.process_proposer_slashing(explained_proposer_slashing.slashing);
        }

        Ok(())
    }

    fn process_attestation(&self, attestation: &Attestation<P>) -> Result<()> {
        let Some(indexed_attestation) = self.indexed_attestation(attestation)? else {
            return Ok(());
        };

        let current_epoch = self.controller.finalized_epoch();

        debug_with_peers!(
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
            info_with_peers!("attester slashing constructed: {explained_attester_slashing:?}");

            self.process_attester_slashing(explained_attester_slashing.slashing);
        }

        Ok(())
    }

    // Convert an attestation of any variant into an Electra `IndexedAttestation`, which the slasher
    // uses uniformly for slashing detection and reporting. Electra's `attesting_indices` bound is a
    // superset of Phase 0's, so Phase 0 attestations widen losslessly. A `SingleAttestation` carries
    // its attester index explicitly, so it needs no committee lookup and no target state.
    //
    // Returns `None` when the target state needed to resolve aggregated attesting indices is
    // unavailable.
    fn indexed_attestation(
        &self,
        attestation: &Attestation<P>,
    ) -> Result<Option<IndexedAttestation<P>>> {
        // `SingleAttestation` carries its attester index explicitly, so no target state is needed.
        if let Attestation::Single(attestation) = attestation {
            return Ok(Some(single_attestation_to_indexed(attestation)));
        }

        let target = attestation.data().target;
        let slot = misc::compute_start_slot_at_epoch::<P>(target.epoch);

        let target_state = if Feature::CacheTargetStates.is_enabled() {
            self.controller.checkpoint_state_blocking(target)?
        } else {
            self.controller.state_before_or_at_slot(target.root, slot)
        };

        let Some(target_state) = target_state else {
            return Ok(None);
        };

        let indexed_attestation = match attestation {
            Attestation::Phase0(attestation) => {
                let attestation = phase0::get_indexed_attestation(&target_state, attestation)?;
                widen_indexed_attestation(attestation)
            }
            Attestation::Electra(attestation) => {
                electra::get_indexed_attestation(&target_state, attestation)?
            }
            Attestation::Single(_) => unreachable!("Single attestations are handled above"),
        };

        Ok(Some(indexed_attestation))
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
            .on_own_attester_slashing(Box::new(CombinedAttesterSlashing::Electra(
                attester_slashing.clone(),
            )));

        SlasherToValidator::AttesterSlashing(attester_slashing).send(&self.slasher_to_validator_tx);
    }
}

// `SingleAttestation` already identifies its single attester, so its `IndexedAttestation` can be
// built directly without resolving a committee against the target state.
fn single_attestation_to_indexed<P: Preset>(
    attestation: &SingleAttestation,
) -> IndexedAttestation<P> {
    let attesting_indices =
        ContiguousList::try_from_iter(core::iter::once(attestation.attester_index))
            .expect("a single index always fits in IndexedAttestation.attesting_indices");

    IndexedAttestation {
        attesting_indices,
        data: attestation.data,
        signature: attestation.signature,
    }
}

// Phase 0 `IndexedAttestation`s have a smaller `attesting_indices` bound than Electra ones, so they
// always widen losslessly into the Electra representation the slasher uses internally.
fn widen_indexed_attestation<P: Preset>(
    attestation: Phase0IndexedAttestation<P>,
) -> IndexedAttestation<P> {
    IndexedAttestation {
        attesting_indices: ContiguousList::try_from_iter(attestation.attesting_indices).expect(
            "Phase 0 attesting indices always fit in Electra IndexedAttestation.attesting_indices",
        ),
        data: attestation.data,
        signature: attestation.signature,
    }
}

#[cfg(test)]
mod tests {
    use bls::SignatureBytes;
    use types::{
        phase0::{containers::AttestationData, primitives::ValidatorIndex},
        preset::Mainnet,
    };

    use super::*;

    #[test]
    fn single_attestation_converts_to_single_index_indexed_attestation() {
        let attester_index: ValidatorIndex = 42;
        let data = AttestationData::default();
        let signature = SignatureBytes::default();

        let single = SingleAttestation {
            committee_index: 3,
            attester_index,
            data,
            signature,
        };

        let indexed = single_attestation_to_indexed::<Mainnet>(&single);

        assert_eq!(
            indexed
                .attesting_indices
                .into_iter()
                .collect::<Vec<ValidatorIndex>>(),
            vec![attester_index],
        );
        assert_eq!(indexed.data, data);
        assert_eq!(indexed.signature, signature);
    }

    #[test]
    fn phase0_indexed_attestation_widens_preserving_indices_data_and_signature() {
        let attesting_indices = ContiguousList::try_from_iter([7, 9, 11])
            .expect("three indices fit within the Phase 0 bound");

        let phase0_attestation = Phase0IndexedAttestation::<Mainnet> {
            attesting_indices,
            data: AttestationData::default(),
            signature: SignatureBytes::default(),
        };

        let widened = widen_indexed_attestation(phase0_attestation.clone());

        assert_eq!(
            widened
                .attesting_indices
                .into_iter()
                .collect::<Vec<ValidatorIndex>>(),
            vec![7, 9, 11],
        );
        assert_eq!(widened.data, phase0_attestation.data);
        assert_eq!(widened.signature, phase0_attestation.signature);
    }
}
