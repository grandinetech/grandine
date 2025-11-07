use core::time::Duration;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use anyhow::Result;
use bitvec::vec::BitVec;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use fork_choice_store::StateCacheError;
use futures::{StreamExt as _, channel::mpsc::UnboundedReceiver, select};
use helper_functions::{electra, misc, phase0};
use itertools::Itertools as _;
use logging::{debug_with_peers, warn_with_peers};
use operation_pools::PoolToLivenessMessage;
use prometheus_metrics::Metrics;
use types::{
    altair::containers::SyncCommitteeMessage,
    combined::{Attestation, BeaconState, SignedBeaconBlock},
    electra::containers::IndexedAttestation as ElectraIndexedAttestation,
    phase0::primitives::{Epoch, ValidatorIndex},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

pub use crate::messages::{ApiToLiveness, ValidatorToLiveness};

mod messages;

const EPOCHS_TO_KEEP_LIVE_VALIDATORS: u64 = 2;
const TOO_MANY_EMPTY_SLOTS_MESSAGE_COOLDOWN: Duration = Duration::from_secs(3);

pub struct LivenessTracker<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    live_validators: BTreeMap<Epoch, BitVec>,
    metrics: Option<Arc<Metrics>>,
    too_many_empty_slots_message_shown_at: Option<Instant>,
    api_to_liveness_rx: UnboundedReceiver<ApiToLiveness>,
    pool_to_liveness_rx: UnboundedReceiver<PoolToLivenessMessage>,
    validator_to_liveness_rx: UnboundedReceiver<ValidatorToLiveness<P>>,
}

impl<P: Preset, W: Wait> LivenessTracker<P, W> {
    #[must_use]
    pub const fn new(
        controller: ApiController<P, W>,
        metrics: Option<Arc<Metrics>>,
        api_to_liveness_rx: UnboundedReceiver<ApiToLiveness>,
        pool_to_liveness_rx: UnboundedReceiver<PoolToLivenessMessage>,
        validator_to_liveness_rx: UnboundedReceiver<ValidatorToLiveness<P>>,
    ) -> Self {
        Self {
            controller,
            live_validators: BTreeMap::new(),
            metrics,
            too_many_empty_slots_message_shown_at: None,
            api_to_liveness_rx,
            pool_to_liveness_rx,
            validator_to_liveness_rx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            select! {
                api_message = self.api_to_liveness_rx.select_next_some() => {
                    match api_message {
                        ApiToLiveness::CheckLiveness(sender, epoch, validator_indices) => {
                            if let Err(error) = sender.send(self.check_liveness(epoch, validator_indices)) {
                                warn_with_peers!("unable to send liveness data: {error:?}");
                            }
                        }
                    }
                },

                pool_message = self.pool_to_liveness_rx.select_next_some() => {
                    match pool_message {
                        PoolToLivenessMessage::SyncCommitteeMessage(sync_committee_message) => {
                            if let Err(error) = self.process_sync_committee_message(sync_committee_message) {
                                warn_with_peers!("Error while tracking liveness from sync committee message: {error:?}");
                            }
                        },
                    }
                },

                validator_message = self.validator_to_liveness_rx.select_next_some() => {
                    match validator_message {
                        ValidatorToLiveness::Epoch(current_epoch) => {
                            self.prune(current_epoch);
                        }
                        ValidatorToLiveness::Head(block, state) => {
                            self.track_collection_metrics();

                            debug_with_peers!(
                                "Tracked epochs: {:?}, Values: {}",
                                self.live_validators.keys().collect_vec(),
                                self.live_validators
                                    .values()
                                    .map(|bits| bits.count_ones())
                                    .sum::<usize>(),
                            );

                            if let Err(error) = self.process_block(&block, &state) {
                                warn_with_peers!("Error while tracking liveness from block: {error:?}");
                            }
                        }
                        ValidatorToLiveness::ValidAttestation(attestation) => {
                            let result = self
                                .controller
                                .preprocessed_state_at_current_slot().await
                                .map(|state| self.process_attestation(&attestation, &state));

                            if let Err(error) = result {
                                if let Some(StateCacheError::StateFarBehind { .. }) = error.downcast_ref() {
                                    if self
                                        .too_many_empty_slots_message_shown_at
                                        .map(|instant| instant.elapsed() > TOO_MANY_EMPTY_SLOTS_MESSAGE_COOLDOWN)
                                        .unwrap_or(true)
                                    {
                                        warn_with_peers!("Error while tracking liveness from attestation: {error:?}");
                                        self.too_many_empty_slots_message_shown_at = Some(Instant::now());
                                    }
                                } else {
                                     warn_with_peers!("Error while tracking liveness from attestation: {error:?}");
                                }
                            }
                        }
                        ValidatorToLiveness::Stop => break Ok(()),
                    }
                }
            }
        }
    }

    fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: Vec<ValidatorIndex>,
    ) -> Result<Vec<(ValidatorIndex, bool)>> {
        validator_indices
            .into_iter()
            .map(|validator_index| {
                let index = usize::try_from(validator_index)?;

                let is_live = self
                    .live_validators
                    .get(&epoch)
                    .and_then(|validators| validators.get(index))
                    .is_some_and(|bit| *bit);

                Ok((validator_index, is_live))
            })
            .collect()
    }

    fn process_attestation(
        &mut self,
        attestation: &Attestation<P>,
        state: &BeaconState<P>,
    ) -> Result<()> {
        let epoch = attestation.data().target.epoch;

        if self.is_epoch_allowed(epoch) {
            match attestation {
                Attestation::Phase0(attestation) => {
                    let indexed_attestation = phase0::get_indexed_attestation(state, attestation)?;

                    for validator_index in indexed_attestation.attesting_indices {
                        self.set(epoch, validator_index)?;
                    }
                }
                Attestation::Electra(attestation) => {
                    let indexed_attestation = electra::get_indexed_attestation(state, attestation)?;

                    for validator_index in indexed_attestation.attesting_indices {
                        self.set(epoch, validator_index)?;
                    }
                }
                Attestation::Single(attestation) => {
                    let indexed_attestation: ElectraIndexedAttestation<P> =
                        (*attestation).try_into()?;

                    for validator_index in indexed_attestation.attesting_indices {
                        self.set(epoch, validator_index)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn process_block(
        &mut self,
        block: &SignedBeaconBlock<P>,
        state: &BeaconState<P>,
    ) -> Result<()> {
        let epoch = misc::compute_epoch_at_slot::<P>(block.message().slot());

        if self.is_epoch_allowed(epoch) {
            let validator_index = block.message().proposer_index();
            self.set(epoch, validator_index)?;

            for attestation in block.message().body().combined_attestations() {
                self.process_attestation(&attestation, state)?;
            }
        }

        Ok(())
    }

    fn process_sync_committee_message(
        &mut self,
        sync_committee_message: SyncCommitteeMessage,
    ) -> Result<()> {
        let SyncCommitteeMessage {
            slot,
            validator_index,
            ..
        } = sync_committee_message;

        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        if self.is_epoch_allowed(epoch) {
            self.set(epoch, validator_index)?;
        }

        Ok(())
    }

    fn prune(&mut self, current_epoch: Epoch) {
        if let Some(epoch_boundary) = current_epoch.checked_sub(EPOCHS_TO_KEEP_LIVE_VALIDATORS) {
            self.live_validators = self.live_validators.split_off(&epoch_boundary);
        }
    }

    fn is_epoch_allowed(&self, epoch: Epoch) -> bool {
        let current_epoch = misc::compute_epoch_at_slot::<P>(self.controller.slot());
        let previous_epoch = misc::previous_epoch(current_epoch);
        epoch == previous_epoch || epoch == current_epoch
    }

    fn set(&mut self, epoch: Epoch, validator_index: ValidatorIndex) -> Result<()> {
        let index = usize::try_from(validator_index)?;
        let bits = self.live_validators.entry(epoch).or_default();

        bits.resize(bits.len().max(index + 1), false);
        bits.set(index, true);

        Ok(())
    }

    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "live_validators_epochs",
                self.live_validators.keys().len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "live_validators_indexes",
                self.live_validators.values().map(BitVec::len).sum(),
            );
        }
    }
}
