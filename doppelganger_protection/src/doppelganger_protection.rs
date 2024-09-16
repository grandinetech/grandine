use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{ensure, Result};
use arc_swap::{ArcSwap, Guard};
use bls::PublicKeyBytes;
use futures::channel::mpsc::UnboundedSender;
use helper_functions::{accessors, misc};
use liveness_tracker::ApiToLiveness;
use log::warn;
use typenum::Unsigned as _;
use types::{
    combined::BeaconState,
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        primitives::{Epoch, Slot, ValidatorIndex},
    },
    preset::Preset,
};

use crate::error::Error;

const DOPPELGANGER_CHECK_DURATION_IN_EPOCHS: Epoch = 2;

#[derive(Clone, Copy)]
struct TrackedValidator {
    added_in_slot: Slot,
    validator_index: ValidatorIndex,
}

pub struct DoppelgangerProtection {
    snapshot: ArcSwap<Snapshot>,
    liveness_checker: LivenessChecker,
}

impl DoppelgangerProtection {
    #[must_use]
    pub fn new(liveness_tx: UnboundedSender<ApiToLiveness>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            liveness_checker: LivenessChecker::Live { liveness_tx },
        }
    }

    pub fn activate_validators_that_pass_checks<P: Preset>(&self, current_slot: Slot) {
        let check_duration_in_slots = DOPPELGANGER_CHECK_DURATION_IN_EPOCHS * P::SlotsPerEpoch::U64;

        let (validators_to_activate, validators_to_track): (HashMap<_, _>, HashMap<_, _>) = self
            .load()
            .tracked_validators
            .iter()
            .map(|(public_key, validator)| (*public_key, *validator))
            .partition(|(_, validator)| {
                validator.added_in_slot + check_duration_in_slots <= current_slot
            });

        if validators_to_activate.is_empty() {
            return;
        }

        self.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            snapshot
                .active_validators
                .extend(validators_to_activate.keys());

            snapshot.tracked_validators.clone_from(&validators_to_track);

            snapshot
        });
    }

    pub fn add_tracked_validators<P: Preset>(
        &self,
        public_keys: impl IntoIterator<Item = PublicKeyBytes>,
        beacon_state: &BeaconState<P>,
        current_slot: Slot,
    ) {
        let snapshot = self.load();

        let filtered_public_keys = public_keys
            .into_iter()
            .filter(|public_key| !snapshot.active_validators.contains(public_key))
            .collect::<Vec<_>>();

        if filtered_public_keys.is_empty() {
            return;
        }

        if current_slot == GENESIS_SLOT {
            self.update(|snapshot| {
                let mut snapshot = snapshot.as_ref().clone();

                snapshot.active_validators.extend(&filtered_public_keys);

                snapshot
            });

            return;
        }

        self.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            for public_key in &filtered_public_keys {
                match accessors::index_of_public_key(beacon_state, *public_key) {
                    Some(validator_index) => {
                        snapshot.tracked_validators
                            .entry(*public_key)
                            .or_insert(TrackedValidator {
                                added_in_slot: current_slot,
                                validator_index,
                            });
                    }
                    None => {
                        warn!(
                            "validator with public key {public_key:?} was not found in beacon state!",
                        );
                    }
                }
            }

            snapshot
        });
    }

    pub async fn detect_doppelgangers<P: Preset>(&self, current_slot: Slot) -> Result<()> {
        self.activate_validators_that_pass_checks::<P>(current_slot);

        let validator_indices_with_pubkeys = self
            .load()
            .tracked_validators
            .iter()
            .map(|(pubkey, validator)| (validator.validator_index, *pubkey))
            .collect::<HashMap<_, _>>();

        if validator_indices_with_pubkeys.is_empty() {
            return Ok(());
        }

        let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

        if current_epoch > GENESIS_EPOCH {
            self.detect_doppelgangers_in_epoch(current_epoch - 1, &validator_indices_with_pubkeys)
                .await?;
        }

        self.detect_doppelgangers_in_epoch(current_epoch, &validator_indices_with_pubkeys)
            .await?;

        Ok(())
    }

    async fn detect_doppelgangers_in_epoch(
        &self,
        epoch: Epoch,
        validator_indices_with_pubkeys: &HashMap<ValidatorIndex, PublicKeyBytes>,
    ) -> Result<()> {
        let liveness = self
            .liveness_checker
            .check_liveness(
                epoch,
                validator_indices_with_pubkeys.keys().copied().collect(),
            )
            .await?;

        let public_keys = liveness
            .into_iter()
            .filter(|(_, live)| *live)
            .filter_map(|(validator_index, _)| validator_indices_with_pubkeys.get(&validator_index))
            .copied()
            .collect::<Vec<_>>();

        ensure!(
            public_keys.is_empty(),
            Error::DoppelgangersDetected { public_keys },
        );

        Ok(())
    }

    #[must_use]
    pub fn load(&self) -> Guard<Arc<Snapshot>> {
        self.snapshot.load()
    }

    fn update<R, F>(&self, f: F) -> Arc<Snapshot>
    where
        F: FnMut(&Arc<Snapshot>) -> R,
        R: Into<Arc<Snapshot>>,
    {
        self.snapshot.rcu(f)
    }

    #[cfg(test)]
    #[must_use]
    pub fn new_with_mock_liveness(liveness: HashMap<Epoch, Vec<(ValidatorIndex, bool)>>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(Snapshot::default()),
            liveness_checker: LivenessChecker::Mock { liveness },
        }
    }
}

#[derive(Clone, Default)]
pub struct Snapshot {
    // Validators that are already active and have passed doppelganger protection checks
    active_validators: HashSet<PublicKeyBytes>,
    // Validators that are tracked by doppelganger protection
    tracked_validators: HashMap<PublicKeyBytes, TrackedValidator>,
}

impl Snapshot {
    pub fn is_validator_active(&self, public_key: PublicKeyBytes) -> bool {
        self.active_validators.contains(&public_key)
    }

    pub fn tracking_end_slot<P: Preset>(&self, public_key: PublicKeyBytes) -> Slot {
        self.tracked_validators
            .get(&public_key)
            .map(|validator| {
                validator.added_in_slot
                    + DOPPELGANGER_CHECK_DURATION_IN_EPOCHS * P::SlotsPerEpoch::U64
            })
            .unwrap_or(Slot::MAX)
    }
}

enum LivenessChecker {
    Live {
        liveness_tx: UnboundedSender<ApiToLiveness>,
    },
    #[cfg(test)]
    Mock {
        liveness: HashMap<Epoch, Vec<(ValidatorIndex, bool)>>,
    },
}

impl LivenessChecker {
    pub async fn check_liveness(
        &self,
        epoch: Epoch,
        validator_indices: Vec<ValidatorIndex>,
    ) -> Result<Vec<(ValidatorIndex, bool)>> {
        match self {
            Self::Live { liveness_tx } => {
                let (sender, receiver) = futures::channel::oneshot::channel();

                ApiToLiveness::CheckLiveness(sender, epoch, validator_indices).send(liveness_tx);

                receiver.await?
            }
            #[cfg(test)]
            Self::Mock { liveness } => Ok(liveness.get(&epoch).cloned().unwrap_or_default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use types::{config::Config, preset::Minimal};

    use super::*;

    fn doppelganger_protection() -> DoppelgangerProtection {
        let liveness = [(GENESIS_EPOCH, vec![(0, false), (1, true)])].into();

        DoppelgangerProtection::new_with_mock_liveness(liveness)
    }

    fn minimal_beacon_state() -> Arc<BeaconState<Minimal>> {
        factory::min_genesis_state::<Minimal>(&Config::minimal())
            .expect("should build beacon state")
            .0
    }

    fn validator_pubkey(
        state: &BeaconState<Minimal>,
        validator_index: ValidatorIndex,
    ) -> PublicKeyBytes {
        accessors::public_key(state, validator_index)
            .unwrap_or_else(|_| panic!("validator at position {validator_index} should exist"))
            .to_bytes()
    }

    #[test]
    fn test_is_validator_active_added_at_genesis_slot() {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);

        doppelganger_protection.add_tracked_validators([pubkey], &state, GENESIS_SLOT);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        assert!(is_active());
    }

    #[tokio::test]
    async fn test_is_validator_active_added_later_than_genesis_slot() -> Result<()> {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);
        let added_at_slot = GENESIS_SLOT + 1;

        doppelganger_protection.add_tracked_validators([pubkey], &state, added_at_slot);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal>(added_at_slot + 1)
            .await?;

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal>(added_at_slot + 15)
            .await?;

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal>(added_at_slot + 16)
            .await?;

        assert!(is_active());

        Ok(())
    }

    #[test]
    fn test_adding_validators_multiple_times() {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        doppelganger_protection.add_tracked_validators([pubkey], &state, GENESIS_SLOT);

        assert!(is_active());

        doppelganger_protection.add_tracked_validators([pubkey], &state, GENESIS_SLOT + 40);

        assert!(is_active());
    }

    #[tokio::test]
    async fn test_doppelganger_detection() -> Result<()> {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 1);
        let added_at_slot = GENESIS_SLOT + 1;

        doppelganger_protection.add_tracked_validators([pubkey], &state, added_at_slot);

        assert_eq!(
            doppelganger_protection
                .detect_doppelgangers::<Minimal>(added_at_slot + 1)
                .await
                .expect_err("a doppelganger should be detected")
                .downcast::<Error>()?,
            Error::DoppelgangersDetected {
                public_keys: vec![pubkey],
            },
        );

        Ok(())
    }
}
