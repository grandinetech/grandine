use core::future::Future;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{Result, ensure};
use arc_swap::{ArcSwap, Guard};
use bls::PublicKeyBytes;
use helper_functions::misc;
use logging::warn_with_peers;
use typenum::Unsigned as _;
use types::{
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        primitives::{Epoch, Slot, ValidatorIndex},
    },
    preset::Preset,
};

use crate::error::Error;

const DOPPELGANGER_CHECK_DURATION_IN_EPOCHS: Epoch = 2;

#[derive(Default)]
pub struct DoppelgangerProtection {
    snapshot: ArcSwap<Snapshot>,
}

impl DoppelgangerProtection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only validators whose liveness the checks could cover are activated; time alone does not
    /// clear one whose index is still unknown.
    fn activate_validators_that_pass_checks<P: Preset>(
        &self,
        current_slot: Slot,
        checked: &HashMap<PublicKeyBytes, ValidatorIndex>,
    ) {
        let check_duration_in_slots =
            DOPPELGANGER_CHECK_DURATION_IN_EPOCHS.saturating_mul(P::SlotsPerEpoch::U64);

        let (validators_to_activate, validators_to_track): (HashMap<_, _>, HashMap<_, _>) = self
            .load()
            .tracked_validators
            .iter()
            .map(|(public_key, added_in_slot)| (*public_key, *added_in_slot))
            .partition(|(public_key, added_in_slot)| {
                checked.contains_key(public_key)
                    && added_in_slot.saturating_add(check_duration_in_slots) <= current_slot
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

    pub fn add_tracked_validators(
        &self,
        public_keys: impl IntoIterator<Item = PublicKeyBytes>,
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
                // The validator index is resolved when the checks run, as a key may be tracked
                // before its deposit is processed.
                snapshot
                    .tracked_validators
                    .entry(*public_key)
                    .or_insert(current_slot);
            }

            snapshot
        });
    }

    /// Detects doppelgangers among the tracked validators, with their indices supplied by
    /// `indices_by_pubkey` and their liveness by `check_liveness`.
    pub async fn detect_doppelgangers<P: Preset, F, Fut>(
        &self,
        current_slot: Slot,
        indices_by_pubkey: &HashMap<PublicKeyBytes, ValidatorIndex>,
        check_liveness: F,
    ) -> Result<()>
    where
        F: Fn(Epoch, Vec<ValidatorIndex>) -> Fut + Send + Sync,
        Fut: Future<Output = Result<Vec<(ValidatorIndex, bool)>>> + Send,
    {
        let mut checked = HashMap::new();
        let mut validator_indices_with_pubkeys = HashMap::new();

        for public_key in self.load().tracked_validators.keys() {
            match indices_by_pubkey.get(public_key) {
                Some(validator_index) => {
                    checked.insert(*public_key, *validator_index);
                    validator_indices_with_pubkeys.insert(*validator_index, *public_key);
                }
                None => warn_with_peers!(
                    "liveness of validator with public key {public_key:?} cannot be checked \
                     until its index is known; it will not perform duties",
                ),
            }
        }

        if !validator_indices_with_pubkeys.is_empty() {
            let current_epoch = misc::compute_epoch_at_slot::<P>(current_slot);

            if current_epoch > GENESIS_EPOCH {
                Self::detect_doppelgangers_in_epoch(
                    current_epoch.saturating_sub(1),
                    &validator_indices_with_pubkeys,
                    &check_liveness,
                )
                .await?;
            }

            Self::detect_doppelgangers_in_epoch(
                current_epoch,
                &validator_indices_with_pubkeys,
                &check_liveness,
            )
            .await?;
        }

        // Activation comes after the checks so that a failed liveness query postpones it.
        self.activate_validators_that_pass_checks::<P>(current_slot, &checked);

        Ok(())
    }

    async fn detect_doppelgangers_in_epoch<F, Fut>(
        epoch: Epoch,
        validator_indices_with_pubkeys: &HashMap<ValidatorIndex, PublicKeyBytes>,
        check_liveness: &F,
    ) -> Result<()>
    where
        F: Fn(Epoch, Vec<ValidatorIndex>) -> Fut + Send + Sync,
        Fut: Future<Output = Result<Vec<(ValidatorIndex, bool)>>> + Send,
    {
        let liveness = check_liveness(
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
}

#[derive(Clone, Default)]
pub struct Snapshot {
    // Validators that are already active and have passed doppelganger protection checks
    active_validators: HashSet<PublicKeyBytes>,
    // Validators that are tracked by doppelganger protection, by the slot they were added in
    tracked_validators: HashMap<PublicKeyBytes, Slot>,
}

impl Snapshot {
    pub fn is_validator_active(&self, public_key: PublicKeyBytes) -> bool {
        self.active_validators.contains(&public_key)
    }

    pub fn tracking_end_slot<P: Preset>(&self, public_key: PublicKeyBytes) -> Slot {
        self.tracked_validators
            .get(&public_key)
            .map(|added_in_slot| {
                added_in_slot.saturating_add(
                    DOPPELGANGER_CHECK_DURATION_IN_EPOCHS.saturating_mul(P::SlotsPerEpoch::U64),
                )
            })
            .unwrap_or(Slot::MAX)
    }
}

#[cfg(test)]
mod tests {
    use core::future::{Ready, ready};

    use helper_functions::accessors;
    use pubkey_cache::PubkeyCache;
    use types::{combined::BeaconState, config::Config, preset::Minimal};

    use super::*;

    fn doppelganger_protection() -> DoppelgangerProtection {
        DoppelgangerProtection::new()
    }

    fn mock_liveness(
        epoch: Epoch,
        _validator_indices: Vec<ValidatorIndex>,
    ) -> Ready<Result<Vec<(ValidatorIndex, bool)>>> {
        let liveness: HashMap<Epoch, Vec<(ValidatorIndex, bool)>> =
            [(GENESIS_EPOCH, vec![(0, false), (1, true)])].into();

        ready(Ok(liveness.get(&epoch).cloned().unwrap_or_default()))
    }

    fn indices_by_pubkey(
        state: &BeaconState<Minimal>,
        validator_indices: impl IntoIterator<Item = ValidatorIndex>,
    ) -> HashMap<PublicKeyBytes, ValidatorIndex> {
        validator_indices
            .into_iter()
            .map(|validator_index| (validator_pubkey(state, validator_index), validator_index))
            .collect()
    }

    fn minimal_beacon_state() -> Arc<BeaconState<Minimal>> {
        factory::min_genesis_state::<Minimal>(&Config::minimal(), &PubkeyCache::default())
            .expect("should build beacon state")
            .0
    }

    fn validator_pubkey(
        state: &BeaconState<Minimal>,
        validator_index: ValidatorIndex,
    ) -> PublicKeyBytes {
        *accessors::public_key(state, validator_index)
            .unwrap_or_else(|_| panic!("validator at position {validator_index} should exist"))
    }

    #[test]
    fn test_is_validator_active_added_at_genesis_slot() {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);

        doppelganger_protection.add_tracked_validators([pubkey], GENESIS_SLOT);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        assert!(is_active());
    }

    #[tokio::test]
    async fn test_is_validator_active_added_later_than_genesis_slot() -> Result<()> {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);
        let indices = indices_by_pubkey(&state, [0]);
        let added_at_slot = GENESIS_SLOT + 1;

        doppelganger_protection.add_tracked_validators([pubkey], added_at_slot);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal, _, _>(added_at_slot + 1, &indices, mock_liveness)
            .await?;

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal, _, _>(added_at_slot + 15, &indices, mock_liveness)
            .await?;

        assert!(!is_active());

        doppelganger_protection
            .detect_doppelgangers::<Minimal, _, _>(added_at_slot + 16, &indices, mock_liveness)
            .await?;

        assert!(is_active());

        Ok(())
    }

    // A validator whose index is not resolved yet is neither checked nor activated on time alone.
    #[tokio::test]
    async fn test_validator_with_unknown_index_is_not_activated() -> Result<()> {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 0);
        let added_at_slot = GENESIS_SLOT + 1;

        doppelganger_protection.add_tracked_validators([pubkey], added_at_slot);

        let is_active = || doppelganger_protection.load().is_validator_active(pubkey);

        doppelganger_protection
            .detect_doppelgangers::<Minimal, _, _>(
                added_at_slot + 16,
                &HashMap::new(),
                mock_liveness,
            )
            .await?;

        assert!(!is_active());

        let indices = indices_by_pubkey(&state, [0]);

        doppelganger_protection
            .detect_doppelgangers::<Minimal, _, _>(added_at_slot + 17, &indices, mock_liveness)
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

        doppelganger_protection.add_tracked_validators([pubkey], GENESIS_SLOT);

        assert!(is_active());

        doppelganger_protection.add_tracked_validators([pubkey], GENESIS_SLOT + 40);

        assert!(is_active());
    }

    #[tokio::test]
    async fn test_doppelganger_detection() -> Result<()> {
        let doppelganger_protection = doppelganger_protection();
        let state = minimal_beacon_state();
        let pubkey = validator_pubkey(&state, 1);
        let indices = indices_by_pubkey(&state, [1]);
        let added_at_slot = GENESIS_SLOT + 1;

        doppelganger_protection.add_tracked_validators([pubkey], added_at_slot);

        assert_eq!(
            doppelganger_protection
                .detect_doppelgangers::<Minimal, _, _>(added_at_slot + 1, &indices, mock_liveness)
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
