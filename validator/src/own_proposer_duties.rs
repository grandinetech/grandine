use std::sync::Arc;

use anyhow::{Result, ensure};
use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use http_api_utils::ValidatorProposerDutyResponse;
use scc::{HashMap as SccHashMap, HashSet as SccHashSet};
use signer::Signer;
use ssz::H256;
use tokio::sync::Mutex;
use types::{
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::{BeaconNodeApi as _, ProposerDuties},
    beacon_nodes::BeaconNodes,
};

/// Own proposals of the epochs in flight, from duties.
pub struct OwnProposerDuties {
    signer: Arc<Signer>,
    proposers: SccHashMap<(H256, Slot), (ValidatorIndex, PublicKeyBytes)>,
    /// Most slots have no entry, so a fetched epoch has to be recorded on its own.
    fetched: SccHashSet<(H256, Epoch)>,
    /// The indices the duties were fetched for; a key imported at runtime changes the set.
    requested: Mutex<Arc<[ValidatorIndex]>>,
}

impl OwnProposerDuties {
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            proposers: SccHashMap::new(),
            fetched: SccHashSet::new(),
            requested: Mutex::new(Arc::from([])),
        }
    }

    async fn discard_for_other_keys(&self, validator_indices: &[ValidatorIndex]) {
        let mut requested = self.requested.lock().await;

        if **requested == *validator_indices {
            return;
        }

        *requested = validator_indices.into();
        self.proposers.clear_async().await;
        self.fetched.clear_async().await;
    }

    pub fn len(&self) -> usize {
        self.proposers.len()
    }

    pub async fn get_at_slot(
        &self,
        dependent_root: H256,
        slot: Slot,
    ) -> Option<(ValidatorIndex, PublicKeyBytes)> {
        self.proposers
            .read_async(&(dependent_root, slot), |_, proposer| *proposer)
            .await
    }

    /// Fetches the proposers of `epoch` unless they are already known under `dependent_root`.
    pub async fn init_at_epoch<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        epoch: Epoch,
        dependent_root: H256,
        validator_indices: &[ValidatorIndex],
    ) -> Result<()> {
        self.discard_for_other_keys(validator_indices).await;

        if self.is_fetched(dependent_root, epoch).await {
            return Ok(());
        }

        let ProposerDuties {
            dependent_root: reported_root,
            duties,
        } = beacon_nodes.proposer_duties(epoch).await?;

        // Another root is another shuffling; the duties cannot stand in for the ones asked for.
        ensure!(
            reported_root == dependent_root,
            "proposer duties for epoch {epoch} were reported under dependent root \
             {reported_root:?} rather than {dependent_root:?}",
        );

        self.record(dependent_root, epoch, duties).await;

        Ok(())
    }

    async fn record(
        &self,
        dependent_root: H256,
        epoch: Epoch,
        duties: Vec<ValidatorProposerDutyResponse>,
    ) {
        let signer_snapshot = self.signer.load();

        for duty in duties {
            if !signer_snapshot.has_key(duty.pubkey) {
                continue;
            }

            self.proposers
                .upsert_async(
                    (dependent_root, duty.slot),
                    (duty.validator_index, duty.pubkey),
                )
                .await;
        }

        let _ = self.fetched.insert_async((dependent_root, epoch)).await;
    }

    pub async fn is_fetched(&self, dependent_root: H256, epoch: Epoch) -> bool {
        self.fetched.contains_async(&(dependent_root, epoch)).await
    }

    pub async fn prune<P: Preset>(&self, up_to_slot: Slot) {
        let up_to_epoch = helper_functions::misc::compute_epoch_at_slot::<P>(up_to_slot);

        self.proposers
            .retain_async(|(_, slot), _| *slot >= up_to_slot)
            .await;

        self.fetched
            .retain_async(|(_, epoch)| *epoch >= up_to_epoch)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use bls::traits::SecretKey as _;
    use reqwest::Client;
    use signer::{KeyOrigin, Web3SignerConfig};
    use types::preset::Minimal;

    use super::*;

    fn own_duties_with_keys(indices: [ValidatorIndex; 2]) -> OwnProposerDuties {
        let secret_keys = indices.map(|index| Arc::new(interop::secret_key(index)));

        let signer = Arc::new(Signer::new(
            secret_keys.map(|secret_key| {
                (
                    secret_key.to_public_key().into(),
                    secret_key,
                    KeyOrigin::External,
                )
            }),
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));

        OwnProposerDuties::new(signer)
    }

    fn duty(validator_index: ValidatorIndex, slot: Slot) -> ValidatorProposerDutyResponse {
        ValidatorProposerDutyResponse {
            pubkey: interop::secret_key(validator_index).to_public_key().into(),
            validator_index,
            slot,
        }
    }

    // The endpoint lists every proposer of the epoch; only the keys held are worth keeping, and a
    // fetched epoch must be told apart from one with no own proposals.
    #[tokio::test]
    async fn only_own_proposals_are_kept_and_the_epoch_is_recorded() {
        let own_duties = own_duties_with_keys([40, 41]);
        let root = H256::repeat_byte(1);

        own_duties
            .record(root, 1, vec![duty(40, 8), duty(7, 9), duty(41, 15)])
            .await;

        assert_eq!(
            own_duties.get_at_slot(root, 8).await,
            Some((40, duty(40, 8).pubkey)),
        );
        assert_eq!(own_duties.get_at_slot(root, 9).await, None);
        assert_eq!(own_duties.len(), 2);
        assert!(own_duties.is_fetched(root, 1).await);
        assert!(!own_duties.is_fetched(root, 2).await);
    }

    // Duties of another shuffling must never answer for the one asked about.
    #[tokio::test]
    async fn duties_are_only_found_under_the_root_they_were_fetched_under() {
        let own_duties = own_duties_with_keys([40, 41]);

        own_duties
            .record(H256::repeat_byte(1), 1, vec![duty(40, 8)])
            .await;

        assert_eq!(own_duties.get_at_slot(H256::repeat_byte(2), 8).await, None);
        assert!(!own_duties.is_fetched(H256::repeat_byte(2), 1).await);
    }

    #[tokio::test]
    async fn pruning_drops_past_epochs_only() {
        let own_duties = own_duties_with_keys([40, 41]);
        let root = H256::repeat_byte(1);

        own_duties.record(root, 0, vec![duty(40, 3)]).await;
        own_duties.record(root, 1, vec![duty(41, 12)]).await;

        own_duties.prune::<Minimal>(8).await;

        assert_eq!(own_duties.get_at_slot(root, 3).await, None);
        assert!(!own_duties.is_fetched(root, 0).await);
        assert_eq!(
            own_duties.get_at_slot(root, 12).await,
            Some((41, duty(41, 12).pubkey)),
        );
        assert!(own_duties.is_fetched(root, 1).await);
    }
}
