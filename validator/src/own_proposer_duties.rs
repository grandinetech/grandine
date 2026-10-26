use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use helper_functions::misc;
use http_api_utils::ValidatorProposerDutyResponse;
use logging::debug_with_peers;
use scc::HashMap as SccHashMap;
use signer::Signer;
use ssz::H256;
use types::{
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::{BeaconNodeApi as _, ProposerDuties},
    beacon_nodes::BeaconNodes,
    misc::RequestedIndices,
};

type ProposersBySlot = HashMap<Slot, (ValidatorIndex, PublicKeyBytes)>;

/// Own proposals of the epochs in flight, from duties.
pub struct OwnProposerDuties {
    signer: Arc<Signer>,
    /// Each epoch under the root its duties were last reported under, even with no own proposals.
    proposers: SccHashMap<Epoch, (H256, ProposersBySlot)>,
    /// Proposals are kept only for the keys held when fetched, so a changed key set clears them.
    requested: RequestedIndices,
}

impl OwnProposerDuties {
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            proposers: SccHashMap::new(),
            requested: RequestedIndices::default(),
        }
    }

    async fn discard_for_other_keys(&self, validator_indices: &[ValidatorIndex]) {
        if self.requested.changed(validator_indices).await {
            self.proposers.clear_async().await;
        }
    }

    pub async fn len(&self) -> usize {
        let mut len = 0_usize;

        self.proposers
            .iter_async(|_, (_, proposers)| {
                len = len.saturating_add(proposers.len());
                true
            })
            .await;

        len
    }

    pub async fn get_at_slot<P: Preset>(
        &self,
        dependent_root: H256,
        slot: Slot,
    ) -> Option<(ValidatorIndex, PublicKeyBytes)> {
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        self.proposers
            .read_async(&epoch, |_, (fetched_root, proposers)| {
                (*fetched_root == dependent_root)
                    .then(|| proposers.get(&slot).copied())
                    .flatten()
            })
            .await
            .flatten()
    }

    /// Returns the epoch's own proposers per slot, fetched unless held under `dependent_root`.
    pub async fn init_at_epoch<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        epoch: Epoch,
        dependent_root: H256,
        validator_indices: &[ValidatorIndex],
    ) -> Result<ProposersBySlot> {
        self.discard_for_other_keys(validator_indices).await;

        // Taken in the check's own read, as a concurrent fetch may replace the epoch right after.
        if let Some(proposers) = self.existing(dependent_root, epoch).await {
            return Ok(proposers);
        }

        let ProposerDuties {
            dependent_root: reported_root,
            duties,
        } = beacon_nodes.proposer_duties(epoch).await?;

        // Recorded under the reported root, as another root may or may not be the same shuffling.
        if reported_root != dependent_root {
            debug_with_peers!(
                "proposer duties for epoch {epoch} were reported under dependent root \
                 {reported_root:?} rather than {dependent_root:?}",
            );
        }

        Ok(self.record(reported_root, epoch, duties).await)
    }

    async fn record(
        &self,
        dependent_root: H256,
        epoch: Epoch,
        duties: Vec<ValidatorProposerDutyResponse>,
    ) -> ProposersBySlot {
        let signer_snapshot = self.signer.load();

        let proposers = duties
            .into_iter()
            .filter(|duty| signer_snapshot.has_key(duty.pubkey))
            .map(|duty| (duty.slot, (duty.validator_index, duty.pubkey)))
            .collect::<HashMap<_, _>>();

        let previous = self
            .proposers
            .upsert_async(epoch, (dependent_root, proposers.clone()))
            .await;

        if previous.is_some_and(|(fetched_root, _)| fetched_root == dependent_root) {
            debug_with_peers!(
                "proposer duties for epoch {epoch} were already fetched under {dependent_root:?}",
            );
        }

        proposers
    }

    pub async fn upcoming(&self, slot: Slot) -> Vec<(H256, Slot, ValidatorIndex, PublicKeyBytes)> {
        let mut proposals = vec![];

        self.proposers
            .iter_async(|_, (dependent_root, proposers)| {
                proposals.extend(
                    proposers
                        .iter()
                        .filter(|(proposal_slot, _)| **proposal_slot > slot)
                        .map(|(proposal_slot, (validator_index, pubkey))| {
                            (*dependent_root, *proposal_slot, *validator_index, *pubkey)
                        }),
                );

                true
            })
            .await;

        proposals
    }

    async fn existing(&self, dependent_root: H256, epoch: Epoch) -> Option<ProposersBySlot> {
        self.proposers
            .read_async(&epoch, |_, (existing_root, proposers)| {
                (*existing_root == dependent_root).then(|| proposers.clone())
            })
            .await
            .flatten()
    }

    pub async fn prune<P: Preset>(&self, up_to_slot: Slot) {
        let up_to_epoch = misc::compute_epoch_at_slot::<P>(up_to_slot);

        self.proposers
            .retain_async(|epoch, _| *epoch >= up_to_epoch)
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

        let recorded = own_duties
            .record(root, 1, vec![duty(40, 8), duty(7, 9), duty(41, 15)])
            .await;
        own_duties.record(root, 2, vec![duty(7, 17)]).await;

        assert_eq!(
            recorded,
            HashMap::from([
                (8, (40, duty(40, 8).pubkey)),
                (15, (41, duty(41, 15).pubkey)),
            ]),
        );
        assert_eq!(
            own_duties.get_at_slot::<Minimal>(root, 8).await,
            Some((40, duty(40, 8).pubkey)),
        );
        assert_eq!(own_duties.get_at_slot::<Minimal>(root, 9).await, None);
        assert_eq!(own_duties.len().await, 2);
        assert!(own_duties.existing(root, 1).await.is_some());
        assert_eq!(own_duties.existing(root, 2).await, Some(HashMap::new()));
        assert!(own_duties.existing(root, 3).await.is_none());
    }

    // Duties of another shuffling must never answer for the one asked about.
    #[tokio::test]
    async fn duties_are_only_found_under_the_root_they_were_fetched_under() {
        let own_duties = own_duties_with_keys([40, 41]);

        own_duties
            .record(H256::repeat_byte(1), 1, vec![duty(40, 8)])
            .await;

        assert_eq!(
            own_duties
                .get_at_slot::<Minimal>(H256::repeat_byte(2), 8)
                .await,
            None
        );
        assert!(own_duties.existing(H256::repeat_byte(2), 1).await.is_none());
    }

    // Preferences are signed for later proposals, under the root last reported for each epoch.
    #[tokio::test]
    async fn upcoming_lists_later_proposals_under_the_last_fetched_root() {
        let own_duties = own_duties_with_keys([40, 41]);
        let old_root = H256::repeat_byte(1);
        let new_root = H256::repeat_byte(2);

        own_duties
            .record(old_root, 1, vec![duty(40, 8), duty(41, 12)])
            .await;
        own_duties
            .record(new_root, 1, vec![duty(41, 13), duty(7, 14)])
            .await;
        own_duties.record(old_root, 2, vec![duty(40, 17)]).await;

        let mut upcoming = own_duties.upcoming(8).await;

        // The map iterates in no particular order.
        upcoming.sort_unstable();

        assert_eq!(
            upcoming,
            vec![
                (old_root, 17, 40, duty(40, 17).pubkey),
                (new_root, 13, 41, duty(41, 13).pubkey),
            ],
        );
        assert_eq!(own_duties.upcoming(17).await, vec![]);
    }

    #[tokio::test]
    async fn pruning_drops_past_epochs_only() {
        let own_duties = own_duties_with_keys([40, 41]);
        let root = H256::repeat_byte(1);

        own_duties.record(root, 0, vec![duty(40, 3)]).await;
        own_duties.record(root, 1, vec![duty(41, 12)]).await;

        own_duties.prune::<Minimal>(8).await;

        assert_eq!(own_duties.get_at_slot::<Minimal>(root, 3).await, None);
        assert!(own_duties.existing(root, 0).await.is_none());
        assert_eq!(
            own_duties.get_at_slot::<Minimal>(root, 12).await,
            Some((41, duty(41, 12).pubkey)),
        );
        assert!(own_duties.existing(root, 1).await.is_some());
    }
}
