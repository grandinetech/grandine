use core::future::Future;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use anyhow::Result;
use bls::PublicKeyBytes;
use http_api_utils::{ValidatorAttesterDutyResponse, ValidatorSyncDutyResponse};
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use types::{
    altair::{
        containers::{SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::{Attestation, SignedAggregateAndProof},
    nonstandard::OwnAttestation,
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
};

use crate::slot_head::SlotHead;

pub struct AttesterDuties {
    pub dependent_root: H256,
    pub duties: Vec<ValidatorAttesterDutyResponse>,
}

/// A beacon node the validator can perform duties against.
pub trait BeaconNodeApi<P: Preset> {
    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/postStateValidators>
    fn validator_indices(
        &self,
        public_keys: &[PublicKeyBytes],
    ) -> impl Future<Output = Result<HashMap<PublicKeyBytes, ValidatorIndex>>> + Send;

    fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> impl Future<Output = Result<H256>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData>
    fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> impl Future<Output = Result<AttestationData>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestationV2>
    fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> impl Future<Output = Result<Attestation<P>>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestationsV2>
    fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> impl Future<Output = Result<()>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofsV2>
    fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> impl Future<Output = Result<()>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet>
    fn subscribe_to_beacon_committees(
        &self,
        current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> impl Future<Output = Result<()>> + Send;

    /// [`None`] when this node has no head recent enough to sign for.
    fn slot_head(&self, slot: Slot) -> impl Future<Output = Result<Option<SlotHead<P>>>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties>
    fn sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> impl Future<Output = Result<Vec<ValidatorSyncDutyResponse>>> + Send;

    // Grouped by subcommittee because the built-in node gossips each message on the subnet of
    // every subcommittee its validator sits in.
    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolSyncCommitteeSignatures>
    fn publish_sync_committee_messages(
        &self,
        messages: &BTreeMap<SubcommitteeIndex, Vec<SyncCommitteeMessage>>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets>
    fn subscribe_to_sync_committees(
        &self,
        current_epoch: Epoch,
        subscriptions: &[SyncCommitteeSubscription],
    ) -> impl Future<Output = Result<()>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution>
    fn sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: SubcommitteeIndex,
        beacon_block_root: H256,
    ) -> impl Future<Output = Result<SyncCommitteeContribution<P>>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/submitPoolSyncCommitteeContributionAndProofs>
    fn publish_contributions_and_proofs(
        &self,
        contributions_and_proofs: &[SignedContributionAndProof<P>],
    ) -> impl Future<Output = Result<()>> + Send;
}
