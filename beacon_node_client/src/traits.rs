use std::{pin::Pin, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use bls::{PublicKeyBytes, SignatureBytes};
use fork_choice_control::{Event, Topic};
use futures::Stream;
use p2p::{BeaconCommitteeSubscription, SyncCommitteeSubscription};
use types::{
    altair::containers::{
        SignedContributionAndProof, SyncCommitteeContribution, SyncCommitteeMessage,
    },
    combined::{Attestation, AttesterSlashing, BeaconState, SignedBeaconBlock},
    gloas::containers::ExecutionPayloadBid,
    nonstandard::WithBlobsAndMev,
    phase0::{
        containers::{AttestationData, ProposerSlashing},
        primitives::{CommitteeIndex, Epoch, H256, Slot, SubnetId, ValidatorIndex},
    },
    preset::Preset,
};

use crate::{
    ids::StateId,
    types::{
        AttesterDuty, BlockHeaderSummary, BlockProductionOptions, BroadcastValidation,
        DutiesResponse, GenesisData, ProposerDuty, ProposerPreparation, SyncCommitteeDuty,
        SyncingStatus, ValidatorLiveness,
    },
};

// `Arc<dyn Trait>` + `async_trait` is intentional: the validator holds these
// as trait objects so the impl can be swapped at runtime without
// re-monomorphising the validator stack.
#[async_trait]
pub trait BeaconChainReader<P: Preset>: Send + Sync {
    async fn genesis(&self) -> Result<GenesisData>;

    async fn syncing_status(&self) -> Result<SyncingStatus>;

    async fn head_block_header(&self) -> Result<BlockHeaderSummary>;

    async fn state_root(&self, state_id: StateId) -> Result<H256>;

    async fn beacon_state(&self, state_id: StateId) -> Result<Arc<BeaconState<P>>>;

    async fn attester_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<DutiesResponse<Vec<AttesterDuty>>>;

    async fn proposer_duties(&self, epoch: Epoch) -> Result<DutiesResponse<Vec<ProposerDuty>>>;

    async fn sync_committee_duties(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<DutiesResponse<Vec<SyncCommitteeDuty>>>;

    async fn validator_liveness(
        &self,
        epoch: Epoch,
        indices: &[ValidatorIndex],
    ) -> Result<Vec<ValidatorLiveness>>;
}

#[async_trait]
pub trait BeaconDutyEndpoints<P: Preset>: Send + Sync {
    async fn produce_attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData>;

    async fn produce_block(
        &self,
        slot: Slot,
        randao_reveal: SignatureBytes,
        options: BlockProductionOptions,
    ) -> Result<WithBlobsAndMev<block_producer::ValidatorBlindedBlock<P>, P>>;

    async fn produce_aggregate(
        &self,
        slot: Slot,
        attestation_data_root: H256,
        committee_index: Option<CommitteeIndex>,
    ) -> Result<Attestation<P>>;

    async fn produce_sync_committee_contribution(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        beacon_block_root: H256,
    ) -> Result<SyncCommitteeContribution<P>>;

    async fn execution_payload_bid(
        &self,
        slot: Slot,
        builder_index: ValidatorIndex,
    ) -> Result<ExecutionPayloadBid<P>>;
}

#[async_trait]
pub trait BeaconPublisher<P: Preset>: Send + Sync {
    async fn publish_block(
        &self,
        block: Arc<SignedBeaconBlock<P>>,
        validation: BroadcastValidation,
    ) -> Result<()>;

    async fn publish_sync_committee_message(
        &self,
        subnet_id: SubnetId,
        message: SyncCommitteeMessage,
    ) -> Result<()>;

    async fn publish_contribution_and_proof(
        &self,
        contribution: Box<SignedContributionAndProof<P>>,
        beacon_state: Arc<BeaconState<P>>,
    ) -> Result<()>;

    async fn publish_attester_slashing(&self, slashing: AttesterSlashing<P>) -> Result<()>;

    async fn publish_proposer_slashing(&self, slashing: ProposerSlashing) -> Result<()>;

    async fn subscribe_beacon_committee(
        &self,
        subscriptions: Vec<BeaconCommitteeSubscription>,
    ) -> Result<()>;

    async fn subscribe_sync_committee(
        &self,
        subscriptions: Vec<SyncCommitteeSubscription>,
    ) -> Result<()>;

    async fn prepare_beacon_proposer(&self, preparations: Vec<ProposerPreparation>) -> Result<()>;

    async fn set_registered_validators(
        &self,
        pubkeys: Vec<PublicKeyBytes>,
        prepared_proposer_indices: Vec<ValidatorIndex>,
    ) -> Result<()>;
}

pub trait BeaconEventStream<P: Preset>: Send + Sync {
    fn subscribe(&self, topics: &[Topic])
    -> Pin<Box<dyn Stream<Item = Event<P>> + Send + 'static>>;
}

pub trait BeaconClient<P: Preset>:
    BeaconChainReader<P> + BeaconDutyEndpoints<P> + BeaconPublisher<P> + BeaconEventStream<P>
{
}

impl<P, T> BeaconClient<P> for T
where
    P: Preset,
    T: BeaconChainReader<P> + BeaconDutyEndpoints<P> + BeaconPublisher<P> + BeaconEventStream<P>,
{
}
