use std::{collections::HashSet, sync::Arc};

use anyhow::{Error, Result};
use bls::{PublicKeyBytes, SignatureBytes};
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::warn;
use operation_pools::PoolAdditionOutcome;
use types::{
    altair::containers::SignedContributionAndProof,
    combined::{
        BeaconBlock, BeaconState, ExecutionPayload, SignedBeaconBlock, SignedBlindedBeaconBlock,
    },
    nonstandard::WithBlobsAndMev,
    phase0::{
        containers::{Attestation, AttesterSlashing, ProposerSlashing, SignedVoluntaryExit},
        primitives::{Epoch, Slot, H256},
    },
    preset::Preset,
};

use crate::misc::{ProposerData, ValidatorBlindedBlock};

pub type BeaconBlockSender<P> = Sender<Result<Option<WithBlobsAndMev<BeaconBlock<P>, P>>>>;
pub type BlindedBlockSender<P> =
    Sender<Result<Option<WithBlobsAndMev<ValidatorBlindedBlock<P>, P>>>>;

pub enum ApiToValidator<P: Preset> {
    ProduceBeaconBlock(BeaconBlockSender<P>, H256, SignatureBytes, Slot, bool),
    ProduceBlindedBeaconBlock(BlindedBlockSender<P>, H256, SignatureBytes, Slot, bool, u64),
    AttesterSlashing(Sender<PoolAdditionOutcome>, Box<AttesterSlashing<P>>),
    ProposerSlashing(Sender<PoolAdditionOutcome>, Box<ProposerSlashing>),
    PublishSignedBlindedBlock(
        Sender<Option<WithBlobsAndMev<ExecutionPayload<P>, P>>>,
        Box<SignedBlindedBeaconBlock<P>>,
    ),
    RegisteredValidators(Sender<HashSet<PublicKeyBytes>>),
    RequestAttesterSlashings(Sender<Vec<AttesterSlashing<P>>>),
    RequestProposerSlashings(Sender<Vec<ProposerSlashing>>),
    RequestSignedVoluntaryExits(Sender<Vec<SignedVoluntaryExit>>),
    SignedVoluntaryExit(Sender<PoolAdditionOutcome>, Box<SignedVoluntaryExit>),
    SignedValidatorRegistrations(
        Sender<Vec<(usize, Error)>>,
        Vec<SignedValidatorRegistrationV1>,
    ),
    SignedContributionsAndProofs(
        Sender<Option<Vec<(usize, Error)>>>,
        Vec<SignedContributionAndProof<P>>,
    ),
    ValidatorProposerData(Vec<ProposerData>),
}

impl<P: Preset> ApiToValidator<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn!("send to validator failed because the receiver was dropped");
        }
    }
}

pub enum ValidatorToApi<P: Preset> {
    ContributionAndProof(Box<SignedContributionAndProof<P>>),
    VoluntaryExit(Box<SignedVoluntaryExit>),
}

impl<P: Preset> ValidatorToApi<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn!("send from validator to HTTP API failed because the receiver was dropped");
        }
    }
}

pub enum ValidatorToLiveness<P: Preset> {
    Epoch(Epoch),
    Head(Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>),
    ValidAttestation(Arc<Attestation<P>>),
}

impl<P: Preset> ValidatorToLiveness<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn!(
                "send from validator to liveness tracker failed because the receiver was dropped"
            );
        }
    }
}
