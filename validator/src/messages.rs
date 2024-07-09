use std::{collections::HashSet, sync::Arc};

use anyhow::Error;
use bls::PublicKeyBytes;
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::warn;
use types::{
    altair::containers::SignedContributionAndProof,
    combined::{Attestation, BeaconState, SignedBeaconBlock},
    phase0::{containers::SignedVoluntaryExit, primitives::Epoch},
    preset::Preset,
};

pub enum ApiToValidator<P: Preset> {
    RegisteredValidators(Sender<HashSet<PublicKeyBytes>>),
    SignedValidatorRegistrations(
        Sender<Vec<(usize, Error)>>,
        Vec<SignedValidatorRegistrationV1>,
    ),
    SignedContributionsAndProofs(
        Sender<Option<Vec<(usize, Error)>>>,
        Vec<SignedContributionAndProof<P>>,
    ),
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
