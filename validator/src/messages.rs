use std::collections::HashSet;

use anyhow::{Error, Result};
use bls::PublicKeyBytes;
use builder_api::unphased::containers::SignedValidatorRegistrationV1;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::warn;
use types::{altair::containers::SignedContributionAndProof, preset::Preset};

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

pub enum InternalMessage {
    DoppelgangerProtectionResult(Result<()>),
}

impl InternalMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn!("send internal validator message failed because the receiver was dropped");
        }
    }
}
