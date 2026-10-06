use std::{collections::HashSet, sync::Arc};

use anyhow::{Error, Result};
use bls::{PublicKeyBytes, Signature};
use builder_api::unphased::containers::ValidatorRegistrationV1;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use logging::warn_with_peers;
use types::{
    altair::containers::SignedContributionAndProof,
    phase0::primitives::{Epoch, H256, Slot},
    preset::Preset,
};

use crate::remote_beacon_node::RemoteBeaconNode;

pub enum ApiToValidator<P: Preset> {
    RegisteredValidators(Sender<HashSet<PublicKeyBytes>>),
    SignedContributionsAndProofs(
        Sender<Option<Vec<(usize, Error)>>>,
        Vec<SignedContributionAndProof<P>>,
    ),
    ValidatorRegistrations(Vec<(ValidatorRegistrationV1, Signature)>),
}

impl<P: Preset> ApiToValidator<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn_with_peers!("send to validator failed because the receiver was dropped");
        }
    }
}

pub enum InternalMessage {
    DoppelgangerProtectionResult(Result<()>),
    FinalizedCheckpoint(Epoch),
    /// A head one node streamed and reports as not optimistic.
    Head {
        node: Arc<RemoteBeaconNode>,
        slot: Slot,
        block_root: H256,
    },
}

impl InternalMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn_with_peers!(
                "send internal validator message failed because the receiver was dropped"
            );
        }
    }
}
