use std::sync::Arc;

use anyhow::Result;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use log::debug;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    phase0::{
        containers::Attestation,
        primitives::{Epoch, ValidatorIndex},
    },
    preset::Preset,
};

pub enum ApiToLiveness {
    CheckLiveness(
        Sender<Result<Vec<(ValidatorIndex, bool)>>>,
        Epoch,
        Vec<ValidatorIndex>,
    ),
}

impl ApiToLiveness {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!(
                "send from HTTP API to liveness tracker failed because the receiver was dropped"
            );
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
            debug!(
                "send from validator to liveness tracker failed because the receiver was dropped"
            );
        }
    }
}
