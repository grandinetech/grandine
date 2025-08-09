use futures::channel::mpsc::UnboundedSender;
use logging::warn_with_peers;
use types::{
    phase0::{
        containers::{AttesterSlashing, ProposerSlashing},
        primitives::Epoch,
    },
    preset::Preset,
};

pub enum ValidatorToSlasher {
    Epoch(Epoch),
}

impl ValidatorToSlasher {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn_with_peers!("send to slasher failed because the receiver was dropped");
        }
    }
}

pub enum SlasherToValidator<P: Preset> {
    AttesterSlashing(AttesterSlashing<P>),
    ProposerSlashing(ProposerSlashing),
}

impl<P: Preset> SlasherToValidator<P> {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            warn_with_peers!("send to validator failed because the receiver was dropped");
        }
    }
}
