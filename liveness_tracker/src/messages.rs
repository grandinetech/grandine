use anyhow::Result;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use tracing::debug;
use types::phase0::primitives::{Epoch, ValidatorIndex};

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
